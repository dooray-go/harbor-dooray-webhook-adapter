package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HarborClient is a minimal read-only client for Harbor's v2.0 API. It exists
// solely for the expiry watcher: Harbor emits no webhook when a CVE allowlist
// or a robot account expires, so the only way to see it coming is to poll.
type HarborClient struct {
	baseURL  string
	username string
	password string
	client   *http.Client
}

func NewHarborClient(cfg HarborConfig) *HarborClient {
	return &HarborClient{
		baseURL:  strings.TrimRight(cfg.URL, "/"),
		username: cfg.Username,
		password: cfg.Password,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// CVEAllowlist mirrors Harbor's CVEAllowlist model. ExpiresAt is seconds since
// epoch and is nil when the allowlist never expires.
type CVEAllowlist struct {
	ExpiresAt *int64             `json:"expires_at"`
	Items     []CVEAllowlistItem `json:"items"`
}

type CVEAllowlistItem struct {
	CVEID string `json:"cve_id"`
}

// Expiry returns the allowlist's expiry time and whether one is set. Harbor
// also writes 0 for "no expiry" in some code paths, so treat that as unset.
func (a CVEAllowlist) Expiry() (time.Time, bool) {
	if a.ExpiresAt == nil || *a.ExpiresAt <= 0 {
		return time.Time{}, false
	}
	return time.Unix(*a.ExpiresAt, 0), true
}

type HarborProject struct {
	ProjectID    int64           `json:"project_id"`
	Name         string          `json:"name"`
	Metadata     ProjectMetadata `json:"metadata"`
	CVEAllowlist CVEAllowlist    `json:"cve_allowlist"`
}

// ProjectMetadata carries the deployment-security switches. Harbor stores them
// as strings ("true"/"false"), and omits them entirely when never configured.
type ProjectMetadata struct {
	PreventVul               string `json:"prevent_vul"`
	Severity                 string `json:"severity"`
	ReuseSysCVEAllowlist     string `json:"reuse_sys_cve_allowlist"`
	EnableContentTrustCosign string `json:"enable_content_trust_cosign"`
}

// PreventsVulnerable reports whether "Prevent images with vulnerability
// severity of X or higher from running" is on. Harbor's default is off, so an
// absent value means false.
func (m ProjectMetadata) PreventsVulnerable() bool {
	return m.PreventVul == "true"
}

// ReusesSystemAllowlist reports whether the project defers to the system-wide
// CVE allowlist instead of its own. Harbor defaults this to "true", so an
// absent value means true — and that matters here: such a project's exposure
// follows the *system* allowlist's expiry, not its own.
func (m ProjectMetadata) ReusesSystemAllowlist() bool {
	return m.ReuseSysCVEAllowlist != "false"
}

type HarborRobot struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Level is "system" or "project".
	Level   string `json:"level"`
	Disable bool   `json:"disable"`
	// ExpiresAt is seconds since epoch; -1 means the robot never expires.
	ExpiresAt int64 `json:"expires_at"`
}

// Expiry returns the robot's expiry time and whether one is set.
func (r HarborRobot) Expiry() (time.Time, bool) {
	if r.ExpiresAt <= 0 {
		return time.Time{}, false
	}
	return time.Unix(r.ExpiresAt, 0), true
}

// get issues an authenticated GET against the v2.0 API and decodes the JSON
// body into out. byName marks a path segment as a resource *name* rather than
// an ID, which Harbor requires for numeric-looking project names.
func (c *HarborClient) get(ctx context.Context, path string, byName bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2.0"+path, nil)
	if err != nil {
		return fmt.Errorf("build harbor request %s: %w", path, err)
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Accept", "application/json")
	if byName {
		req.Header.Set("X-Is-Resource-Name", "true")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("call harbor %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("harbor %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode harbor %s response: %w", path, err)
	}
	return nil
}

// harborPageSize is the page size used for list endpoints. Harbor caps
// page_size at 100.
const harborPageSize = 100

// SystemCVEAllowlist returns the instance-wide CVE allowlist.
func (c *HarborClient) SystemCVEAllowlist(ctx context.Context) (CVEAllowlist, error) {
	var a CVEAllowlist
	err := c.get(ctx, "/system/CVEAllowlist", false, &a)
	return a, err
}

// Project returns a single project by name, including its metadata and its own
// CVE allowlist.
func (c *HarborClient) Project(ctx context.Context, name string) (HarborProject, error) {
	var p HarborProject
	err := c.get(ctx, "/projects/"+url.PathEscape(name), true, &p)
	return p, err
}

// ProjectNames lists the names of every project the configured account can see.
func (c *HarborClient) ProjectNames(ctx context.Context) ([]string, error) {
	var names []string
	for page := 1; ; page++ {
		var batch []HarborProject
		path := fmt.Sprintf("/projects?page=%d&page_size=%d", page, harborPageSize)
		if err := c.get(ctx, path, false, &batch); err != nil {
			return nil, err
		}
		for _, p := range batch {
			names = append(names, p.Name)
		}
		if len(batch) < harborPageSize {
			return names, nil
		}
	}
}

// SystemRobots lists system-level robot accounts. It needs the system-scope
// "robot: list" permission, and the caller must itself be a system-level robot
// (or a system administrator); anything else gets 403 here, which callers
// should treat as a skipped check rather than a fatal one.
func (c *HarborClient) SystemRobots(ctx context.Context) ([]HarborRobot, error) {
	return c.listRobots(ctx, "Level=system")
}

// ProjectRobots lists the robot accounts owned by one project. Harbor's
// /robots endpoint silently defaults to level=system, so project robots are
// invisible unless the level and project are named explicitly — and a CI
// robot is usually a project one. Needs the project-scope "robot: list"
// permission.
func (c *HarborClient) ProjectRobots(ctx context.Context, projectID int64) ([]HarborRobot, error) {
	return c.listRobots(ctx, "Level=project,ProjectID="+strconv.FormatInt(projectID, 10))
}

// listRobots pages through /robots with Harbor's "q" filter syntax.
func (c *HarborClient) listRobots(ctx context.Context, filter string) ([]HarborRobot, error) {
	var robots []HarborRobot
	for page := 1; ; page++ {
		var batch []HarborRobot
		path := fmt.Sprintf("/robots?q=%s&page=%d&page_size=%d",
			url.QueryEscape(filter), page, harborPageSize)
		if err := c.get(ctx, path, false, &batch); err != nil {
			return nil, err
		}
		robots = append(robots, batch...)
		if len(batch) < harborPageSize {
			return robots, nil
		}
	}
}
