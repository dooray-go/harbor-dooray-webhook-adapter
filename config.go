package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string       `yaml:"listen_addr"`
	Dooray     DoorayConfig `yaml:"dooray"`
	Harbor     HarborConfig `yaml:"harbor"`
}

// HarborConfig holds the API credentials used by the expiry watcher. The
// webhook receiver itself never calls Harbor, so this section is optional.
type HarborConfig struct {
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`

	ExpiryWatch ExpiryWatchConfig `yaml:"expiry_watch"`
}

// ExpiryWatchConfig configures polling for CVE allowlist and robot account
// expiry dates. Harbor emits no webhook when either lapses — the allowlist
// simply stops applying and pulls begin failing with 412 — so the dates have to
// be polled ahead of time.
type ExpiryWatchConfig struct {
	// Enabled defaults to true whenever harbor.url is set.
	Enabled *bool `yaml:"enabled"`
	// Interval is a Go duration such as "24h" (default).
	Interval string `yaml:"interval"`
	// WarnDays are the countdown steps that trigger a notification, e.g.
	// [30, 14, 7, 3, 1]. Anything already expired is re-announced daily.
	WarnDays []int `yaml:"warn_days"`
	// Projects limits the check to these project names. Empty means every
	// project the account can see.
	Projects []string `yaml:"projects"`
	// WatchRobots also tracks robot account expiry (default true). Listing
	// robots requires a system administrator account.
	WatchRobots *bool `yaml:"watch_robots"`
	// WebhookURL overrides where expiry warnings are sent. Empty falls back to
	// dooray.default_webhook_url.
	WebhookURL string `yaml:"webhook_url"`

	// interval is Interval parsed; 0 when it could not be parsed.
	interval time.Duration
}

type DoorayConfig struct {
	DefaultWebhookURL string            `yaml:"default_webhook_url"`
	BotName           string            `yaml:"bot_name"`
	BotIconImage      string            `yaml:"bot_icon_image"`
	Repositories      map[string]string `yaml:"repositories"`

	// CriticalCVEThreshold colors the Dooray notification red when a scan
	// report's Critical vulnerability count reaches this value (default 1).
	// Set to 0 to disable the red override. Only affects SCANNING_COMPLETED
	// events, which are the ones that carry a scan summary.
	CriticalCVEThreshold *int `yaml:"critical_cve_threshold"`

	// AllowedEvents is a whitelist of Harbor event types to forward. Empty
	// means all event types are forwarded. Comparison is case-insensitive.
	AllowedEvents []string `yaml:"allowed_events"`
	// IgnoreOperatorsContaining drops events whose operator contains any of the
	// given substrings (case-insensitive). Use this to silence the Trivy
	// scanner (operator contains "-Trivy-") while still forwarding pushes made
	// by CI robot accounts. Empty means no operator is filtered out.
	IgnoreOperatorsContaining []string `yaml:"ignore_operators_containing"`
	// IgnoreUntagged drops events whose resources are all digest-only (tag empty
	// or "sha256:..."). These are accessory artifacts — SBOM documents, cosign
	// signatures and scan reports — that Harbor pushes/deletes around scanning,
	// not images a human pushed or deleted by tag.
	IgnoreUntagged bool `yaml:"ignore_untagged"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.Dooray.BotName == "" {
		c.Dooray.BotName = "Harbor"
	}
	if c.Dooray.BotIconImage == "" {
		c.Dooray.BotIconImage = "https://goharbor.io/img/logos/harbor-icon-color.png"
	}
	if c.Dooray.CriticalCVEThreshold == nil {
		def := 1
		c.Dooray.CriticalCVEThreshold = &def
	}

	c.Harbor.URL = strings.TrimRight(strings.TrimSpace(c.Harbor.URL), "/")
	w := &c.Harbor.ExpiryWatch
	if w.Interval == "" {
		w.Interval = "24h"
	}
	if d, err := time.ParseDuration(w.Interval); err == nil {
		w.interval = d
	}
	if len(w.WarnDays) == 0 {
		w.WarnDays = []int{30, 14, 7, 3, 1}
	}
	w.WarnDays = normalizeWarnDays(w.WarnDays)
}

// normalizeWarnDays drops non-positive entries, removes duplicates and sorts
// ascending, which is the order expiryBucket expects.
func normalizeWarnDays(days []int) []int {
	seen := make(map[int]bool, len(days))
	out := make([]int, 0, len(days))
	for _, d := range days {
		if d <= 0 || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Ints(out)
	return out
}

// ExpiryWatchEnabled reports whether the expiry watcher should run. It needs a
// Harbor URL; beyond that it is on unless explicitly disabled.
func (c *Config) ExpiryWatchEnabled() bool {
	if c.Harbor.URL == "" {
		return false
	}
	return c.Harbor.ExpiryWatch.Enabled == nil || *c.Harbor.ExpiryWatch.Enabled
}

func (c *Config) validate() error {
	if c.Dooray.DefaultWebhookURL == "" && len(c.Dooray.Repositories) == 0 {
		return fmt.Errorf("config must set either dooray.default_webhook_url or dooray.repositories")
	}
	if c.Harbor.URL != "" && !strings.HasPrefix(c.Harbor.URL, "http://") && !strings.HasPrefix(c.Harbor.URL, "https://") {
		return fmt.Errorf("harbor.url must start with http:// or https://")
	}
	if !c.ExpiryWatchEnabled() {
		return nil
	}
	w := c.Harbor.ExpiryWatch
	if c.Harbor.Username == "" || c.Harbor.Password == "" {
		return fmt.Errorf("harbor.username and harbor.password are required when the expiry watch is enabled")
	}
	if w.interval <= 0 {
		return fmt.Errorf("harbor.expiry_watch.interval %q is not a positive duration (e.g. \"24h\")", w.Interval)
	}
	if len(w.WarnDays) == 0 {
		return fmt.Errorf("harbor.expiry_watch.warn_days must contain at least one positive number of days")
	}
	if w.WebhookURL == "" && c.Dooray.DefaultWebhookURL == "" {
		return fmt.Errorf("harbor.expiry_watch needs dooray.default_webhook_url or harbor.expiry_watch.webhook_url to send warnings to")
	}
	return nil
}

// ShouldForward reports whether an event of the given type and operator should
// be forwarded to Dooray. When it returns false, the second value is a short
// human-readable reason for logging.
func (c *Config) ShouldForward(h *HarborWebhook) (bool, string) {
	lowerOp := strings.ToLower(h.Operator)
	for _, sub := range c.Dooray.IgnoreOperatorsContaining {
		sub = strings.TrimSpace(sub)
		if sub != "" && strings.Contains(lowerOp, strings.ToLower(sub)) {
			return false, fmt.Sprintf("operator contains %q", sub)
		}
	}
	if c.Dooray.IgnoreUntagged && len(h.EventData.Resources) > 0 && allUntagged(h.EventData.Resources) {
		return false, "untagged artifact (sbom/signature/scan accessory)"
	}
	if len(c.Dooray.AllowedEvents) > 0 {
		for _, e := range c.Dooray.AllowedEvents {
			if strings.EqualFold(strings.TrimSpace(e), h.Type) {
				return true, ""
			}
		}
		return false, "event type not in allowed_events"
	}
	return true, ""
}

// allUntagged reports whether every resource lacks a human-readable tag, i.e.
// the tag is empty or a bare digest ("sha256:..."). Such resources are Harbor
// accessory artifacts (SBOM, signatures, scan reports) rather than tagged images.
func allUntagged(resources []Resource) bool {
	for _, r := range resources {
		if r.Tag != "" && !strings.HasPrefix(r.Tag, "sha256:") {
			return false
		}
	}
	return true
}

func (c *Config) ResolveDoorayURL(repoFullName string) string {
	if u, ok := c.Dooray.Repositories[repoFullName]; ok && u != "" {
		return u
	}
	return c.Dooray.DefaultWebhookURL
}
