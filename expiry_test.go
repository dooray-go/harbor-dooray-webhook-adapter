package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)

func days(n float64) time.Duration { return time.Duration(n * float64(24*time.Hour)) }

// fakeHarbor serves the handful of v2.0 endpoints the watcher reads. Each field
// is the JSON body for that endpoint; status overrides turn an endpoint into a
// failure.
type fakeHarbor struct {
	system      CVEAllowlist
	projects    map[string]HarborProject
	order       []string
	robots      []HarborRobot
	projectsErr int
	robotsErr   int

	requests int
}

func (f *fakeHarbor) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/api/v2.0/system/CVEAllowlist", func(w http.ResponseWriter, r *http.Request) {
		write(w, f.system)
	})
	mux.HandleFunc("/api/v2.0/projects", func(w http.ResponseWriter, r *http.Request) {
		if f.projectsErr != 0 {
			http.Error(w, "boom", f.projectsErr)
			return
		}
		list := make([]HarborProject, 0, len(f.order))
		for _, name := range f.order {
			list = append(list, HarborProject{Name: name})
		}
		write(w, list)
	})
	mux.HandleFunc("/api/v2.0/projects/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v2.0/projects/")
		if r.Header.Get("X-Is-Resource-Name") != "true" {
			http.Error(w, "expected X-Is-Resource-Name header", http.StatusBadRequest)
			return
		}
		p, ok := f.projects[name]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		write(w, p)
	})
	mux.HandleFunc("/api/v2.0/robots", func(w http.ResponseWriter, r *http.Request) {
		if f.robotsErr != 0 {
			http.Error(w, "forbidden", f.robotsErr)
			return
		}
		write(w, f.robots)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		if u, p, ok := r.BasicAuth(); !ok || u != "robot$watch" || p != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func epoch(t time.Time) *int64 { v := t.Unix(); return &v }

// sampleHarbor builds an instance with one of every interesting case.
func sampleHarbor() *fakeHarbor {
	return &fakeHarbor{
		system: CVEAllowlist{
			ExpiresAt: epoch(testNow.Add(days(10))),
			Items:     []CVEAllowlistItem{{CVEID: "CVE-1"}, {CVEID: "CVE-2"}},
		},
		order: []string{"alpha", "beta", "gamma"},
		projects: map[string]HarborProject{
			// Own allowlist, policy enforced: the dangerous case.
			"alpha": {
				Name:     "alpha",
				Metadata: ProjectMetadata{PreventVul: "true", Severity: "High", ReuseSysCVEAllowlist: "false"},
				CVEAllowlist: CVEAllowlist{
					ExpiresAt: epoch(testNow.Add(days(5))),
					Items:     []CVEAllowlistItem{{CVEID: "CVE-3"}},
				},
			},
			// Reuses the system allowlist (metadata absent = Harbor's default)
			// and enforces, so it is what makes the system allowlist risky.
			"beta": {
				Name:         "beta",
				Metadata:     ProjectMetadata{PreventVul: "true", Severity: "Critical"},
				CVEAllowlist: CVEAllowlist{ExpiresAt: epoch(testNow.Add(days(1)))},
			},
			// Own allowlist expiring soon, but the policy is off: informational.
			"gamma": {
				Name:     "gamma",
				Metadata: ProjectMetadata{PreventVul: "false", ReuseSysCVEAllowlist: "false"},
				CVEAllowlist: CVEAllowlist{
					ExpiresAt: epoch(testNow.Add(days(2))),
					Items:     []CVEAllowlistItem{{CVEID: "CVE-4"}},
				},
			},
		},
		robots: []HarborRobot{
			{ID: 1, Name: "robot$ci", Level: "system", ExpiresAt: testNow.Add(days(3)).Unix()},
			{ID: 2, Name: "robot$forever", Level: "system", ExpiresAt: -1},
		},
	}
}

// captureNotifier records notifications instead of delivering them.
type captureNotifier struct {
	sent []Notification
	err  error
}

func (c *captureNotifier) Notify(n Notification) error {
	c.sent = append(c.sent, n)
	return c.err
}

func (c *captureNotifier) Target() string { return "capture" }

// newWatcher wires a watcher against the fake Harbor, capturing notifications
// instead of posting them.
func newWatcher(t *testing.T, h *fakeHarbor) (*ExpiryWatcher, *captureNotifier) {
	t.Helper()
	srv := h.start(t)

	cfg := &Config{
		Dooray: DoorayConfig{DefaultWebhookURL: "https://dooray.example/hook"},
		Harbor: HarborConfig{URL: srv.URL, Username: "robot$watch", Password: "secret"},
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	capture := &captureNotifier{}
	w := NewExpiryWatcher(cfg, NewAdapter(cfg))
	w.now = func() time.Time { return testNow }
	w.notifier = capture
	return w, capture
}

func findFinding(t *testing.T, findings []ExpiryFinding, kind, name string) ExpiryFinding {
	t.Helper()
	for _, f := range findings {
		if f.Kind == kind && f.Name == name {
			return f
		}
	}
	t.Fatalf("no finding for %s %q in %+v", kind, name, findings)
	return ExpiryFinding{}
}

func TestCollectFindsEveryExpiringThing(t *testing.T) {
	w, _ := newWatcher(t, sampleHarbor())

	findings, warnings, err := w.collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d: %+v", len(findings), findings)
	}

	alpha := findFinding(t, findings, kindProjectAllowlist, "alpha")
	if alpha.DaysLeft != 5 || !alpha.Enforcing {
		t.Errorf("alpha: got daysLeft=%d enforcing=%v, want 5/true", alpha.DaysLeft, alpha.Enforcing)
	}
	if !strings.Contains(alpha.Detail, "severity High") {
		t.Errorf("alpha detail should name the blocking severity, got %q", alpha.Detail)
	}

	// gamma expires sooner than alpha but cannot block a pull.
	gamma := findFinding(t, findings, kindProjectAllowlist, "gamma")
	if gamma.Enforcing {
		t.Error("gamma has prevent_vul off, so its expiry must not count as enforcing")
	}

	// beta reuses the system allowlist, so its own expiry date is inert and
	// must not be reported — but it makes the system allowlist enforcing.
	for _, f := range findings {
		if f.Kind == kindProjectAllowlist && f.Name == "beta" {
			t.Error("beta reuses the system allowlist; its own expiry is ignored by Harbor")
		}
	}
	sys := findFinding(t, findings, kindSystemAllowlist, "system")
	if !sys.Enforcing || !strings.Contains(sys.Detail, "beta") {
		t.Errorf("system allowlist should be enforcing via beta, got %+v", sys)
	}

	robot := findFinding(t, findings, kindRobot, "robot$ci")
	if robot.DaysLeft != 3 {
		t.Errorf("robot$ci: got daysLeft=%d, want 3", robot.DaysLeft)
	}
	for _, f := range findings {
		if f.Name == "robot$forever" {
			t.Error("a robot with expires_at=-1 never expires and must not be reported")
		}
	}
}

func TestCollectDegradesWhenRobotsForbidden(t *testing.T) {
	h := sampleHarbor()
	h.robotsErr = http.StatusForbidden
	w, _ := newWatcher(t, h)

	findings, warnings, err := w.collect(context.Background())
	if err != nil {
		t.Fatalf("a 403 on /robots must not fail the whole poll: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("expected the 3 allowlist findings to survive, got %d", len(findings))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "robot") {
		t.Errorf("expected a warning about robots, got %v", warnings)
	}
}

func TestCollectFailsWhenProjectsUnreadable(t *testing.T) {
	h := sampleHarbor()
	h.projectsErr = http.StatusUnauthorized
	w, _ := newWatcher(t, h)

	if _, _, err := w.collect(context.Background()); err == nil {
		t.Fatal("expected an error when projects cannot be listed")
	}
}

func TestFirstPollReportsFullInventory(t *testing.T) {
	w, sent := newWatcher(t, sampleHarbor())
	w.checkOnce(context.Background())

	if len(sent.sent) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(sent.sent))
	}
	n := sent.sent[0]
	if !strings.Contains(n.Title, "Expiry watch started") {
		t.Errorf("unexpected title %q", n.Title)
	}
	// Every dated item is listed, even the ones still far out, because an
	// expiry date nobody remembers setting is the actual hazard.
	for _, want := range []string{"alpha", "gamma", "system", "robot$ci"} {
		if !strings.Contains(n.Body, want) {
			t.Errorf("inventory missing %q:\n%s", want, n.Body)
		}
	}
	if n.Color != "red" {
		t.Errorf("robot$ci is 3 days out and enforcing, so color should be red, got %q", n.Color)
	}
}

func TestSteadyStateDoesNotRepeatWarnings(t *testing.T) {
	w, sent := newWatcher(t, sampleHarbor())
	w.checkOnce(context.Background()) // inventory
	w.checkOnce(context.Background())
	w.checkOnce(context.Background())

	if len(sent.sent) != 1 {
		t.Fatalf("nothing changed, so only the inventory should have been sent; got %d", len(sent.sent))
	}
}

func TestWarningFiresWhenCrossingAStep(t *testing.T) {
	w, sent := newWatcher(t, sampleHarbor())
	w.checkOnce(context.Background()) // inventory at D-5 for alpha

	// Two days on: alpha moves from the D-7 step into D-3.
	w.now = func() time.Time { return testNow.Add(days(2)) }
	w.checkOnce(context.Background())

	if len(sent.sent) != 2 {
		t.Fatalf("expected an expiry warning, got %d notifications", len(sent.sent))
	}
	n := sent.sent[1]
	if !strings.Contains(n.Body, "alpha") {
		t.Errorf("warning should name alpha:\n%s", n.Body)
	}
	if !strings.Contains(n.Body, "412") {
		t.Errorf("warning should explain the 412 consequence:\n%s", n.Body)
	}
}

func TestExpiredItemsAreReannouncedDaily(t *testing.T) {
	w, sent := newWatcher(t, sampleHarbor())
	w.checkOnce(context.Background())

	// Six days on, alpha is one day past its expiry.
	w.now = func() time.Time { return testNow.Add(days(6)) }
	w.checkOnce(context.Background())
	first := len(sent.sent)

	// The next day it is still broken and must be raised again.
	w.now = func() time.Time { return testNow.Add(days(7)) }
	w.checkOnce(context.Background())

	if len(sent.sent) <= first {
		t.Fatal("an already-expired allowlist must be re-announced every poll day")
	}
	n := sent.sent[len(sent.sent)-1]
	if !strings.Contains(n.Body, "EXPIRED") {
		t.Errorf("expected an EXPIRED marker:\n%s", n.Body)
	}
	if n.Color != "red" {
		t.Errorf("expected red for an expired enforcing allowlist, got %q", n.Color)
	}
}

func TestWatcherReportsItsOwnBlindness(t *testing.T) {
	h := sampleHarbor()
	w, sent := newWatcher(t, h)
	w.checkOnce(context.Background()) // inventory

	h.projectsErr = http.StatusUnauthorized
	for i := 0; i < failureThreshold; i++ {
		w.checkOnce(context.Background())
	}
	if len(sent.sent) != 2 {
		t.Fatalf("expected exactly one blindness alert after %d failures, got %d notifications",
			failureThreshold, len(sent.sent))
	}
	n := sent.sent[1]
	if !strings.Contains(n.Title, "blind") || n.Color != "red" {
		t.Errorf("unexpected blindness alert: %+v", n)
	}

	// Further failures must not spam.
	w.checkOnce(context.Background())
	if len(sent.sent) != 2 {
		t.Fatalf("blindness alert repeated; got %d notifications", len(sent.sent))
	}

	// Recovery is worth saying out loud.
	h.projectsErr = 0
	w.checkOnce(context.Background())
	if len(sent.sent) != 3 {
		t.Fatalf("expected a recovery notice, got %d notifications", len(sent.sent))
	}
	if !strings.Contains(sent.sent[2].Title, "recovered") {
		t.Errorf("unexpected recovery notice: %+v", sent.sent[2])
	}
}

func TestDaysUntil(t *testing.T) {
	cases := []struct {
		name string
		at   time.Time
		want int
	}{
		// Rounded up, so something 6.5 days out still trips the D-7 step.
		{"partial day rounds up", testNow.Add(days(6.5)), 7},
		{"exactly seven days", testNow.Add(days(7)), 7},
		{"hours away", testNow.Add(2 * time.Hour), 1},
		{"just expired", testNow.Add(-time.Minute), 0},
		{"expired yesterday", testNow.Add(-days(1.2)), -1},
		{"expired three days ago", testNow.Add(-days(3)), -3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := daysUntil(c.at, testNow); got != c.want {
				t.Errorf("daysUntil = %d, want %d", got, c.want)
			}
		})
	}
}

func TestExpiryBucket(t *testing.T) {
	warn := []int{1, 3, 7, 14, 30}
	cases := []struct {
		daysLeft int
		want     string
	}{
		{60, ""}, // beyond the furthest warning: silent
		{31, ""},
		{30, "d-30"},
		{20, "d-30"},
		{14, "d-14"},
		{8, "d-14"},
		{7, "d-7"},
		{1, "d-1"},
		{0, "expired:0"},
		{-1, "expired:-1"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.daysLeft), func(t *testing.T) {
			if got := expiryBucket(c.daysLeft, warn); got != c.want {
				t.Errorf("expiryBucket(%d) = %q, want %q", c.daysLeft, got, c.want)
			}
		})
	}
}
