package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	path := writeTempConfig(t, `
dooray:
  default_webhook_url: https://example.com/default
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("default listen_addr wrong: %q", cfg.ListenAddr)
	}
	if cfg.Dooray.BotName != "Harbor" {
		t.Errorf("default bot name wrong: %q", cfg.Dooray.BotName)
	}
	if cfg.Dooray.BotIconImage == "" {
		t.Error("expected default bot icon")
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	path := writeTempConfig(t, `
listen_addr: ":9090"
dooray:
  default_webhook_url: https://example.com/default
  bot_name: MyBot
  bot_icon_image: https://example.com/icon.png
  repositories:
    library/nginx: https://example.com/nginx
    team/api: https://example.com/api
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("listen_addr override failed: %q", cfg.ListenAddr)
	}
	if cfg.Dooray.BotName != "MyBot" {
		t.Errorf("bot_name override failed: %q", cfg.Dooray.BotName)
	}
	if got := cfg.ResolveDoorayURL("library/nginx"); got != "https://example.com/nginx" {
		t.Errorf("route nginx: %q", got)
	}
	if got := cfg.ResolveDoorayURL("unknown/repo"); got != "https://example.com/default" {
		t.Errorf("fallback to default: %q", got)
	}
}

// hook builds a minimal HarborWebhook with the given type, operator and resource tags.
func hook(eventType, operator string, tags ...string) *HarborWebhook {
	h := &HarborWebhook{Type: eventType, Operator: operator}
	for _, tag := range tags {
		h.EventData.Resources = append(h.EventData.Resources, Resource{Tag: tag})
	}
	return h
}

func TestShouldForward(t *testing.T) {
	path := writeTempConfig(t, `
dooray:
  default_webhook_url: https://example.com/default
  ignore_operators_containing:
    - "-Trivy-"
  ignore_untagged: true
  allowed_events:
    - PUSH_ARTIFACT
    - DELETE_ARTIFACT
    - scanning_completed
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	cases := []struct {
		name string
		h    *HarborWebhook
		want bool
	}{
		{"human tagged push", hook("PUSH_ARTIFACT", "admin", "latest"), true},
		{"scanning completed", hook("SCANNING_COMPLETED", "admin"), true},
		{"event not whitelisted", hook("PULL_ARTIFACT", "admin", "latest"), false},
		{"CI robot push kept", hook("PUSH_ARTIFACT", "robot$doorayci-build", "v1.2.3"), true},
		{"scanner pull dropped", hook("PULL_ARTIFACT", "robot$dooray+n5yhKABW-Trivy-edaf9aa2", "latest"), false},
		{"sbom accessory delete dropped", hook("DELETE_ARTIFACT", "admin", "sha256:dc80f90bcd90"), false},
		{"human digest-less delete dropped", hook("DELETE_ARTIFACT", "admin", ""), false},
		{"human tagged delete kept", hook("DELETE_ARTIFACT", "admin", "v1.0.0"), true},
	}
	for _, tc := range cases {
		if got, reason := cfg.ShouldForward(tc.h); got != tc.want {
			t.Errorf("%s: ShouldForward = %v (reason %q), want %v", tc.name, got, reason, tc.want)
		}
	}
}

func TestShouldForwardEmptyAllowsAll(t *testing.T) {
	path := writeTempConfig(t, `
dooray:
  default_webhook_url: https://example.com/default
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ok, _ := cfg.ShouldForward(hook("ANYTHING", "admin")); !ok {
		t.Error("empty allowed_events should forward all events")
	}
	if ok, _ := cfg.ShouldForward(hook("PUSH_ARTIFACT", "robot$dooray+x-Trivy-abc")); !ok {
		t.Error("no operator filter configured should forward all operators")
	}
	if ok, _ := cfg.ShouldForward(hook("DELETE_ARTIFACT", "admin", "sha256:abc")); !ok {
		t.Error("untagged should pass when ignore_untagged is false")
	}
}

func TestLoadConfigRequiresSomeURL(t *testing.T) {
	path := writeTempConfig(t, `
listen_addr: ":8080"
dooray:
  bot_name: X
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error when no default and no repositories")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestExpiryWatchDefaults(t *testing.T) {
	path := writeTempConfig(t, `
dooray:
  default_webhook_url: https://example.com/default
harbor:
  url: https://harbor.example.com/
  username: robot$watch
  password: secret
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.ExpiryWatchEnabled() {
		t.Error("a configured harbor.url should enable the expiry watch")
	}
	if cfg.Harbor.URL != "https://harbor.example.com" {
		t.Errorf("trailing slash should be trimmed, got %q", cfg.Harbor.URL)
	}
	if cfg.Harbor.ExpiryWatch.interval != 24*time.Hour {
		t.Errorf("default interval wrong: %v", cfg.Harbor.ExpiryWatch.interval)
	}
	want := []int{1, 3, 7, 14, 30}
	if got := cfg.Harbor.ExpiryWatch.WarnDays; !slices.Equal(got, want) {
		t.Errorf("default warn_days = %v, want %v", got, want)
	}
}

func TestExpiryWatchDisabledWithoutHarborURL(t *testing.T) {
	path := writeTempConfig(t, `
dooray:
  default_webhook_url: https://example.com/default
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ExpiryWatchEnabled() {
		t.Error("expiry watch must stay off when no harbor.url is set")
	}
}

func TestExpiryWatchConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing credentials", `
dooray:
  default_webhook_url: https://example.com/default
harbor:
  url: https://harbor.example.com
`},
		{"bad interval", `
dooray:
  default_webhook_url: https://example.com/default
harbor:
  url: https://harbor.example.com
  username: u
  password: p
  expiry_watch:
    interval: "every day"
`},
		{"scheme-less url", `
dooray:
  default_webhook_url: https://example.com/default
harbor:
  url: harbor.example.com
  username: u
  password: p
`},
		{"warn_days all non-positive", `
dooray:
  default_webhook_url: https://example.com/default
harbor:
  url: https://harbor.example.com
  username: u
  password: p
  expiry_watch:
    warn_days: [0, -5]
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadConfig(writeTempConfig(t, c.body)); err == nil {
				t.Fatal("expected a config error")
			}
		})
	}
}

func TestExpiryWatchExplicitlyDisabled(t *testing.T) {
	// Disabled means the credential requirements do not apply.
	path := writeTempConfig(t, `
dooray:
  default_webhook_url: https://example.com/default
harbor:
  url: https://harbor.example.com
  expiry_watch:
    enabled: false
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ExpiryWatchEnabled() {
		t.Error("expiry_watch.enabled=false must win over a configured harbor.url")
	}
}

// harborConfig builds a loadable config with the given expiry_watch body.
func harborConfig(watch string) string {
	return `
dooray:
  default_webhook_url: https://example.com/default
harbor:
  url: https://harbor.example.com
  username: u
  password: p
  expiry_watch:` + watch
}

func TestExpiryNotifyTargetRouting(t *testing.T) {
	cases := []struct {
		name       string
		watch      string
		wantDooray string
		wantSlack  string
	}{
		{
			// Nothing specified: keep posting where everything else goes.
			name:       "falls back to the default dooray url",
			watch:      "\n    interval: 24h",
			wantDooray: "https://example.com/default",
		},
		{
			// Slack-only must NOT keep quietly posting to Dooray as well.
			name:      "slack only suppresses the dooray fallback",
			watch:     "\n    slack:\n      webhook_url: https://hooks.slack.com/services/T/B/X",
			wantSlack: "https://hooks.slack.com/services/T/B/X",
		},
		{
			name:       "both destinations when both are set",
			watch:      "\n    dooray:\n      webhook_url: https://example.com/expiry\n    slack:\n      webhook_url: https://hooks.slack.com/services/T/B/X",
			wantDooray: "https://example.com/expiry",
			wantSlack:  "https://hooks.slack.com/services/T/B/X",
		},
		{
			// The flat spelling shipped before Slack support existed.
			name:       "deprecated flat webhook_url still routes to dooray",
			watch:      "\n    webhook_url: https://example.com/legacy",
			wantDooray: "https://example.com/legacy",
		},
		{
			name:       "nested dooray url wins over the flat alias",
			watch:      "\n    webhook_url: https://example.com/legacy\n    dooray:\n      webhook_url: https://example.com/nested",
			wantDooray: "https://example.com/nested",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeTempConfig(t, harborConfig(c.watch)))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got := cfg.expiryDoorayURL(); got != c.wantDooray {
				t.Errorf("dooray target = %q, want %q", got, c.wantDooray)
			}
			if got := cfg.Harbor.ExpiryWatch.Slack.WebhookURL; got != c.wantSlack {
				t.Errorf("slack target = %q, want %q", got, c.wantSlack)
			}
		})
	}
}

func TestSlackDefaultsFollowBotIdentity(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, `
dooray:
  default_webhook_url: https://example.com/default
  bot_name: MyBot
  bot_icon_image: https://example.com/icon.png
harbor:
  url: https://harbor.example.com
  username: u
  password: p
  expiry_watch:
    slack:
      webhook_url: https://hooks.slack.com/services/T/B/X
      channel: harbor-alerts
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s := cfg.Harbor.ExpiryWatch.Slack
	if s.Channel != "#harbor-alerts" {
		t.Errorf("channel should be normalized to #harbor-alerts, got %q", s.Channel)
	}
	if s.Username != "MyBot" {
		t.Errorf("slack username should default to the dooray bot name, got %q", s.Username)
	}
	if s.IconURL != "https://example.com/icon.png" {
		t.Errorf("slack icon should default to the dooray bot icon, got %q", s.IconURL)
	}
}

func TestExpiryWatchNeedsADestination(t *testing.T) {
	// No default_webhook_url, no expiry target: the watcher would have nowhere
	// to report, so refuse at startup rather than warn into the void.
	_, err := LoadConfig(writeTempConfig(t, `
dooray:
  repositories:
    library/nginx: https://example.com/nginx
harbor:
  url: https://harbor.example.com
  username: u
  password: p
`))
	if err == nil {
		t.Fatal("expected an error when the expiry watch has no destination")
	}
}

func TestSlackWebhookURLNeedsScheme(t *testing.T) {
	_, err := LoadConfig(writeTempConfig(t, harborConfig("\n    slack:\n      webhook_url: hooks.slack.com/services/T/B/X")))
	if err == nil {
		t.Fatal("expected an error for a scheme-less slack webhook_url")
	}
}

// The shipped example must stay loadable, since it is what people copy.
func TestLoadExampleConfig(t *testing.T) {
	cfg, err := LoadConfig("config.example.yaml")
	if err != nil {
		t.Fatalf("config.example.yaml does not load: %v", err)
	}
	if !cfg.ExpiryWatchEnabled() {
		t.Error("the example enables the expiry watch")
	}
}

func TestNormalizeWarnDays(t *testing.T) {
	got := normalizeWarnDays([]int{7, 30, 7, 0, -3, 1})
	want := []int{1, 7, 30}
	if !slices.Equal(got, want) {
		t.Errorf("normalizeWarnDays = %v, want %v", got, want)
	}
}
