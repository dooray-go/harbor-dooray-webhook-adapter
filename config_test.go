package main

import (
	"os"
	"path/filepath"
	"testing"
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
