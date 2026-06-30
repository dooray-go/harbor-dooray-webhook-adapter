package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string       `yaml:"listen_addr"`
	Dooray     DoorayConfig `yaml:"dooray"`
}

type DoorayConfig struct {
	DefaultWebhookURL string            `yaml:"default_webhook_url"`
	BotName           string            `yaml:"bot_name"`
	BotIconImage      string            `yaml:"bot_icon_image"`
	Repositories      map[string]string `yaml:"repositories"`

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
}

func (c *Config) validate() error {
	if c.Dooray.DefaultWebhookURL == "" && len(c.Dooray.Repositories) == 0 {
		return fmt.Errorf("config must set either dooray.default_webhook_url or dooray.repositories")
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
