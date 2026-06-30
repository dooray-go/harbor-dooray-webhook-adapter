package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const samplePayload = `{
  "type": "PUSH_ARTIFACT",
  "occur_at": 1781872026,
  "operator": "admin",
  "event_data": {
    "resources": [
      {
        "digest": "sha256:a47921a2247b977ec3097cb1cb33ed2a96b4bf29a67664f331ef286a111b7d52",
        "tag": "v1.0.0",
        "resource_url": "https://example.com/library/nginx:v1.0.0"
      }
    ],
    "repository": {
      "date_creation": 1781871000,
      "name": "nginx",
      "namespace": "library",
      "repo_full_name": "library/nginx",
      "repo_type": "private"
    }
  }
}`

func newTestConfig(defaultURL string, repos map[string]string) *Config {
	c := &Config{
		Dooray: DoorayConfig{
			DefaultWebhookURL: defaultURL,
			Repositories:      repos,
		},
	}
	c.applyDefaults()
	return c
}

func TestBuildDoorayPayload(t *testing.T) {
	var hook HarborWebhook
	if err := json.Unmarshal([]byte(samplePayload), &hook); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	a := NewAdapter(newTestConfig("https://default.example/hook", nil))
	p := a.buildDoorayPayload(&hook)
	if p.BotName == "" {
		t.Fatal("expected bot name to be set")
	}
	if len(p.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(p.Attachments))
	}
	att := p.Attachments[0]
	if !strings.Contains(att.Title, "PUSH_ARTIFACT") {
		t.Errorf("title missing event type: %s", att.Title)
	}
	if !strings.Contains(att.Title, "library/nginx") {
		t.Errorf("title missing repo: %s", att.Title)
	}
	if !strings.Contains(att.Text, "v1.0.0") {
		t.Errorf("text missing tag: %s", att.Text)
	}
	if !strings.Contains(att.Text, "admin") {
		t.Errorf("text missing operator: %s", att.Text)
	}
	if att.Color != "green" {
		t.Errorf("expected green color for PUSH_ARTIFACT, got %s", att.Color)
	}
	if att.TitleLink != "https://example.com/library/nginx:v1.0.0" {
		t.Errorf("unexpected title link: %s", att.TitleLink)
	}
}

func TestEventColor(t *testing.T) {
	cases := map[string]string{
		"PUSH_ARTIFACT":   "green",
		"DELETE_ARTIFACT": "red",
		"REPLICATION":     "yellow",
		"UNKNOWN_EVENT":   "blue",
	}
	for in, want := range cases {
		if got := eventColor(in); got != want {
			t.Errorf("eventColor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShortDigest(t *testing.T) {
	d := "sha256:a47921a2247b977ec3097cb1cb33ed2a96b4bf29a67664f331ef286a111b7d52"
	got := shortDigest(d)
	if got != "sha256:a47921a2247b" {
		t.Errorf("shortDigest = %q", got)
	}
	if shortDigest("short") != "short" {
		t.Errorf("expected passthrough for short digest")
	}
}

func TestWebhookHandlerForwardsToDefault(t *testing.T) {
	var received []byte
	doorayStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer doorayStub.Close()

	a := NewAdapter(newTestConfig(doorayStub.URL, nil))

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewBufferString(samplePayload))
	rr := httptest.NewRecorder()
	a.webhookHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var dw DoorayWebhook
	if err := json.Unmarshal(received, &dw); err != nil {
		t.Fatalf("forwarded body not valid dooray json: %v", err)
	}
	if len(dw.Attachments) == 0 || !strings.Contains(dw.Attachments[0].Text, "library/nginx") {
		t.Errorf("forwarded payload missing repo info: %+v", dw)
	}
}

func TestWebhookHandlerUsesPerRepoRoute(t *testing.T) {
	hits := make(map[string]bool)
	stubA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits["A"] = true
		w.WriteHeader(http.StatusOK)
	}))
	defer stubA.Close()
	stubDefault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits["DEFAULT"] = true
		w.WriteHeader(http.StatusOK)
	}))
	defer stubDefault.Close()

	a := NewAdapter(newTestConfig(stubDefault.URL, map[string]string{
		"library/nginx": stubA.URL,
	}))

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewBufferString(samplePayload))
	rr := httptest.NewRecorder()
	a.webhookHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !hits["A"] || hits["DEFAULT"] {
		t.Errorf("expected route to stubA only, hits=%v", hits)
	}
}

func TestWebhookHandlerNoRouteConfigured(t *testing.T) {
	a := NewAdapter(newTestConfig("", map[string]string{
		"other/repo": "https://example.com/hook",
	}))

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewBufferString(samplePayload))
	rr := httptest.NewRecorder()
	a.webhookHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when repo has no route, got %d", rr.Code)
	}
}

func TestWebhookHandlerRejectsGET(t *testing.T) {
	a := NewAdapter(newTestConfig("https://example.com/hook", nil))
	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	rr := httptest.NewRecorder()
	a.webhookHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}
