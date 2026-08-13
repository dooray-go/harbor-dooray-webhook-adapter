package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureServer records the JSON bodies posted to it.
type captureServer struct {
	bodies []map[string]any
	status int
}

func (c *captureServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Errorf("posted body is not JSON: %v (%s)", err, body)
		}
		c.bodies = append(c.bodies, parsed)
		if c.status != 0 {
			http.Error(w, "nope", c.status)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// firstAttachment digs the single attachment out of a captured payload.
func firstAttachment(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	list, ok := body["attachments"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("expected exactly 1 attachment in %v", body)
	}
	att, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("attachment is not an object: %v", list[0])
	}
	return att
}

var sampleNotification = Notification{
	Summary: "Harbor expiry watch: *started*",
	Title:   "[Harbor] Expiry watch started",
	Body:    "- something `expires` soon",
	Color:   "red",
}

func TestSlackNotifierPayload(t *testing.T) {
	cap := &captureServer{}
	srv := cap.start(t)
	adapter := NewAdapter(newTestConfig("https://dooray.example/hook", nil))

	s := &SlackNotifier{
		url:       srv.URL,
		channel:   "#harbor-alerts",
		username:  "Harbor",
		iconEmoji: ":whale:",
		post:      adapter.postJSON,
	}
	if err := s.Notify(sampleNotification); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if len(cap.bodies) != 1 {
		t.Fatalf("expected 1 post, got %d", len(cap.bodies))
	}

	body := cap.bodies[0]
	if body["channel"] != "#harbor-alerts" {
		t.Errorf("channel = %v, want #harbor-alerts", body["channel"])
	}
	if body["username"] != "Harbor" || body["icon_emoji"] != ":whale:" {
		t.Errorf("identity fields wrong: %v", body)
	}
	if body["text"] != sampleNotification.Summary {
		t.Errorf("text = %v", body["text"])
	}

	att := firstAttachment(t, body)
	if att["title"] != sampleNotification.Title || att["text"] != sampleNotification.Body {
		t.Errorf("attachment content wrong: %v", att)
	}
	// Slack does not understand Dooray's colour names.
	if att["color"] != "danger" {
		t.Errorf("color = %v, want danger", att["color"])
	}
	// Without mrkdwn_in the backticks in the body render literally.
	mrkdwn, ok := att["mrkdwn_in"].([]any)
	if !ok || len(mrkdwn) != 1 || mrkdwn[0] != "text" {
		t.Errorf("mrkdwn_in = %v, want [text]", att["mrkdwn_in"])
	}
}

func TestSlackNotifierOmitsUnsetChannel(t *testing.T) {
	cap := &captureServer{}
	srv := cap.start(t)
	adapter := NewAdapter(newTestConfig("https://dooray.example/hook", nil))

	s := &SlackNotifier{url: srv.URL, post: adapter.postJSON}
	if err := s.Notify(sampleNotification); err != nil {
		t.Fatalf("notify: %v", err)
	}
	// An empty channel must be absent, not "", so Slack uses the channel the
	// webhook is bound to.
	if _, present := cap.bodies[0]["channel"]; present {
		t.Errorf("empty channel should be omitted from the payload: %v", cap.bodies[0])
	}
}

func TestDoorayNotifierPayload(t *testing.T) {
	cap := &captureServer{}
	srv := cap.start(t)
	adapter := NewAdapter(newTestConfig("https://dooray.example/hook", nil))

	d := &DoorayNotifier{
		url:          srv.URL,
		botName:      "Harbor",
		botIconImage: "https://example.com/icon.png",
		post:         adapter.postJSON,
	}
	if err := d.Notify(sampleNotification); err != nil {
		t.Fatalf("notify: %v", err)
	}

	body := cap.bodies[0]
	if body["botName"] != "Harbor" {
		t.Errorf("botName = %v", body["botName"])
	}
	att := firstAttachment(t, body)
	// Dooray keeps the plain colour name.
	if att["color"] != "red" {
		t.Errorf("color = %v, want red", att["color"])
	}
}

func TestSlackNotifierReportsHTTPFailure(t *testing.T) {
	cap := &captureServer{status: http.StatusBadRequest}
	srv := cap.start(t)
	adapter := NewAdapter(newTestConfig("https://dooray.example/hook", nil))

	s := &SlackNotifier{url: srv.URL, post: adapter.postJSON}
	err := s.Notify(sampleNotification)
	if err == nil {
		t.Fatal("expected an error for a non-2xx Slack response")
	}
	if !strings.Contains(err.Error(), "slack") || !strings.Contains(err.Error(), "400") {
		t.Errorf("error should name the service and status: %v", err)
	}
}

// failingNotifier always fails, to prove one dead destination does not silence
// the others.
type failingNotifier struct{ name string }

func (f *failingNotifier) Notify(Notification) error { return fmt.Errorf("boom") }
func (f *failingNotifier) Target() string            { return f.name }

func TestNotifiersDeliverDespiteOneFailure(t *testing.T) {
	ok := &captureNotifier{}
	ns := Notifiers{&failingNotifier{name: "slack"}, ok}

	err := ns.Notify(sampleNotification)
	if err == nil {
		t.Fatal("expected the failure to be reported")
	}
	if !strings.Contains(err.Error(), "slack") {
		t.Errorf("error should name the failing target: %v", err)
	}
	if len(ok.sent) != 1 {
		t.Error("a failing destination must not stop delivery to the others")
	}
}

func TestNotifiersTargetNamesEveryDestination(t *testing.T) {
	ns := Notifiers{
		&DoorayNotifier{},
		&SlackNotifier{channel: "#harbor-alerts"},
	}
	if got, want := ns.Target(), "dooray + slack(#harbor-alerts)"; got != want {
		t.Errorf("Target() = %q, want %q", got, want)
	}
}

func TestNormalizeSlackChannel(t *testing.T) {
	cases := map[string]string{
		"harbor-alerts":  "#harbor-alerts", // the common mistake, fixed silently
		"#harbor-alerts": "#harbor-alerts",
		"@someone":       "@someone",
		"  spaced  ":     "#spaced",
		"":               "",
		"C01ABCDEFG":     "C01ABCDEFG", // a channel ID must not be prefixed
	}
	for in, want := range cases {
		if got := normalizeSlackChannel(in); got != want {
			t.Errorf("normalizeSlackChannel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSlackColorMapping(t *testing.T) {
	cases := map[string]string{
		"red":     "danger",
		"yellow":  "warning",
		"green":   "good",
		"blue":    "#3aa3e3",
		"#123456": "#123456",
	}
	for in, want := range cases {
		if got := slackColor(in); got != want {
			t.Errorf("slackColor(%q) = %q, want %q", in, got, want)
		}
	}
}
