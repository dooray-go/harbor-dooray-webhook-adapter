package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type HarborWebhook struct {
	Type      string    `json:"type"`
	OccurAt   int64     `json:"occur_at"`
	Operator  string    `json:"operator"`
	EventData EventData `json:"event_data"`
}

type EventData struct {
	Resources  []Resource `json:"resources"`
	Repository Repository `json:"repository"`
}

type Resource struct {
	Digest      string `json:"digest"`
	Tag         string `json:"tag"`
	ResourceURL string `json:"resource_url"`
}

type Repository struct {
	DateCreation int64  `json:"date_creation"`
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	RepoFullName string `json:"repo_full_name"`
	RepoType     string `json:"repo_type"`
}

type DoorayWebhook struct {
	BotName      string             `json:"botName"`
	BotIconImage string             `json:"botIconImage,omitempty"`
	Text         string             `json:"text"`
	Attachments  []DoorayAttachment `json:"attachments,omitempty"`
}

type DoorayAttachment struct {
	Title     string `json:"title"`
	TitleLink string `json:"titleLink,omitempty"`
	Text      string `json:"text"`
	Color     string `json:"color,omitempty"`
}

func eventColor(eventType string) string {
	switch eventType {
	case "PUSH_ARTIFACT", "PULL_ARTIFACT", "SCANNING_COMPLETED":
		return "green"
	case "DELETE_ARTIFACT", "SCANNING_FAILED", "SCANNING_STOPPED", "QUOTA_EXCEED":
		return "red"
	case "QUOTA_WARNING", "REPLICATION":
		return "yellow"
	default:
		return "blue"
	}
}

func shortDigest(d string) string {
	if i := strings.Index(d, ":"); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	return d
}

type Adapter struct {
	cfg    *Config
	client *http.Client
}

func NewAdapter(cfg *Config) *Adapter {
	return &Adapter{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *Adapter) buildDoorayPayload(h *HarborWebhook) *DoorayWebhook {
	repo := h.EventData.Repository.RepoFullName
	if repo == "" {
		repo = strings.TrimLeft(h.EventData.Repository.Namespace+"/"+h.EventData.Repository.Name, "/")
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("- Repository: `%s`", repo))
	lines = append(lines, fmt.Sprintf("- Operator: `%s`", h.Operator))
	if h.OccurAt > 0 {
		lines = append(lines, fmt.Sprintf("- Time: %s", time.Unix(h.OccurAt, 0).Format(time.RFC3339)))
	}
	for _, r := range h.EventData.Resources {
		tag := r.Tag
		if tag == "" {
			tag = "(no tag)"
		}
		line := fmt.Sprintf("- Tag: `%s` (digest `%s`)", tag, shortDigest(r.Digest))
		if r.ResourceURL != "" {
			line += fmt.Sprintf("\n  %s", r.ResourceURL)
		}
		lines = append(lines, line)
	}

	title := fmt.Sprintf("[Harbor] %s — %s", h.Type, repo)
	titleLink := ""
	if len(h.EventData.Resources) > 0 {
		titleLink = h.EventData.Resources[0].ResourceURL
	}

	return &DoorayWebhook{
		BotName:      a.cfg.Dooray.BotName,
		BotIconImage: a.cfg.Dooray.BotIconImage,
		Text:         fmt.Sprintf("Harbor event: *%s*", h.Type),
		Attachments: []DoorayAttachment{
			{
				Title:     title,
				TitleLink: titleLink,
				Text:      strings.Join(lines, "\n"),
				Color:     eventColor(h.Type),
			},
		},
	}
}

func (a *Adapter) postToDooray(url string, payload *DoorayWebhook) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal dooray payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build dooray request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("send dooray request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("dooray returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (a *Adapter) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var hook HarborWebhook
	if err := json.Unmarshal(body, &hook); err != nil {
		log.Printf("invalid harbor payload: %v; body=%s", err, string(body))
		http.Error(w, "invalid harbor payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	repoName := hook.EventData.Repository.RepoFullName

	if ok, reason := a.cfg.ShouldForward(&hook); !ok {
		log.Printf("skipping %s for %s (operator=%s): %s", hook.Type, repoName, hook.Operator, reason)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("skipped"))
		return
	}

	doorayURL := a.cfg.ResolveDoorayURL(repoName)
	if doorayURL == "" {
		log.Printf("no dooray webhook configured for repo %q; body=%s", repoName, string(body))
		http.Error(w, "no dooray webhook configured for repo", http.StatusBadRequest)
		return
	}

	payload := a.buildDoorayPayload(&hook)
	if err := a.postToDooray(doorayURL, payload); err != nil {
		log.Printf("forward to dooray failed: %v; body=%s", err, string(body))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	log.Printf("forwarded %s for %s (operator=%s)", hook.Type, repoName, hook.Operator)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// statusRecorder wraps http.ResponseWriter to capture the status code and
// number of bytes written for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// accessLog wraps a handler and logs one line per request with method, path,
// client address, response status, response size and latency.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("access method=%s path=%s remote=%s status=%d bytes=%d duration=%s",
			r.Method, r.URL.Path, r.RemoteAddr, rec.status, rec.bytes, time.Since(start))
	})
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	adapter := NewAdapter(cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/webhook", adapter.webhookHandler)
	// Harbor's webhook endpoint is often configured as the bare host URL, so
	// accept the root path as a webhook target too. More specific patterns
	// above (/healthz, /webhook) still take precedence.
	mux.HandleFunc("/", adapter.webhookHandler)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           accessLog(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("harbor-dooray-webhook-adapter listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
