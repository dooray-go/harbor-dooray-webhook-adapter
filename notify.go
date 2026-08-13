package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// Notification is one alert, expressed independently of where it is sent.
// Dooray and Slack both render a coloured attachment with a title and a body,
// so the shape maps cleanly onto either.
type Notification struct {
	// Summary is the one-line lead shown above the attachment.
	Summary string
	Title   string
	Body    string
	// Color is one of "red", "yellow", "green" or "blue"; each notifier
	// translates it to whatever its service expects.
	Color string
}

// Notifier delivers notifications to one destination.
type Notifier interface {
	Notify(n Notification) error
	// Target describes the destination for log messages, without leaking the
	// webhook URL (which is a credential).
	Target() string
}

// Notifiers fans a notification out to several destinations. Delivery to one
// destination never stops the others: a Slack outage must not also cost the
// Dooray notice.
type Notifiers []Notifier

func (ns Notifiers) Notify(n Notification) error {
	var failures []string
	for _, target := range ns {
		if err := target.Notify(n); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", target.Target(), err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func (ns Notifiers) Target() string {
	names := make([]string, 0, len(ns))
	for _, target := range ns {
		names = append(names, target.Target())
	}
	return strings.Join(names, " + ")
}

// DoorayNotifier posts to a Dooray incoming webhook.
type DoorayNotifier struct {
	url          string
	botName      string
	botIconImage string
	post         func(target, url string, payload any) error
}

func (d *DoorayNotifier) Target() string { return "dooray" }

func (d *DoorayNotifier) Notify(n Notification) error {
	return d.post("dooray", d.url, &DoorayWebhook{
		BotName:      d.botName,
		BotIconImage: d.botIconImage,
		Text:         n.Summary,
		Attachments: []DoorayAttachment{{
			Title: n.Title,
			Text:  n.Body,
			Color: n.Color,
		}},
	})
}

// SlackWebhook is the incoming-webhook payload.
type SlackWebhook struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	Text        string            `json:"text"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackAttachment struct {
	Title string `json:"title,omitempty"`
	Text  string `json:"text,omitempty"`
	Color string `json:"color,omitempty"`
	// MrkdwnIn tells Slack which fields to render as markup; without it the
	// backticks and bold markers in the body are shown literally.
	MrkdwnIn []string `json:"mrkdwn_in,omitempty"`
}

// SlackNotifier posts to a Slack incoming webhook.
type SlackNotifier struct {
	url       string
	channel   string
	username  string
	iconEmoji string
	iconURL   string
	post      func(target, url string, payload any) error
}

func (s *SlackNotifier) Target() string {
	if s.channel != "" {
		return "slack(" + s.channel + ")"
	}
	return "slack"
}

func (s *SlackNotifier) Notify(n Notification) error {
	return s.post("slack", s.url, &SlackWebhook{
		Channel:   s.channel,
		Username:  s.username,
		IconEmoji: s.iconEmoji,
		IconURL:   s.iconURL,
		Text:      n.Summary,
		Attachments: []SlackAttachment{{
			Title:    n.Title,
			Text:     n.Body,
			Color:    slackColor(n.Color),
			MrkdwnIn: []string{"text"},
		}},
	})
}

// slackColor maps the neutral colour names onto Slack's attachment colours.
// Slack understands "good"/"warning"/"danger" plus hex, but not Dooray's names.
func slackColor(c string) string {
	switch c {
	case "red":
		return "danger"
	case "yellow":
		return "warning"
	case "green":
		return "good"
	case "blue":
		return "#3aa3e3"
	default:
		return c
	}
}

// slackChannelID matches Slack's channel/group/DM identifiers, which are passed
// through untouched — only human-readable names get the "#" prefix.
var slackChannelID = regexp.MustCompile(`^[CGD][A-Z0-9]{6,}$`)

// normalizeSlackChannel accepts "harbor-alerts" as well as "#harbor-alerts",
// since an incoming webhook silently ignores a channel override that is not a
// well-formed name.
func normalizeSlackChannel(channel string) string {
	channel = strings.TrimSpace(channel)
	if channel == "" || strings.HasPrefix(channel, "#") || strings.HasPrefix(channel, "@") {
		return channel
	}
	if slackChannelID.MatchString(channel) {
		return channel
	}
	return "#" + channel
}

// buildExpiryNotifiers resolves the configured destinations for expiry
// warnings. Slack is used when a Slack webhook is set, Dooray when a Dooray URL
// is set, and both when both are; only when neither is configured does it fall
// back to dooray.default_webhook_url.
func buildExpiryNotifiers(cfg *Config, adapter *Adapter) Notifiers {
	var out Notifiers
	if url := cfg.expiryDoorayURL(); url != "" {
		out = append(out, &DoorayNotifier{
			url:          url,
			botName:      cfg.Dooray.BotName,
			botIconImage: cfg.Dooray.BotIconImage,
			post:         adapter.postJSON,
		})
	}
	s := cfg.Harbor.ExpiryWatch.Slack
	if s.WebhookURL != "" {
		out = append(out, &SlackNotifier{
			url:       s.WebhookURL,
			channel:   s.Channel,
			username:  s.Username,
			iconEmoji: s.IconEmoji,
			iconURL:   s.IconURL,
			post:      adapter.postJSON,
		})
	}
	if len(out) == 0 {
		log.Printf("expiry watch: no notification target configured; warnings will only be logged")
	}
	return out
}
