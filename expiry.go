package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"
)

// Kinds of expiring things the watcher tracks.
const (
	kindSystemAllowlist  = "system CVE allowlist"
	kindProjectAllowlist = "project CVE allowlist"
	kindRobot            = "robot account"
)

// ExpiryFinding is one Harbor object that carries an expiry date.
//
// Expiry is the failure mode Harbor gives no warning about: when a CVE
// allowlist expires, Harbor stops bypassing the listed CVEs (see
// GetVulnerable's `!allowlistIsExpired && allowlist.Contains(v.ID)` check), so
// images that pulled fine yesterday start failing with 412 — with no webhook,
// no rescan and no state change of any kind. Robot accounts fail the same way,
// with 401 instead.
type ExpiryFinding struct {
	Kind      string
	Name      string
	ExpiresAt time.Time
	// DaysLeft is the whole days remaining, rounded up. It is 0 on the day the
	// object expired and goes negative afterwards.
	DaysLeft int
	// Enforcing is true when this expiry actually breaks something. An expired
	// allowlist on a project that does not prevent vulnerable images from
	// running changes nothing, and is reported as information only.
	Enforcing bool
	Detail    string
}

func (f ExpiryFinding) key() string { return f.Kind + "|" + f.Name }

// label renders the countdown prefix, e.g. "D-7" or "EXPIRED 2d ago".
func (f ExpiryFinding) label() string {
	switch {
	case f.DaysLeft > 0:
		return fmt.Sprintf("D-%d", f.DaysLeft)
	case f.DaysLeft == 0:
		return "EXPIRED today"
	default:
		return fmt.Sprintf("EXPIRED %dd ago", -f.DaysLeft)
	}
}

func (f ExpiryFinding) line() string {
	verb := "expires"
	if f.DaysLeft <= 0 {
		verb = "expired"
	}
	line := fmt.Sprintf("- [%s] %s `%s` — %s %s", f.label(), f.Kind, f.Name, verb,
		f.ExpiresAt.Format(time.RFC3339))
	if f.Detail != "" {
		line += fmt.Sprintf("\n  %s", f.Detail)
	}
	return line
}

// daysUntil returns whole days from now until t, rounded up, so an object
// expiring in 6.5 days reports 7 and still trips the D-7 warning. Once past,
// it returns 0 on the first day and decreases by one per elapsed day.
func daysUntil(t, now time.Time) int {
	d := t.Sub(now)
	if d > 0 {
		return int(math.Ceil(d.Hours() / 24))
	}
	return -int(math.Floor(-d.Hours() / 24))
}

// expiryBucket names the warning step a finding currently sits in, or "" when
// it is still further out than the largest configured warning. warnDays must be
// sorted ascending. Expired findings get a bucket that changes every day, so
// they are re-announced daily until someone fixes them.
func expiryBucket(daysLeft int, warnDays []int) string {
	if daysLeft <= 0 {
		return fmt.Sprintf("expired:%d", daysLeft)
	}
	for _, w := range warnDays {
		if daysLeft <= w {
			return fmt.Sprintf("d-%d", w)
		}
	}
	return ""
}

// ExpiryWatcher polls Harbor for approaching expiry dates and posts warnings to
// Dooray.
type ExpiryWatcher struct {
	cfg         *Config
	harbor      *HarborClient
	notifier    Notifier
	interval    time.Duration
	warnDays    []int
	watchRobots bool

	// now is injectable so tests can drive the clock.
	now func() time.Time

	// alerted remembers the last warning step announced per finding, so a
	// steady D-14 is reported once rather than on every poll.
	alerted map[string]string
	// started is false until the first poll has sent its inventory report.
	started bool
	// failures counts consecutive polling failures; a watcher that dies quietly
	// is the same silent failure it exists to prevent, so it reports itself.
	failures     int
	failureAlert bool
}

func NewExpiryWatcher(cfg *Config, adapter *Adapter) *ExpiryWatcher {
	w := cfg.Harbor.ExpiryWatch
	return &ExpiryWatcher{
		cfg:         cfg,
		harbor:      NewHarborClient(cfg.Harbor),
		notifier:    buildExpiryNotifiers(cfg, adapter),
		interval:    w.interval,
		warnDays:    w.WarnDays,
		watchRobots: w.WatchRobots == nil || *w.WatchRobots,
		now:         time.Now,
		alerted:     make(map[string]string),
	}
}

// failureThreshold is how many consecutive failed polls it takes before the
// watcher reports its own blindness to Dooray.
const failureThreshold = 3

func (w *ExpiryWatcher) Run(ctx context.Context) {
	log.Printf("expiry watch: polling %s every %s (warn at D-%s, notify %s)",
		w.cfg.Harbor.URL, w.interval, joinInts(w.warnDays, "/D-"), w.notifier.Target())
	w.checkOnce(ctx)

	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.checkOnce(ctx)
		}
	}
}

func (w *ExpiryWatcher) checkOnce(ctx context.Context) {
	findings, warnings, err := w.collect(ctx)
	if err != nil {
		w.failures++
		log.Printf("expiry watch: poll failed (%d consecutive): %v", w.failures, err)
		if w.failures >= failureThreshold && !w.failureAlert {
			w.failureAlert = true
			w.send(Notification{
				Summary: "Harbor expiry watch: *polling failed*",
				Title:   "[Harbor] Expiry watch is blind",
				Body: fmt.Sprintf("- %d consecutive polls failed; expiry dates are no longer being checked.\n- Last error: %v\n- Check `harbor.url` and the watcher's credentials (an expired watcher robot account will do exactly this).",
					w.failures, err),
				Color: "red",
			})
		}
		return
	}
	if w.failureAlert {
		w.send(Notification{
			Summary: "Harbor expiry watch: *recovered*",
			Title:   "[Harbor] Expiry watch recovered",
			Body:    "- Polling Harbor succeeded again; expiry dates are being checked.",
			Color:   "green",
		})
	}
	w.failures, w.failureAlert = 0, false

	sortFindings(findings)

	if !w.started {
		w.started = true
		// The first poll reports the full inventory: an expiry date nobody
		// remembers setting is the whole problem, so list them all once even
		// when none is close.
		for _, f := range findings {
			w.alerted[f.key()] = expiryBucket(f.DaysLeft, w.warnDays)
		}
		w.send(w.inventoryNotification(findings, warnings))
		return
	}

	var due []ExpiryFinding
	for _, f := range findings {
		b := expiryBucket(f.DaysLeft, w.warnDays)
		if b == "" || w.alerted[f.key()] == b {
			continue
		}
		w.alerted[f.key()] = b
		due = append(due, f)
	}
	if len(due) == 0 {
		for _, msg := range warnings {
			log.Printf("expiry watch: %s", msg)
		}
		return
	}
	w.send(w.alertNotification(due, warnings))
}

func (w *ExpiryWatcher) send(n Notification) {
	if err := w.notifier.Notify(n); err != nil {
		log.Printf("expiry watch: notification failed: %v", err)
	}
}

// collect gathers every expiry date the configured account can see. Individual
// check failures become warnings so one broken endpoint (typically /robots,
// which needs system admin) does not blind the rest; only failing to enumerate
// projects at all is returned as an error.
func (w *ExpiryWatcher) collect(ctx context.Context) ([]ExpiryFinding, []string, error) {
	now := w.now()
	var findings []ExpiryFinding
	var warnings []string

	names := w.cfg.Harbor.ExpiryWatch.Projects
	if len(names) == 0 {
		var err error
		names, err = w.harbor.ProjectNames(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("list projects: %w", err)
		}
	}

	// systemReliant counts projects that both enforce the vulnerability policy
	// and defer to the system allowlist — they are what makes the system
	// allowlist's expiry dangerous.
	var systemReliant []string
	for _, name := range names {
		p, err := w.harbor.Project(ctx, name)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("project %q could not be read: %v", name, err))
			continue
		}
		enforcing := p.Metadata.PreventsVulnerable()
		if p.Metadata.ReusesSystemAllowlist() {
			if enforcing {
				systemReliant = append(systemReliant, name)
			}
			// A project reusing the system allowlist ignores its own, so its
			// own expiry date is meaningless — do not report it.
			continue
		}
		exp, ok := p.CVEAllowlist.Expiry()
		if !ok {
			continue
		}
		findings = append(findings, ExpiryFinding{
			Kind:      kindProjectAllowlist,
			Name:      name,
			ExpiresAt: exp,
			DaysLeft:  daysUntil(exp, now),
			Enforcing: enforcing,
			Detail:    policyDetail(p.Metadata, len(p.CVEAllowlist.Items)),
		})
	}

	if allow, err := w.harbor.SystemCVEAllowlist(ctx); err != nil {
		warnings = append(warnings, fmt.Sprintf("system CVE allowlist could not be read: %v", err))
	} else if exp, ok := allow.Expiry(); ok {
		detail := fmt.Sprintf("%d CVE(s) allowlisted; no project enforces the vulnerability policy through it",
			len(allow.Items))
		if len(systemReliant) > 0 {
			detail = fmt.Sprintf("%d CVE(s) allowlisted; %d enforcing project(s) rely on it: %s",
				len(allow.Items), len(systemReliant), strings.Join(systemReliant, ", "))
		}
		findings = append(findings, ExpiryFinding{
			Kind:      kindSystemAllowlist,
			Name:      "system",
			ExpiresAt: exp,
			DaysLeft:  daysUntil(exp, now),
			Enforcing: len(systemReliant) > 0,
			Detail:    detail,
		})
	}

	if w.watchRobots {
		robots, err := w.harbor.Robots(ctx)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("robot accounts could not be listed (system admin required): %v", err))
		}
		for _, r := range robots {
			exp, ok := r.Expiry()
			if !ok {
				continue
			}
			detail := fmt.Sprintf("level=%s", r.Level)
			if r.Disable {
				detail += "; already disabled"
			}
			findings = append(findings, ExpiryFinding{
				Kind:      kindRobot,
				Name:      r.Name,
				ExpiresAt: exp,
				DaysLeft:  daysUntil(exp, now),
				Enforcing: !r.Disable,
				Detail:    detail,
			})
		}
	}

	return findings, warnings, nil
}

// policyDetail summarises the project settings that decide whether an expired
// allowlist actually blocks pulls.
func policyDetail(m ProjectMetadata, items int) string {
	if !m.PreventsVulnerable() {
		return fmt.Sprintf("%d CVE(s) allowlisted; prevent_vul is off, so expiry does not block pulls", items)
	}
	sev := m.Severity
	if sev == "" {
		sev = "(unset)"
	}
	return fmt.Sprintf("%d CVE(s) allowlisted; prevent_vul is on at severity %s — pulls start failing with 412 on expiry", items, sev)
}

// sortFindings orders by urgency first so the most pressing item leads.
func sortFindings(f []ExpiryFinding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].DaysLeft != f[j].DaysLeft {
			return f[i].DaysLeft < f[j].DaysLeft
		}
		if f[i].Kind != f[j].Kind {
			return f[i].Kind < f[j].Kind
		}
		return f[i].Name < f[j].Name
	})
}

func (w *ExpiryWatcher) inventoryNotification(findings []ExpiryFinding, warnings []string) Notification {
	var lines []string
	if len(findings) == 0 {
		lines = append(lines, "- No CVE allowlist or robot account has an expiry date set. Nothing can expire out from under a pull.")
	} else {
		lines = append(lines, fmt.Sprintf("- %d item(s) carry an expiry date. Harbor sends no webhook when they lapse, so they are polled every %s.",
			len(findings), w.cfg.Harbor.ExpiryWatch.Interval))
		for _, f := range findings {
			lines = append(lines, f.line())
		}
	}
	lines = append(lines, warningLines(warnings)...)

	return Notification{
		Summary: "Harbor expiry watch: *started*",
		Title:   "[Harbor] Expiry watch started",
		Body:    strings.Join(lines, "\n"),
		Color:   inventoryColor(findings),
	}
}

func (w *ExpiryWatcher) alertNotification(due []ExpiryFinding, warnings []string) Notification {
	lines := make([]string, 0, len(due)+2)
	for _, f := range due {
		lines = append(lines, f.line())
	}
	lines = append(lines, "- An expired CVE allowlist stops exempting its CVEs, so pulls that worked yesterday fail with 412 and no Harbor event is emitted.")
	lines = append(lines, warningLines(warnings)...)

	return Notification{
		Summary: "Harbor expiry watch: *expiry approaching*",
		Title:   fmt.Sprintf("[Harbor] Expiry warning — %d item(s)", len(due)),
		Body:    strings.Join(lines, "\n"),
		Color:   alertColor(due),
	}
}

func warningLines(warnings []string) []string {
	lines := make([]string, 0, len(warnings))
	for _, msg := range warnings {
		lines = append(lines, "- (check skipped) "+msg)
	}
	return lines
}

// alertColor turns the message red once something that actually enforces is
// within a week of lapsing, or has already lapsed.
func alertColor(f []ExpiryFinding) string {
	for _, x := range f {
		if x.Enforcing && x.DaysLeft <= 7 {
			return "red"
		}
	}
	return "yellow"
}

func inventoryColor(f []ExpiryFinding) string {
	if len(f) == 0 {
		return "green"
	}
	return alertColor(f)
}

func joinInts(v []int, sep string) string {
	parts := make([]string, 0, len(v))
	for i := len(v) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprint(v[i]))
	}
	return strings.Join(parts, sep)
}
