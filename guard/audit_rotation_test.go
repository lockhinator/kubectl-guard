package guard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestAuditRotationTriggersAndKeepsArchives: with a small size cap and 2
// archives, writing many entries rotates the log and keeps exactly .1 and .2
// (never .3), and the live log keeps receiving new entries.
func TestAuditRotationTriggersAndKeepsArchives(t *testing.T) {
	path := withTempAuditHome(t)
	// 1 "MB" cap is too coarse for a unit test; drive rotation with a tiny cap by
	// setting the field directly is not possible (it is MB), so instead write
	// enough entries that many rotations occur at 1 MB would be slow. Use a config
	// with AuditMaxSizeMB=1 but force many large lines? Simpler: assert the
	// rotateAudit chain directly for archive-count correctness, and drive one real
	// rotation through AppendAudit below.
	cfg := &config.Config{AuditMode: config.AuditModeAll, AuditMaxSizeMB: 1, AuditMaxFiles: 2}

	// Pre-fill the live log just over 1 MB so the next append rotates.
	big := strings.Repeat("x", 1024*1024+10)
	if err := os.WriteFile(path, []byte(big+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AppendAudit(cfg, AuditEntry{Command: "delete pods --all", Outcome: OutcomeBlocked}); err != nil {
		t.Fatal(err)
	}
	// After rotation: .1 holds the old big content; the live log holds the new entry.
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected archive %s.1 after rotation: %v", path, err)
	}
	if got := countLines(t, path); got != 1 {
		t.Errorf("live log after rotation = %d lines, want 1 (the fresh entry)", got)
	}

	// Force a second and third rotation; with AuditMaxFiles=2, .3 must never exist.
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(path, []byte(big+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := AppendAudit(cfg, AuditEntry{Command: "x", Outcome: OutcomeBlocked}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".2"); err != nil {
		t.Errorf("expected archive %s.2: %v", path, err)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("%s.3 should not exist (max_files=2), stat err=%v", path, err)
	}
}

// TestAuditRotationCleansStaleArchivesAfterReducingMaxFiles: if archives beyond
// the current max_files exist (e.g. from a previously larger setting), a rotation
// removes them, keeping exactly max_files.
func TestAuditRotationCleansStaleArchivesAfterReducingMaxFiles(t *testing.T) {
	path := withTempAuditHome(t)
	// Simulate stale archives .1...5 from a prior max_files=5.
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte("old\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AuditMode: config.AuditModeAll, AuditMaxSizeMB: 1, AuditMaxFiles: 2}
	big := strings.Repeat("z", 1024*1024+10)
	if err := os.WriteFile(path, []byte(big+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AppendAudit(cfg, AuditEntry{Command: "x", Outcome: OutcomeBlocked}); err != nil {
		t.Fatal(err)
	}
	// Exactly .1 and .2 survive; .3/.4/.5 are removed.
	for _, keep := range []int{1, 2} {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, keep)); err != nil {
			t.Errorf("archive .%d should exist: %v", keep, err)
		}
	}
	for _, gone := range []int{3, 4, 5} {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, gone)); !os.IsNotExist(err) {
			t.Errorf("stale archive .%d should have been removed", gone)
		}
	}
}

// TestAuditRotationDisabledByDefault: with no size cap, the log grows unbounded
// and no archives appear.
func TestAuditRotationDisabledByDefault(t *testing.T) {
	path := withTempAuditHome(t)
	cfg := &config.Config{AuditMode: config.AuditModeAll} // AuditMaxSizeMB == 0
	big := strings.Repeat("y", 2*1024*1024)
	if err := os.WriteFile(path, []byte(big+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AppendAudit(cfg, AuditEntry{Command: "get pods", Outcome: OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("no rotation expected when audit_max_size_mb is 0; %s.1 exists", path)
	}
}

// TestAuditWebhookSinkFires: with audit_webhook_url set, each entry is POSTed as
// JSON to the webhook.
func TestAuditWebhookSinkFires(t *testing.T) {
	withTempAuditHome(t)

	var got atomic.Int32
	var mu sync.Mutex
	var body []byte
	var ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got.Add(1)
		ctype = r.Header.Get("Content-Type")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		body = b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{AuditMode: config.AuditModeAll, AuditWebhookURL: srv.URL}
	if err := AppendAudit(cfg, AuditEntry{Command: "delete secret db", Outcome: OutcomeBlocked, Reason: "protected"}); err != nil {
		t.Fatal(err)
	}
	if got.Load() != 1 {
		t.Fatalf("webhook received %d requests, want 1", got.Load())
	}
	if ctype != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ctype)
	}
	var entry AuditEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		t.Fatalf("webhook body is not valid AuditEntry JSON: %v (%q)", err, string(body))
	}
	if entry.Command != "delete secret db" || entry.Outcome != OutcomeBlocked {
		t.Errorf("webhook payload = %+v, want the audited entry", entry)
	}
}

// TestAuditWebhookFailureIsNonFatal: a dead webhook must not fail AppendAudit,
// and the local file write must still succeed.
func TestAuditWebhookFailureIsNonFatal(t *testing.T) {
	path := withTempAuditHome(t)
	// A reserved TEST-NET address that will refuse/timeout fast is flaky; instead
	// point at a server we immediately close so the connection is refused.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now connections are refused

	cfg := &config.Config{AuditMode: config.AuditModeAll, AuditWebhookURL: url}
	if err := AppendAudit(cfg, AuditEntry{Command: "get pods", Outcome: OutcomeAllowed}); err != nil {
		t.Fatalf("AppendAudit must not fail on a dead webhook: %v", err)
	}
	if got := countLines(t, path); got != 1 {
		t.Errorf("local log should still have the entry; got %d lines", got)
	}
}

// TestAuditWebhookRefusesRedirect: the webhook client must NOT follow a redirect
// to another host (would re-POST audit metadata to an unconfigured target).
func TestAuditWebhookRefusesRedirect(t *testing.T) {
	withTempAuditHome(t)
	var redirectTargetHit atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	cfg := &config.Config{AuditMode: config.AuditModeAll, AuditWebhookURL: redirector.URL}
	if err := AppendAudit(cfg, AuditEntry{Command: "delete secret db", Outcome: OutcomeBlocked}); err != nil {
		t.Fatalf("AppendAudit must not fail when a redirect is refused: %v", err)
	}
	if redirectTargetHit.Load() != 0 {
		t.Errorf("audit body was re-POSTed to the redirect target %d time(s); redirects must be refused", redirectTargetHit.Load())
	}
}

// TestAuditWebhookRespectsMode: a filtered-out entry (audit_mode gated + an
// allowed outcome) is neither logged nor shipped.
func TestAuditWebhookRespectsMode(t *testing.T) {
	withTempAuditHome(t)
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{AuditMode: config.AuditModeGated, AuditWebhookURL: srv.URL}
	if err := AppendAudit(cfg, AuditEntry{Command: "get pods", Outcome: OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	if got.Load() != 0 {
		t.Errorf("a gated-filtered allowed entry must not ship; webhook got %d", got.Load())
	}
}
