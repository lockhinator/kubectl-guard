package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// withTempAuditHome points HOME at a temp dir and returns the audit log path.
func withTempAuditHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := os.Getenv("HOME")
	_ = os.Setenv("HOME", dir)
	t.Cleanup(func() { _ = os.Setenv("HOME", orig) })
	return filepath.Join(dir, ".kubectl-guard-audit.log")
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimRight(string(data), "\n")
	if s == "" {
		return 0
	}
	return len(strings.Split(s, "\n"))
}

func TestAppendAuditRespectsMode(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		outcome string
		wantLog bool
	}{
		{"all/allowed logged", config.AuditModeAll, OutcomeAllowed, true},
		{"all/blocked logged", config.AuditModeAll, OutcomeBlocked, true},
		{"gated/allowed skipped", config.AuditModeGated, OutcomeAllowed, false},
		{"gated/blocked logged", config.AuditModeGated, OutcomeBlocked, true},
		{"off/allowed skipped", config.AuditModeOff, OutcomeAllowed, false},
		{"off/blocked skipped", config.AuditModeOff, OutcomeBlocked, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := withTempAuditHome(t)
			cfg := &config.Config{AuditMode: c.mode}
			if err := AppendAudit(cfg, AuditEntry{
				Command: "get pods",
				Outcome: c.outcome,
			}); err != nil {
				t.Fatal(err)
			}
			got := countLines(t, path)
			if c.wantLog && got != 1 {
				t.Errorf("expected 1 entry, got %d", got)
			}
			if !c.wantLog && got != 0 {
				t.Errorf("expected 0 entries, got %d", got)
			}
		})
	}
}

func TestAppendAuditNilConfigDefaultsToAll(t *testing.T) {
	path := withTempAuditHome(t)
	// nil cfg should default to "all" and log the entry.
	if err := AppendAudit(nil, AuditEntry{Command: "get pods", Outcome: OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	if got := countLines(t, path); got != 1 {
		t.Errorf("expected 1 entry with nil cfg (default all), got %d", got)
	}
}

func TestAppendAuditStampsTimeAndUser(t *testing.T) {
	path := withTempAuditHome(t)
	cfg := &config.Config{AuditMode: config.AuditModeAll}
	if err := AppendAudit(cfg, AuditEntry{Command: "get pods", Outcome: OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"time":"`) {
		t.Error("audit entry missing time field")
	}
	if !strings.Contains(s, `"user":"`) {
		t.Error("audit entry missing user field")
	}
}

func TestAppendAuditConcurrent(t *testing.T) {
	path := withTempAuditHome(t)
	cfg := &config.Config{AuditMode: config.AuditModeAll}

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)

	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			// Create a long command to test PIPE_BUF boundary
			cmd := strings.Repeat("kubectl ", 100) + "get pods -n " + strings.Repeat("very-long-namespace-", 10)
			_ = AppendAudit(cfg, AuditEntry{
				Command: cmd,
				Outcome: OutcomeBlocked,
				Reason:  "protected resource",
			})
		}(i)
	}

	wg.Wait()

	// Verify line count == N
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != N {
		t.Errorf("expected %d lines, got %d", N, len(lines))
	}

	// Verify every line is valid JSON
	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}
