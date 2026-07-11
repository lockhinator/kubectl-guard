package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

func chainTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvAuditKey, "") // plain SHA-256 unless a test sets it
	t.Setenv("KUBECTL_GUARD_AUDIT_LOG", "")
	cfg := &config.Config{}
	cfg.ApplyDefaults()
	return cfg, filepath.Join(home, ".kubectl-guard-audit.log")
}

func appendN(t *testing.T, cfg *config.Config, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := AppendAudit(cfg, AuditEntry{Command: fmt.Sprintf("get pods %d", i), Outcome: OutcomeAllowed}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAuditChainIntact: appended entries chain (each prev = the previous hash)
// and verify reports intact. #78.
func TestAuditChainIntact(t *testing.T) {
	cfg, path := chainTestConfig(t)
	appendN(t, cfg, 5)
	res, err := VerifyAuditLog(path, AuditKey(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.Chained != 5 || res.Legacy != 0 {
		t.Errorf("intact=%v chained=%d legacy=%d, want true/5/0", res.Intact, res.Chained, res.Legacy)
	}
}

// TestAuditChainDetectsEdit: editing an entry's content breaks the chain at that
// line. #78.
func TestAuditChainDetectsEdit(t *testing.T) {
	cfg, path := chainTestConfig(t)
	appendN(t, cfg, 5)
	lines := readLines(t, path)
	lines[2] = strings.Replace(lines[2], "get pods 2", "delete node evil", 1)
	writeLines(t, path, lines)
	res, _ := VerifyAuditLog(path, AuditKey(cfg))
	if res.Intact || res.BreakLine != 3 {
		t.Errorf("edit: intact=%v breakLine=%d, want false/3", res.Intact, res.BreakLine)
	}
	if !strings.Contains(res.BreakReason, "hash") {
		t.Errorf("break reason = %q, want a hash-mismatch reason", res.BreakReason)
	}
}

// TestAuditChainDetectsDeletion: removing a middle entry breaks the chain (the
// next entry's prev no longer matches). #78.
func TestAuditChainDetectsDeletion(t *testing.T) {
	cfg, path := chainTestConfig(t)
	appendN(t, cfg, 5)
	lines := readLines(t, path)
	lines = append(lines[:2], lines[3:]...) // delete the 3rd line
	writeLines(t, path, lines)
	res, _ := VerifyAuditLog(path, AuditKey(cfg))
	if res.Intact || res.BreakLine != 3 {
		t.Errorf("deletion: intact=%v breakLine=%d, want false/3", res.Intact, res.BreakLine)
	}
	if !strings.Contains(res.BreakReason, "prev") {
		t.Errorf("break reason = %q, want a prev-mismatch reason", res.BreakReason)
	}
}

// TestAuditChainHMACForgeryFails: with an HMAC key, an entry forged with a plain
// SHA-256 hash (no key) fails verification. #78.
func TestAuditChainHMACForgeryFails(t *testing.T) {
	cfg, path := chainTestConfig(t)
	t.Setenv(EnvAuditKey, "supersecretkey")
	appendN(t, cfg, 3)

	// Genuine log verifies with the key.
	if res, _ := VerifyAuditLog(path, AuditKey(cfg)); !res.Intact {
		t.Fatalf("genuine HMAC chain not intact: %+v", res)
	}

	// Attacker (no key) appends a forged entry chained with a PLAIN SHA-256 hash.
	lines := readLines(t, path)
	tip := lastLineHash(path)
	forged := AuditEntry{Time: "2026-01-01T00:00:00Z", User: "attacker", Command: "delete node prod", Outcome: OutcomeAllowed, Prev: tip}
	forged.Hash, _ = entryHash(nil, forged) // nil key = plain SHA-256, forger has no HMAC key
	b, _ := json.Marshal(forged)
	lines = append(lines, string(b))
	writeLines(t, path, lines)

	res, _ := VerifyAuditLog(path, AuditKey(cfg))
	if res.Intact {
		t.Errorf("forged plain-hash entry passed HMAC verification; want broken")
	}
	if res.BreakLine != 4 {
		t.Errorf("break at line %d, want 4 (the forged entry)", res.BreakLine)
	}
}

// TestAuditChainLegacyGraceful: entries written before the chain existed (no
// hash) are counted as legacy and skipped; later chained entries still verify. #78.
func TestAuditChainLegacyGraceful(t *testing.T) {
	cfg, path := chainTestConfig(t)
	// Two legacy (unchained) lines, as an older kubectl-guard would have written.
	writeLines(t, path, []string{
		`{"time":"2026-01-01T00:00:00Z","user":"u","command":"get pods","outcome":"allowed"}`,
		`{"time":"2026-01-01T00:00:01Z","user":"u","command":"get svc","outcome":"allowed"}`,
	})
	appendN(t, cfg, 3) // chained entries appended after the legacy tip
	res, err := VerifyAuditLog(path, AuditKey(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Errorf("legacy+chained should verify intact, got break at %d: %s", res.BreakLine, res.BreakReason)
	}
	if res.Legacy != 2 || res.Chained != 3 {
		t.Errorf("legacy=%d chained=%d, want 2/3", res.Legacy, res.Chained)
	}
}

// TestAuditChainRejectsUnchainedAfterStart: an unhashed line inserted (or a
// stripped hash) AFTER the chain has begun is tampering — it must break
// verification, not be silently skipped as "legacy". Regression for the critical
// legacy-downgrade bypass (security review). #78.
func TestAuditChainRejectsUnchainedAfterStart(t *testing.T) {
	cfg, path := chainTestConfig(t)
	appendN(t, cfg, 3)
	lines := readLines(t, path)
	// Splice a forged, unhashed line into the middle.
	forged := `{"time":"2026-01-01T00:00:00Z","user":"attacker","command":"delete ns kube-system","outcome":"allowed"}`
	spliced := append([]string{lines[0], forged}, lines[1:]...)
	writeLines(t, path, spliced)
	res, _ := VerifyAuditLog(path, AuditKey(cfg))
	if res.Intact {
		t.Errorf("unhashed line after chain start passed verification (legacy-downgrade bypass)")
	}
	if res.BreakLine != 2 {
		t.Errorf("break at line %d, want 2 (the inserted line)", res.BreakLine)
	}
}

// TestAuditChainRejectsExtraFields: an extra JSON field spliced into a chained
// entry (while its known fields still hash-verify) must break — verify compares
// the stored line to the canonical form. Regression for the extra-field
// injection (security review). #78.
func TestAuditChainRejectsExtraFields(t *testing.T) {
	cfg, path := chainTestConfig(t)
	appendN(t, cfg, 3)
	lines := readLines(t, path)
	lines[1] = strings.Replace(lines[1], "{", `{"note":"fabricated APPROVED BY CISO",`, 1)
	writeLines(t, path, lines)
	res, _ := VerifyAuditLog(path, AuditKey(cfg))
	if res.Intact {
		t.Errorf("extra field in a chained entry passed verification")
	}
	if !strings.Contains(res.BreakReason, "canonical") {
		t.Errorf("break reason = %q, want a canonical-form reason", res.BreakReason)
	}
}

// TestAuditChainHugeLastLine: a legitimate audit line larger than the tail-read
// window must not silently restart the chain (which would falsely report a break
// on an untouched log). Regression for the >64KB last-line false positive
// (adversarial review). #78.
func TestAuditChainHugeLastLine(t *testing.T) {
	cfg, path := chainTestConfig(t)
	appendN(t, cfg, 2)
	// A ~70KB justification pushes the last line past the 64KB tail window.
	if err := AppendAudit(cfg, AuditEntry{Command: "delete pod x", Outcome: OutcomeConfirmed, Justification: strings.Repeat("x", 70*1024)}); err != nil {
		t.Fatal(err)
	}
	// One more entry: its Prev must chain to the huge line's hash, not restart.
	if err := AppendAudit(cfg, AuditEntry{Command: "get pods", Outcome: OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyAuditLog(path, AuditKey(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.Chained != 4 {
		t.Errorf("huge-last-line: intact=%v chained=%d, want true/4 (break: %s at %d)", res.Intact, res.Chained, res.BreakReason, res.BreakLine)
	}
}

// TestAuditChainStripAllHashesUnverifiable: stripping every hash makes the whole
// log look pre-feature (Chained==0). VerifyAuditLog cannot distinguish that from a
// genuine pre-v1.0 log, so it reports Chained==0/Legacy>0 — which the CLI treats
// as unverifiable (fail closed). Regression for the strip-all downgrade. #78.
func TestAuditChainStripAllHashesUnverifiable(t *testing.T) {
	cfg, path := chainTestConfig(t)
	t.Setenv(EnvAuditKey, "supersecretkey")
	appendN(t, cfg, 3)
	// Attacker rewrites every entry and strips prev/hash.
	writeLines(t, path, []string{
		`{"time":"x","user":"attacker","command":"delete ns a","outcome":"allowed"}`,
		`{"time":"x","user":"attacker","command":"delete ns b","outcome":"allowed"}`,
		`{"time":"x","user":"attacker","command":"delete ns c","outcome":"allowed"}`,
	})
	res, _ := VerifyAuditLog(path, AuditKey(cfg))
	if res.Chained != 0 || res.Legacy != 3 {
		t.Errorf("strip-all: chained=%d legacy=%d, want 0/3", res.Chained, res.Legacy)
	}
	// The CLI (runAuditVerify) treats Chained==0 && Legacy>0 as unverifiable and
	// exits non-zero — this test locks the result shape the CLI keys on.
}

// TestAuditChainConcurrentAppends: parallel appends (flock-serialized) still
// produce a valid chain. #78.
func TestAuditChainConcurrentAppends(t *testing.T) {
	cfg, path := chainTestConfig(t)
	const n = 25
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = AppendAudit(cfg, AuditEntry{Command: fmt.Sprintf("cmd %d", i), Outcome: OutcomeAllowed})
		}(i)
	}
	wg.Wait()
	res, err := VerifyAuditLog(path, AuditKey(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.Chained != n {
		t.Errorf("concurrent: intact=%v chained=%d, want true/%d (break: %s)", res.Intact, res.Chained, n, res.BreakReason)
	}
}
