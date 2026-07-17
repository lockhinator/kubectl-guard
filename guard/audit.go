package guard

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lockhinator/kubectl-guard/config"
)

// EnvAuditKey names an env var holding the HMAC key for the tamper-evident audit
// chain. When set (or a key file is configured), each entry's hash is an HMAC so
// an attacker who can write the log still cannot forge a valid continuation
// without the key. When unset, the chain uses a plain SHA-256 (tamper-EVIDENT,
// detectable but forgeable by a local attacker).
const EnvAuditKey = "KUBECTL_GUARD_AUDIT_KEY"

// ActorEnvVar is the environment variable that identifies who drove a command
// (e.g. "claude-code", "cursor", "ci-deploy"). Agent frameworks and users set
// it for clean, portable attribution in the audit log.
const ActorEnvVar = "KUBECTL_GUARD_ACTOR"

// Outcome constants for audit entries.
const (
	OutcomeAllowed              = "allowed"           // command passed through ungated
	OutcomeConfirmed            = "confirmed"         // gated command, user confirmed
	OutcomeAborted              = "aborted"           // gated command, user declined
	OutcomeBlocked              = "blocked"           // protected resource, refused
	OutcomeDenied               = "denied"            // fail-closed (config/context error)
	OutcomeAutoConfirmed        = "auto-confirmed"    // gated command, auto-approved via --yes/KUBECTL_GUARD_CONFIRM (audited)
	OutcomeBypassed             = "bypassed"          // guard fully bypassed via KUBECTL_GUARD_BYPASS (audited, discouraged)
	OutcomeDryRun               = "dry-run"           // state-altering command allowed because --dry-run changes nothing
	OutcomeRelayed              = "relayed"           // agent-relay mode: emitted needs-confirmation JSON, did not prompt
	OutcomeApprovalConsumed     = "approval-consumed" // authenticated one-shot request consumed; execution dispatch follows
	OutcomeApprovalRejected     = "approval-rejected"
	OutcomeAuthenticationFailed = "authentication-failed"
	OutcomeApprovalExecFailed   = "approval-exec-failed"
	OutcomeConfigChange         = "config-change" // a `config` subcommand changed the guard's own configuration
)

// AuditEntry is a single line in the audit log.
//
// The audit log captures the guard's decision for every command (when
// audit_mode is "all") or only interventions (when "gated"). It does NOT
// capture kubectl's own exit code or output — only whether the guard allowed,
// blocked, or prompted for the command.
type AuditEntry struct {
	Time        string `json:"time"`
	User        string `json:"user"`                  // OS user (kept for attribution)
	Actor       string `json:"actor,omitempty"`       // who drove it: claude-code, ci, human, etc.
	Impersonate string `json:"impersonate,omitempty"` // --as user, when impersonation was used
	Token       bool   `json:"token,omitempty"`       // true when credentials were overridden via --token
	Context     string `json:"context,omitempty"`
	Command     string `json:"command"`
	Outcome     string `json:"outcome"` // allowed | confirmed | aborted | blocked | denied
	Reason      string `json:"reason,omitempty"`
	// Justification is the free-text reason a human/agent supplied to approve a
	// gated command, when require_justification is on (or --reason is given). It
	// records WHY a gated command was approved, for compliance review.
	Justification string `json:"justification,omitempty"`

	// Prev and Hash form the tamper-evident chain (#78). Prev is the previous
	// entry's Hash; Hash is the (HMAC-)SHA-256 over this entry's canonical JSON
	// with Hash blanked. Editing or deleting any entry breaks the chain from that
	// point. These fields are set by appendAuditFile under the audit lock and must
	// be the LAST fields so a legacy (unchained) reader ignores them.
	Prev string `json:"prev,omitempty"`
	Hash string `json:"hash,omitempty"`
}

// auditKey returns the HMAC key for the audit chain, or nil for plain SHA-256.
// Precedence: the KUBECTL_GUARD_AUDIT_KEY env var (value used directly), then the
// config's audit_hmac_key_file (its contents). Both the append and verify paths
// resolve the key the same way, so a log written with a key verifies with it.
func AuditKey(cfg *config.Config) []byte {
	if v := os.Getenv(EnvAuditKey); v != "" {
		return []byte(v)
	}
	if cfg != nil && cfg.AuditHMACKeyFile != "" {
		if data, err := os.ReadFile(cfg.AuditHMACKeyFile); err == nil {
			k := bytes.TrimSpace(data)
			if len(k) > 0 {
				return k
			}
		}
	}
	return nil
}

// chainHash computes the chain hash over data: an HMAC-SHA-256 when key is
// non-empty, else a plain SHA-256, hex-encoded.
func chainHash(key, data []byte) string {
	if len(key) > 0 {
		m := hmac.New(sha256.New, key)
		m.Write(data)
		return hex.EncodeToString(m.Sum(nil))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// entryHash computes the chain hash of an entry: it blanks Hash, marshals the
// canonical JSON (Prev included), and hashes that. json.Marshal emits struct
// fields in declaration order deterministically, so the canonical form is stable.
func entryHash(key []byte, e AuditEntry) (string, error) {
	e.Hash = ""
	canonical, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return chainHash(key, canonical), nil
}

// AppendAudit appends entry as a JSON line to the configured audit log,
// unless the config's audit mode filters out this outcome. Time and User are
// stamped here so callers can omit them. A nil cfg uses defaults (audit all).
// Errors are returned but should be non-fatal: auditing is best-effort.
func AppendAudit(cfg *config.Config, entry AuditEntry) error {
	if cfg == nil {
		cfg = &config.Config{}
		cfg.ApplyDefaults()
	}
	if !cfg.ShouldAudit(entry.Outcome) {
		return nil
	}
	path, err := config.AuditPath(cfg)
	if err != nil {
		return err
	}

	entry.Time = time.Now().UTC().Format(time.RFC3339)
	entry.User = currentUser()
	entry.Actor = resolveActor(cfg, entry.User)

	// Shipping copy (webhook/syslog): the unchained entry. The tamper-evident
	// chain (prev/hash) is a LOCAL-file property — shipped copies live off-box and
	// have their own integrity story (#24) — so they are not chained.
	shipBytes, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	shipLine := append(shipBytes, '\n')

	// Local file sink (with optional rotation), serialized across processes. The
	// chain is computed here, under the audit lock, so concurrent appends link
	// correctly.
	fileErr := appendAuditFile(cfg, path, entry, AuditKey(cfg))

	// Shipping sinks (webhook/syslog) are best-effort and independent of the file,
	// so a delivery failure never masks a successful local write and vice-versa.
	shipAudit(cfg, shipLine)

	return fileErr
}

// appendAuditFile writes line to the audit log, rotating first when the file
// would exceed audit_max_size_mb. Concurrency safety uses a DEDICATED lock file
// (<log>.lock) rather than an flock on the log itself: rotation renames the log,
// and an flock on the log's inode cannot serialize a writer that opened the file
// before the rename against one that opens the fresh log after it. The lock
// file's inode is stable, so every writer serializes on it regardless of
// rotation, and the previous single-file locking guarantee (no interleaved lines)
// is preserved.
func appendAuditFile(cfg *config.Config, path string, entry AuditEntry, key []byte) error {
	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lockFile.Close() }()
	// lockExclusive/unlockFile are platform-specific: a real advisory flock on
	// unix, no-ops on native Windows (a non-goal — the CLI exits with a WSL2
	// message before any audit write, so the lock is never exercised there).
	if err := lockExclusive(lockFile); err != nil {
		return err
	}
	defer unlockFile(lockFile)

	if cfg.AuditMaxSizeMB > 0 {
		// Estimate the line size (chaining adds ~160 bytes of prev+hash) so rotation
		// still triggers around the configured cap.
		est, _ := json.Marshal(entry)
		maybeRotateAudit(path, int64(cfg.AuditMaxSizeMB)*1024*1024, cfg.AuditMaxFilesOrDefault(), len(est)+180)
	}

	// Chain to the current tip. After a rotation above, the log is fresh so the
	// tip is "" — each rotated segment is its own chain (verify checks one file).
	entry.Prev = lastLineHash(path)
	h, err := entryHash(key, entry)
	if err != nil {
		return err
	}
	entry.Hash = h
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line := append(b, '\n')

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(line)
	return err
}

// lastLineHash returns the Hash field of the last non-empty line of the log, or
// "" for a missing/empty log or a legacy (unchained) last line. It reads the
// file's tail (cheap for a large log) but GROWS the window if the last line is
// bigger than the window — otherwise a single huge line (a long command or
// justification) would be truncated, the chain would silently restart, and verify
// would falsely report a break on an untouched log. Called under the audit lock.
func lastLineHash(path string) string {
	line := readLastLine(path)
	if len(line) == 0 {
		return ""
	}
	var e AuditEntry
	if json.Unmarshal(line, &e) != nil {
		return "" // a genuinely corrupt last line: start a fresh chain (verify flags it)
	}
	return e.Hash
}

// readLastLine returns the last complete, non-empty line of path, growing the
// read window until it captures the line's leading newline (or reads the whole
// file). Returns nil on any error or empty file.
func readLastLine(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return nil
	}
	size := fi.Size()
	for window := int64(64 * 1024); ; window *= 8 {
		if window > size {
			window = size
		}
		start := size - window
		buf := make([]byte, window)
		if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
			return nil
		}
		trimmed := bytes.TrimRight(buf, "\n") // drop trailing blank lines
		if idx := bytes.LastIndexByte(trimmed, '\n'); idx >= 0 {
			return bytes.TrimSpace(trimmed[idx+1:]) // last line = after the last interior newline
		}
		if start == 0 {
			return bytes.TrimSpace(trimmed) // whole file is a single line
		}
		// No interior newline in the window: the last line is longer than it. Grow.
	}
}

// AuditVerifyResult summarizes a tamper-evident audit-chain verification.
type AuditVerifyResult struct {
	Total       int    // total non-empty lines
	Chained     int    // lines carrying a chain hash
	Legacy      int    // lines with no hash (written before the chain existed)
	Intact      bool   // true if the chain of hashed entries is unbroken
	BreakLine   int    // 1-based line of the first break (0 when intact)
	BreakReason string // why the chain broke at BreakLine
}

// VerifyAuditLog walks the audit log and verifies the tamper-evident chain: each
// hashed entry's content must match its own hash (detecting edits, or a wrong
// key), and its Prev must equal the previous hashed entry's Hash (detecting
// deletion or reordering). Legacy (unchained) lines are only tolerated as a
// contiguous prefix before the chain begins; an unchained line AFTER the chain
// started is tampering. key is the HMAC key (nil ⇒ plain SHA-256) and must match
// what wrote the log. It reports the FIRST break.
//
// Two limitations remain, inherent to a local append-only hash chain:
//   - A log of ONLY unchained lines (Chained==0, Legacy>0) cannot be verified —
//     it is indistinguishable from a pre-v1.0 log or one whose every hash was
//     stripped. Callers should treat that as unverifiable, not intact.
//   - TAIL truncation (deleting the most recent entries) leaves an internally
//     consistent shorter chain and is not detectable here; shipping the tip hash
//     off-box (the webhook/syslog sinks, #24) is the mitigation.
func VerifyAuditLog(path string, key []byte) (AuditVerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return AuditVerifyResult{}, err
	}
	defer func() { _ = f.Close() }()

	r := AuditVerifyResult{Intact: true}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var prevHash string
	started := false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		r.Total++
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return breakAt(r, lineNo, "line is not valid JSON"), nil
		}
		if e.Hash == "" {
			// An unchained line is only legitimate as a contiguous PREFIX written
			// before the chain existed. Once the chain has started, an unhashed line
			// is tampering: an attacker cannot be allowed to neutralize an entry by
			// stripping its hash, nor to splice in fresh unhashed lines. (This was a
			// critical bypass: skipping any unhashed line let a writer forge history
			// even under HMAC.)
			if started {
				return breakAt(r, lineNo, "unchained entry after the chain began (a line was inserted or its hash stripped)"), nil
			}
			r.Legacy++
			continue
		}
		r.Chained++
		// The stored line must be EXACTLY the canonical serialization of the parsed
		// entry. Verify hashes the parsed struct, so reordered keys, extra fields,
		// duplicate keys, or added whitespace would otherwise pass while a raw-log
		// reader sees fabricated content. Re-marshal (with the hash) and compare.
		canon, merr := json.Marshal(e)
		if merr != nil {
			return breakAt(r, lineNo, "could not canonicalize entry"), nil
		}
		if !bytes.Equal(canon, raw) {
			return breakAt(r, lineNo, "entry is not in canonical form (reordered, extra, or duplicate fields)"), nil
		}
		expected, herr := entryHash(key, e)
		if herr != nil {
			return breakAt(r, lineNo, "could not hash entry"), nil
		}
		if !hmac.Equal([]byte(expected), []byte(e.Hash)) {
			return breakAt(r, lineNo, "entry content does not match its hash (edited, or wrong HMAC key)"), nil
		}
		if started {
			if e.Prev != prevHash {
				return breakAt(r, lineNo, "prev hash does not match the previous entry (a line was removed or reordered)"), nil
			}
		} else if e.Prev != "" {
			return breakAt(r, lineNo, "first chained entry references a previous hash but none precedes it (leading entries removed)"), nil
		}
		started = true
		prevHash = e.Hash
	}
	if err := sc.Err(); err != nil {
		return r, err
	}
	return r, nil
}

func breakAt(r AuditVerifyResult, line int, reason string) AuditVerifyResult {
	r.Intact = false
	r.BreakLine = line
	r.BreakReason = reason
	return r
}

// maybeRotateAudit rotates the log when writing `incoming` more bytes would push
// it past maxBytes. It must be called while holding the audit lock.
func maybeRotateAudit(path string, maxBytes int64, maxFiles, incoming int) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		// No log yet, or an empty one — nothing worth preserving; the incoming
		// write (even if itself larger than maxBytes) starts a fresh file.
		return
	}
	if fi.Size()+int64(incoming) <= maxBytes {
		return
	}
	rotateAudit(path, maxFiles)
}

// rotateAudit shifts the archive chain: it evicts every archive at or beyond the
// retention count (<log>.maxFiles and any higher — the latter left behind when a
// larger max_files was previously in effect), renames <log>.i → <log>.(i+1) for
// i = maxFiles-1 … 1, then <log> → <log>.1, leaving <log> absent so the caller
// re-creates it. Renames of absent archives are no-ops. Callers hold the audit
// lock, so no other writer observes the gap.
func rotateAudit(path string, maxFiles int) {
	removeArchivesFrom(path, maxFiles)
	for i := maxFiles - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	_ = os.Rename(path, path+".1")
}

// removeArchivesFrom deletes every rotated archive <log>.N with N >= min. It
// globs rather than counting up from min so it also cleans stale archives left by
// a previously larger max_files (and tolerates gaps in the chain). The <log>.lock
// file is never matched — its suffix is not numeric.
func removeArchivesFrom(path string, min int) {
	matches, _ := filepath.Glob(path + ".*")
	for _, m := range matches {
		suffix := strings.TrimPrefix(m, path+".")
		if n, err := strconv.Atoi(suffix); err == nil && n >= min {
			_ = os.Remove(m)
		}
	}
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// CurrentActor resolves the actor that drives the current command (the same
// resolution used for auditing: KUBECTL_GUARD_ACTOR → config actor → OS user).
// It is exported so the CLI can derive the actor-effective modes for its
// human-facing messages, matching the decision the guard already made.
func CurrentActor(cfg *config.Config) string {
	return resolveActor(cfg, currentUser())
}

// resolveActor determines who drove the command, in priority order:
//  1. KUBECTL_GUARD_ACTOR env var (explicit opt-in, e.g. "claude-code")
//  2. config.Actor static default
//  3. the OS username (current behavior)
//
// The OS user is always recorded separately in AuditEntry.User, so Actor is
// purely about *who drove it* rather than *whose account ran it*.
func resolveActor(cfg *config.Config, osUser string) string {
	if v := strings.TrimSpace(os.Getenv(ActorEnvVar)); v != "" {
		return v
	}
	if cfg != nil {
		if v := strings.TrimSpace(cfg.Actor); v != "" {
			return v
		}
	}
	return osUser
}
