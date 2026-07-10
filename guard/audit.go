package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lockhinator/kubectl-guard/config"
)

// ActorEnvVar is the environment variable that identifies who drove a command
// (e.g. "claude-code", "cursor", "ci-deploy"). Agent frameworks and users set
// it for clean, portable attribution in the audit log.
const ActorEnvVar = "KUBECTL_GUARD_ACTOR"

// Outcome constants for audit entries.
const (
	OutcomeAllowed       = "allowed"        // command passed through ungated
	OutcomeConfirmed     = "confirmed"      // gated command, user confirmed
	OutcomeAborted       = "aborted"        // gated command, user declined
	OutcomeBlocked       = "blocked"        // protected resource, refused
	OutcomeDenied        = "denied"         // fail-closed (config/context error)
	OutcomeAutoConfirmed = "auto-confirmed" // gated command, auto-approved via --yes/KUBECTL_GUARD_CONFIRM (audited)
	OutcomeBypassed      = "bypassed"       // guard fully bypassed via KUBECTL_GUARD_BYPASS (audited, discouraged)
	OutcomeDryRun        = "dry-run"        // state-altering command allowed because --dry-run changes nothing
	OutcomeRelayed       = "relayed"        // agent-relay mode: emitted needs-confirmation JSON, did not prompt
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

	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line := append(b, '\n')

	// Local file sink (with optional rotation), serialized across processes.
	fileErr := appendAuditFile(cfg, path, line)

	// Shipping sinks (webhook/syslog) are best-effort and independent of the file,
	// so a delivery failure never masks a successful local write and vice-versa.
	shipAudit(cfg, line)

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
func appendAuditFile(cfg *config.Config, path string, line []byte) error {
	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lockFile.Close() }()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	if cfg.AuditMaxSizeMB > 0 {
		maybeRotateAudit(path, int64(cfg.AuditMaxSizeMB)*1024*1024, cfg.AuditMaxFilesOrDefault(), len(line))
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(line)
	return err
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
