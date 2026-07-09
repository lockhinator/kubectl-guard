package guard

import (
	"encoding/json"
	"os"
	"os/user"
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
	b = append(b, '\n')

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Acquire exclusive lock to prevent concurrent writes from interleaving.
	// flock is advisory and works across processes on the same host.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() {
		// Unlock failure is non-fatal: auditing is best-effort.
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}()

	_, err = f.Write(b)
	return err
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
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
