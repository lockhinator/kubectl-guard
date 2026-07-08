package guard

import (
	"encoding/json"
	"os"
	"os/user"
	"time"

	"github.com/cameronlockhart/kubectl-guard/config"
)

// AuditEntry is a single line in the audit log.
type AuditEntry struct {
	Time    string `json:"time"`
	User    string `json:"user"`
	Context string `json:"context,omitempty"`
	Command string `json:"command"`
	Outcome string `json:"outcome"` // confirmed | aborted | blocked
	Reason  string `json:"reason,omitempty"`
}

// AppendAudit appends entry as a JSON line to the configured audit log. Time
// and User are stamped here so callers can omit them. A nil cfg uses defaults.
// Errors are returned but should be non-fatal: auditing is best-effort.
func AppendAudit(cfg *config.Config, entry AuditEntry) error {
	if cfg == nil {
		cfg = &config.Config{}
	}
	path, err := config.AuditPath(cfg)
	if err != nil {
		return err
	}

	entry.Time = time.Now().UTC().Format(time.RFC3339)
	entry.User = currentUser()

	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(b)
	return err
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}
