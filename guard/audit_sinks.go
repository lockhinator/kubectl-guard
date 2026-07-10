package guard

import (
	"bytes"
	"errors"
	"io"
	"log/syslog"
	"net/http"
	"strings"
	"time"

	"github.com/lockhinator/kubectl-guard/config"
)

// auditWebhookTimeout bounds how long a webhook POST may delay the command. The
// guard syscall.Execs kubectl right after auditing, so shipping cannot be moved
// to a background goroutine (Exec would kill it); it is synchronous with a short
// timeout instead. A slow or dead webhook therefore adds at most this much
// latency, and never fails the command.
const auditWebhookTimeout = 3 * time.Second

// shipAudit sends the JSON audit line to any configured non-file sinks. Every
// sink is best-effort: a failure is swallowed so it can never fail the command or
// mask the local file write. Sinks only fire for entries that passed the
// audit-mode filter (AppendAudit checks ShouldAudit before calling this).
func shipAudit(cfg *config.Config, line []byte) {
	if cfg == nil {
		return
	}
	if cfg.AuditWebhookURL != "" {
		shipWebhook(cfg.AuditWebhookURL, line)
	}
	if cfg.AuditSyslog {
		shipSyslog(line)
	}
}

// errNoRedirect refuses to follow an HTTP redirect from the webhook. A redirect
// would re-POST the audit body (redacted command metadata) to a host the user did
// not configure — a needless SSRF/exfil surface for a security tool — so the POST
// is confined to the exact configured URL.
var errNoRedirect = errors.New("audit webhook: refusing to follow redirect")

// shipWebhook POSTs the audit line as a JSON body to url. Best-effort: transport
// errors, refused redirects, and non-2xx responses are ignored. The response body
// is drained and closed so the connection can be reused/freed.
func shipWebhook(url string, body []byte) {
	client := &http.Client{
		Timeout: auditWebhookTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errNoRedirect
		},
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// shipSyslog writes the audit line to the local syslog at LOG_INFO under
// facility LOG_USER, tagged "kubectl-guard". A fresh connection per entry is fine
// for a short-lived CLI process; any error (no syslog socket) is swallowed.
func shipSyslog(body []byte) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "kubectl-guard")
	if err != nil {
		return
	}
	defer func() { _ = w.Close() }()
	_ = w.Info(strings.TrimRight(string(body), "\n"))
}
