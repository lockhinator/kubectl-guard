//go:build !windows

package guard

import (
	"log/syslog"
	"strings"
)

// shipSyslog writes the audit line to the local syslog at LOG_INFO under facility
// LOG_USER, tagged "kubectl-guard". A fresh connection per entry is fine for a
// short-lived CLI process; any error (no syslog socket) is swallowed. log/syslog
// is unix-only, so this file is unix-only.
func shipSyslog(body []byte) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "kubectl-guard")
	if err != nil {
		return
	}
	defer func() { _ = w.Close() }()
	_ = w.Info(strings.TrimRight(string(body), "\n"))
}
