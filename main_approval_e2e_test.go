//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type approvalE2E struct{ bin, home, tools string }

func newApprovalE2E(t *testing.T, passwordless bool) approvalE2E {
	t.Helper()
	home, tools := t.TempDir(), t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\nconfirm_mode: agent-relay\naudit_mode: all\n")
	writeKubeconfig(t, home, "prod-cluster", nil)
	kubectl := `#!/bin/sh
printf 'EXECUTED:%s\n' "$*"
`
	if err := os.WriteFile(filepath.Join(tools, "kubectl"), []byte(kubectl), 0700); err != nil {
		t.Fatal(err)
	}
	sudo := "#!/bin/sh\n"
	if passwordless {
		sudo += "exit 0\n"
	} else {
		sudo += `case " $* " in *" -n "*) exit 1;; *) exit 0;; esac` + "\n"
	}
	if err := os.WriteFile(filepath.Join(tools, "sudo"), []byte(sudo), 0700); err != nil {
		t.Fatal(err)
	}
	return approvalE2E{bin: buildGuardBin(t), home: home, tools: tools}
}

func (f approvalE2E) run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(f.bin, args...)
	cmd.Env = []string{"HOME=" + f.home, "PATH=" + f.tools + ":/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func TestAuthenticatedApprovalEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	f := newApprovalE2E(t, false)
	if _, stderr, code := f.run(t, "approval", "setup"); code != 0 {
		t.Fatalf("approval setup exit=%d stderr=%s", code, stderr)
	}

	args := []string{"--context=prod-cluster", "delete", "pod", "api"}
	stdout, stderr, code := f.run(t, args...)
	if code != 4 || strings.Contains(stdout, "EXECUTED") {
		t.Fatalf("request: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var decision map[string]any
	line := strings.TrimSpace(stderr)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal([]byte(line), &decision); err != nil {
		t.Fatalf("decision JSON: %v\n%s", err, stderr)
	}
	prompt, _ := decision["prompt"].(string)
	id := regexp.MustCompile(`approve ([A-F0-9]{12})`).FindStringSubmatch(prompt)
	if len(id) != 2 {
		t.Fatalf("request ID missing from prompt: %q", prompt)
	}

	approveArgs := append([]string{"approve", id[1], "--", "kubectl"}, args...)
	stdout, stderr, code = f.run(t, approveArgs...)
	if code != 0 || !strings.Contains(stdout, "EXECUTED:--context=prod-cluster delete pod api") {
		t.Fatalf("approve: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, _, code = f.run(t, approveArgs...)
	if code == 0 || strings.Contains(stdout, "EXECUTED") {
		t.Fatalf("consumed approval replayed: exit=%d stdout=%q", code, stdout)
	}
}

func TestPasswordlessSudoFailsClosedEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	f := newApprovalE2E(t, true)
	_, stderr, code := f.run(t, "approval", "setup")
	if code == 0 || !strings.Contains(stderr, "self-approve") {
		t.Fatalf("passwordless setup: exit=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".kubectl-guard", "approval.json")); !os.IsNotExist(err) {
		t.Fatalf("unsafe setup wrote enabled state: %v", err)
	}
	_, status, statusCode := f.run(t, "approval", "status")
	if statusCode != 0 || !strings.Contains(status, "UNSAFE") || !strings.Contains(status, "self-approve") {
		t.Fatalf("approval status did not expose NOPASSWD: exit=%d output=%q", statusCode, status)
	}
	stdout, stderr, code := f.run(t, "--context=prod-cluster", "delete", "pod", "api")
	if code != 3 || strings.Contains(stdout, "EXECUTED") || !strings.Contains(stderr, "approval-authentication-unsafe") {
		t.Fatalf("passwordless request: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	_, doctor, code := f.run(t, "doctor")
	if code == 0 || !strings.Contains(doctor, "UNSAFE") || !strings.Contains(doctor, "self-approve") {
		t.Fatalf("doctor did not prominently fail: exit=%d output=%q", code, doctor)
	}
}
