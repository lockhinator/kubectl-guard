//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
	bin := filepath.Join(t.TempDir(), "kubectl-guard")
	ld := "-X github.com/lockhinator/kubectl-guard/approval.TrustedSudoPath=" + filepath.Join(tools, "sudo") + " -X github.com/lockhinator/kubectl-guard/approval.TrustedSudoOwnerUID=" + strconv.Itoa(os.Geteuid())
	if out, err := exec.Command("go", "build", "-ldflags", ld, "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return approvalE2E{bin: bin, home: home, tools: tools}
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
	id := regexp.MustCompile(`approve ([A-F0-9]{32})`).FindStringSubmatch(prompt)
	if len(id) != 2 {
		t.Fatalf("request ID missing from prompt: %q", prompt)
	}

	approveArgs := []string{"approve", id[1]}
	stdout, stderr, code = f.run(t, approveArgs...)
	if code != 0 || !strings.Contains(stdout, "EXECUTED:--context=prod-cluster delete pod api") {
		t.Fatalf("approve: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	audit, err := os.ReadFile(filepath.Join(f.home, ".kubectl-guard-audit.log"))
	if err != nil || !strings.Contains(string(audit), `"outcome":"approval-consumed"`) {
		t.Fatalf("successful approval lifecycle not audited: err=%v audit=%s", err, audit)
	}
	stdout, _, code = f.run(t, approveArgs...)
	if code == 0 || strings.Contains(stdout, "EXECUTED") {
		t.Fatalf("consumed approval replayed: exit=%d stdout=%q", code, stdout)
	}
}

func TestApprovalTreatsHostileArgumentsLiterally(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	f := newApprovalE2E(t, false)
	if _, stderr, code := f.run(t, "approval", "setup"); code != 0 {
		t.Fatalf("approval setup exit=%d stderr=%s", code, stderr)
	}
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	hostile := "api;touch " + marker + " $(touch " + marker + ") `touch " + marker + "` * > " + marker + "\nnext"
	_, stderr, code := f.run(t, "--context=prod-cluster", "delete", "pod", hostile)
	if code != 4 {
		t.Fatalf("request exit=%d stderr=%q", code, stderr)
	}
	var decision map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &decision); err != nil {
		t.Fatalf("decision JSON: %v: %q", err, stderr)
	}
	prompt, _ := decision["prompt"].(string)
	if strings.Contains(prompt, hostile) || strings.Contains(prompt, marker) {
		t.Fatalf("agent-controlled argv leaked into copy/paste prompt: %q", prompt)
	}
	id := regexp.MustCompile(`approve ([A-F0-9]{32})`).FindStringSubmatch(prompt)
	if len(id) != 2 {
		t.Fatalf("request ID missing: %q", stderr)
	}
	stdout, stderr, code := f.run(t, "approve", id[1])
	if code != 0 || !strings.Contains(stdout, hostile) {
		t.Fatalf("approve exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("hostile argument was shell-evaluated: %v", err)
	}
}

func TestApprovalRejectsChangedKubernetesTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	f := newApprovalE2E(t, false)
	if _, stderr, code := f.run(t, "approval", "setup"); code != 0 {
		t.Fatalf("approval setup exit=%d stderr=%s", code, stderr)
	}
	_, stderr, code := f.run(t, "--context=prod-cluster", "delete", "pod", "api")
	if code != 4 {
		t.Fatalf("request exit=%d stderr=%q", code, stderr)
	}
	id := regexp.MustCompile(`approve ([A-F0-9]{32})`).FindStringSubmatch(stderr)
	if len(id) != 2 {
		t.Fatalf("request ID missing: %q", stderr)
	}
	kubeconfig := filepath.Join(f.home, ".kube", "config")
	b, err := os.ReadFile(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(b), "https://127.0.0.1:6443", "https://attacker.example.com", 1)
	if changed == string(b) {
		t.Fatal("fixture server was not found")
	}
	if err := os.WriteFile(kubeconfig, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := f.run(t, "approve", id[1])
	if code == 0 || strings.Contains(stdout, "EXECUTED") || !strings.Contains(stderr, "target changed") {
		t.Fatalf("changed target approve exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	audit, err := os.ReadFile(filepath.Join(f.home, ".kubectl-guard-audit.log"))
	if err != nil || !strings.Contains(string(audit), `"outcome":"approval-rejected"`) {
		t.Fatalf("approval rejection not audited: err=%v audit=%s", err, audit)
	}
}

func TestAuthenticationFailureIsAudited(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	f := newApprovalE2E(t, false)
	if _, stderr, code := f.run(t, "approval", "setup"); code != 0 {
		t.Fatalf("setup: %d %s", code, stderr)
	}
	_, stderr, _ := f.run(t, "--context=prod-cluster", "delete", "pod", "api")
	id := regexp.MustCompile(`approve ([A-F0-9]{32})`).FindStringSubmatch(stderr)
	sudo := "#!/bin/sh\ncase \" $* \" in *\" -n \"*) exit 1;; *\" -K \"*) exit 0;; *) exit 1;; esac\n"
	if err := os.WriteFile(filepath.Join(f.tools, "sudo"), []byte(sudo), 0700); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := f.run(t, "approve", id[1])
	if code == 0 || strings.Contains(stdout, "EXECUTED") {
		t.Fatalf("auth failure executed: code=%d stdout=%q", code, stdout)
	}
	audit, err := os.ReadFile(filepath.Join(f.home, ".kubectl-guard-audit.log"))
	if err != nil || !strings.Contains(string(audit), `"outcome":"authentication-failed"`) {
		t.Fatalf("authentication failure not audited: err=%v audit=%s", err, audit)
	}
}

func TestApprovalRevalidatesTargetAfterAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	f := newApprovalE2E(t, false)
	if _, stderr, code := f.run(t, "approval", "setup"); code != 0 {
		t.Fatalf("approval setup exit=%d stderr=%s", code, stderr)
	}
	_, stderr, code := f.run(t, "--context=prod-cluster", "delete", "pod", "api")
	if code != 4 {
		t.Fatalf("request exit=%d stderr=%q", code, stderr)
	}
	id := regexp.MustCompile(`approve ([A-F0-9]{32})`).FindStringSubmatch(stderr)
	kubeconfig := filepath.Join(f.home, ".kube", "config")
	sudo := "#!/bin/sh\ncase \" $* \" in *\" -n \"*) exit 1;; *\" -K \"*) exit 0;; esac\n" +
		"sed 's#https://127.0.0.1:6443#https://changed-during-auth.example.com#' \"" + kubeconfig + "\" > \"" + kubeconfig + ".new\"\n" +
		"mv \"" + kubeconfig + ".new\" \"" + kubeconfig + "\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(f.tools, "sudo"), []byte(sudo), 0700); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := f.run(t, "approve", id[1])
	if code == 0 || strings.Contains(stdout, "EXECUTED") || !strings.Contains(stderr, "changed during authentication") {
		t.Fatalf("post-auth target change exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestApprovalRevalidatesRequestAndExecutableAfterAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	for _, mutation := range []string{"request", "kubectl", "policy"} {
		t.Run(mutation, func(t *testing.T) {
			f := newApprovalE2E(t, false)
			if _, stderr, code := f.run(t, "approval", "setup"); code != 0 {
				t.Fatalf("approval setup exit=%d stderr=%s", code, stderr)
			}
			_, stderr, code := f.run(t, "--context=prod-cluster", "delete", "pod", "api")
			if code != 4 {
				t.Fatalf("request exit=%d stderr=%q", code, stderr)
			}
			id := regexp.MustCompile(`approve ([A-F0-9]{32})`).FindStringSubmatch(stderr)
			var mutate string
			switch mutation {
			case "request":
				path := filepath.Join(f.home, ".kubectl-guard", "approvals", id[1]+".json")
				mutate = "printf 'tampered' > \"" + path + "\""
			case "kubectl":
				path := filepath.Join(f.tools, "kubectl")
				mutate = "printf '#!/bin/sh\\nprintf \\\"ATTACKER\\\\n\\\"\\n' > \"" + path + "\"; chmod 700 \"" + path + "\""
			default:
				path := filepath.Join(f.home, ".kubectl-guard.yaml")
				mutate = "printf '\\ncontext_mode: block\\n' >> \"" + path + "\""
			}
			sudo := "#!/bin/sh\ncase \" $* \" in *\" -n \"*) exit 1;; *\" -K \"*) exit 0;; esac\n" + mutate + "\nexit 0\n"
			if err := os.WriteFile(filepath.Join(f.tools, "sudo"), []byte(sudo), 0700); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, code := f.run(t, "approve", id[1])
			if code == 0 || strings.Contains(stdout, "EXECUTED") || strings.Contains(stdout, "ATTACKER") {
				t.Fatalf("mutation=%s exit=%d stdout=%q stderr=%q", mutation, code, stdout, stderr)
			}
		})
	}
}

func TestAgentRelayRejectsMutableFileInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
	f := newApprovalE2E(t, false)
	if _, stderr, code := f.run(t, "approval", "setup"); code != 0 {
		t.Fatalf("approval setup exit=%d stderr=%s", code, stderr)
	}
	for _, args := range [][]string{
		{"--context=prod-cluster", "apply", "-f", "manifest.yaml"},
		{"--context=prod-cluster", "apply", "-f-"},
		{"--context=prod-cluster", "patch", "pod", "api", "--patch-file=patch.json"},
		{"--context=prod-cluster", "apply", "-k", "overlays/prod"},
	} {
		stdout, stderr, code := f.run(t, args...)
		if code == 0 || strings.Contains(stdout, "EXECUTED") || !strings.Contains(stderr, "mutable input bytes cannot be bound") {
			t.Fatalf("args=%q exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	audit, err := os.ReadFile(filepath.Join(f.home, ".kubectl-guard-audit.log"))
	if err != nil || !strings.Contains(string(audit), "approval-mutable-input:") {
		t.Fatalf("mutable-input denials not audited: err=%v audit=%s", err, audit)
	}
}

func TestUnsupportedApprovalInputClassification(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"apply", "-f", "manifest.yaml"}, true},
		{[]string{"apply", "--filename=manifest.yaml"}, true},
		{[]string{"apply", "-koverlays/prod"}, true},
		{[]string{"apply", "--kustomize", "overlays/prod"}, true},
		{[]string{"patch", "pod", "api", "--patch-file", "patch.json"}, true},
		{[]string{"create", "configmap", "cfg", "--from-file=data"}, true},
		{[]string{"create", "secret", "generic", "s", "--from-env-file", "secret.env"}, true},
		{[]string{"--certificate-authority=ca.pem", "delete", "pod", "api"}, true},
		{[]string{"--client-certificate", "cert.pem", "delete", "pod", "api"}, true},
		{[]string{"--client-key=key.pem", "delete", "pod", "api"}, true},
		{[]string{"--token-file", "token", "delete", "pod", "api"}, true},
		{[]string{"create", "secret", "tls", "site", "--cert=cert.pem", "--key", "key.pem"}, true},
		{[]string{"cp", "local.txt", "pod:/tmp/local.txt"}, true},
		{[]string{"exec", "-i", "pod", "--", "sh"}, true},
		{[]string{"attach", "pod", "--stdin=true"}, true},
		{[]string{"run", "shell", "-i", "--image=busybox"}, true},
		{[]string{"exec", "pod", "--", "app", "-f", "config"}, false},
		{[]string{"run", "job", "--image=app", "--", "app", "--stdin=true"}, false},
		{[]string{"delete", "pod", "api"}, false},
	}
	for _, tt := range tests {
		if got := unsupportedApprovalInput(tt.args) != ""; got != tt.want {
			t.Errorf("args=%q rejected=%v want=%v", tt.args, got, tt.want)
		}
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
	if statusCode == 0 || !strings.Contains(status, "UNSAFE") || !strings.Contains(status, "self-approve") {
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
