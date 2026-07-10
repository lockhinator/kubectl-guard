package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// theSecret is the cleartext that must never reach the audit log, --json
// output, or any user-facing message.
const theSecret = "hunter2"

// runGuardEnv is runGuardBin with extra environment variables, for exercising
// the KUBECTL_GUARD_BYPASS audit path.
func runGuardEnv(t *testing.T, cfgYAML string, extraEnv []string, args ...string) (stdout, stderr string, code int, auditLog string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, cfgYAML)
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append([]string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}, extraEnv...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("guard hung: %v", ctx.Err())
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error running guard: %v", err)
		}
	}
	if data, rerr := os.ReadFile(home + "/.kubectl-guard-audit.log"); rerr == nil {
		auditLog = string(data)
	}
	return outBuf.String(), errBuf.String(), code, auditLog
}

// TestAuditRedactsFromLiteral is the headline #89 criterion: the audit log must
// record `--from-literal=password=***`, never `hunter2`.
func TestAuditRedactsFromLiteral(t *testing.T) {
	_, _, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "create", "secret", "generic", "db", "--from-literal=password="+theSecret)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(audit, theSecret) {
		t.Errorf("audit log leaked the secret value:\n%s", audit)
	}
	if !strings.Contains(audit, `--from-literal=password=***`) {
		t.Errorf("audit should contain --from-literal=password=***, got:\n%s", audit)
	}
}

// TestAuditRedactsTokenBothForms: --token=<v> and --token <v> are redacted.
func TestAuditRedactsTokenBothForms(t *testing.T) {
	for _, args := range [][]string{
		{"--context=dev-cluster", "get", "pods", "--token=" + theSecret},
		{"--context=dev-cluster", "get", "pods", "--token", theSecret},
	} {
		_, _, _, audit := runGuardBin(t, "protected_contexts:\n  - prod-*\naudit_mode: all\n", args...)
		if strings.Contains(audit, theSecret) {
			t.Errorf("audit leaked --token value for %v:\n%s", args, audit)
		}
		if !strings.Contains(audit, "***") {
			t.Errorf("audit should mark the redaction for %v, got:\n%s", args, audit)
		}
		// The existing token-presence flag must still be recorded.
		if !strings.Contains(audit, `"token":true`) {
			t.Errorf("audit should still record token:true for %v, got:\n%s", args, audit)
		}
	}
}

// TestAuditRedactsKeyMaterialFlags covers --docker-password, --password and the
// key-material flags.
func TestAuditRedactsKeyMaterialFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--context=dev-cluster", "create", "secret", "docker-registry", "r", "--docker-password=" + theSecret},
		{"--context=dev-cluster", "get", "pods", "--password", theSecret},
		{"--context=dev-cluster", "get", "pods", "--client-key=" + theSecret},
		{"--context=dev-cluster", "get", "pods", "--certificate-authority", theSecret},
		{"--context=dev-cluster", "get", "pods", "--tls-private-key=" + theSecret},
	} {
		_, _, _, audit := runGuardBin(t, "protected_contexts:\n  - prod-*\naudit_mode: all\n", args...)
		if strings.Contains(audit, theSecret) {
			t.Errorf("audit leaked a secret for %v:\n%s", args, audit)
		}
	}
}

// TestJSONOutputRedacted: the --json decision object's command field must be
// redacted too, since agent frameworks log it.
func TestJSONOutputRedacted(t *testing.T) {
	_, stderr, code, _ := runGuardBin(t,
		"protected_resources:\n  - secret\n",
		"--json", "get", "secret", "db", "--token="+theSecret)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (blocked)", code)
	}
	if strings.Contains(stderr, theSecret) {
		t.Fatalf("--json output leaked the token:\n%s", stderr)
	}
	line := strings.TrimSpace(stderr)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	var jr struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(line), &jr); err != nil {
		t.Fatalf("stderr is not a JSON decision object: %v\nstderr=%q", err, stderr)
	}
	if !strings.Contains(jr.Command, "--token=***") {
		t.Errorf("json command should be redacted, got %q", jr.Command)
	}
}

// TestPromptOutputRedacted: on the gated (RequireConfirmation) path with no TTY
// the guard aborts; nothing it prints may contain the secret.
func TestPromptOutputRedacted(t *testing.T) {
	_, stderr, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=prod-cluster", "delete", "pod", "nginx", "--token="+theSecret)

	if code != 4 {
		t.Fatalf("exit code = %d, want 4 (gated, aborted)", code)
	}
	if strings.Contains(stderr, theSecret) {
		t.Errorf("prompt/warning output leaked the token:\n%s", stderr)
	}
	if strings.Contains(audit, theSecret) {
		t.Errorf("audit leaked the token:\n%s", audit)
	}
}

// TestBypassAuditRedacted: the KUBECTL_GUARD_BYPASS escape hatch writes its own
// audit entry, which must be redacted too — it was a second copy of the leak.
func TestBypassAuditRedacted(t *testing.T) {
	_, _, _, audit := runGuardEnv(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		[]string{"KUBECTL_GUARD_BYPASS=1"},
		"create", "secret", "generic", "db", "--from-literal=password="+theSecret)

	if strings.Contains(audit, theSecret) {
		t.Errorf("bypass audit entry leaked the secret:\n%s", audit)
	}
	if !strings.Contains(audit, `"outcome":"bypassed"`) {
		t.Errorf("expected a bypassed audit entry, got:\n%s", audit)
	}
	if !strings.Contains(audit, "--from-literal=password=***") {
		t.Errorf("bypass audit should be redacted, got:\n%s", audit)
	}
}

// TestAuditRedactsEnvVars: environment variables are a primary carrier of
// credentials. Both the --env flag and `set env`'s positional KEY=VALUE form
// must be redacted on disk and in --json.
func TestAuditRedactsEnvVars(t *testing.T) {
	for _, args := range [][]string{
		{"--context=dev-cluster", "run", "x", "--image=nginx", "--env=DB_PASSWORD=" + theSecret},
		{"--context=dev-cluster", "run", "x", "--env", "DB_PASSWORD=" + theSecret},
		{"--context=dev-cluster", "set", "env", "deployment/web", "--env=DB_PASSWORD=" + theSecret},
		{"--context=dev-cluster", "set", "env", "deployment/web", "DB_PASSWORD=" + theSecret},
		{"--context=dev-cluster", "config", "set-credentials", "u", "--exec-env=TOKEN=" + theSecret},
		{"--context=dev-cluster", "config", "set-credentials", "u", "--auth-provider-arg=client-secret=" + theSecret},
	} {
		_, _, _, audit := runGuardBin(t, "protected_contexts:\n  - prod-*\naudit_mode: all\n", args...)
		if strings.Contains(audit, theSecret) {
			t.Errorf("audit leaked an env secret for %v:\n%s", args, audit)
		}
		if !strings.Contains(audit, "***") {
			t.Errorf("audit should mark the redaction for %v, got:\n%s", args, audit)
		}
	}
}

// TestSetEnvSecretStillReachesKubectl: the positional redaction must not alter
// the args handed to kubectl.
func TestSetEnvSecretStillReachesKubectl(t *testing.T) {
	stdout, _, code, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "set", "env", "deployment/web", "DB_PASSWORD="+theSecret)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "DB_PASSWORD="+theSecret) {
		t.Errorf("kubectl must receive the REAL command, got stdout=%q", stdout)
	}
}

// TestAuditRedactsPatchAndShorthands: JSON-blob flags (--patch/-p, --overrides)
// and the -e shorthand of --env are the remaining cleartext-in-argv carriers.
// `patch secret x -p '{"stringData":{"password":"..."}}'` is the usual way to
// set a secret value from the CLI.
func TestAuditRedactsPatchAndShorthands(t *testing.T) {
	for _, args := range [][]string{
		{"--context=dev-cluster", "patch", "secret", "db", "-p", `{"stringData":{"password":"` + theSecret + `"}}`},
		{"--context=dev-cluster", "patch", "secret", "db", `--patch={"stringData":{"password":"` + theSecret + `"}}`},
		{"--context=dev-cluster", "run", "x", "--image=n", `--overrides={"env":"` + theSecret + `"}`},
		{"--context=dev-cluster", "set", "env", "deploy/x", "-e", "PASSWORD=" + theSecret},
		{"--context=dev-cluster", "set", "env", "deploy/x", "-e=PASSWORD=" + theSecret},
		{"--context=dev-cluster", "set", "env", "deploy/x", "-ePASSWORD=" + theSecret},
		{"--context=dev-cluster", "config", "set-credentials", "u", "--exec-arg=--token=" + theSecret},
	} {
		_, _, _, audit := runGuardBin(t, "protected_contexts:\n  - prod-*\naudit_mode: all\n", args...)
		if strings.Contains(audit, theSecret) {
			t.Errorf("audit leaked a secret for %v:\n%s", args, audit)
		}
		if !strings.Contains(audit, "***") {
			t.Errorf("audit should mark the redaction for %v, got:\n%s", args, audit)
		}
	}
}

// TestAuditRedactsConfigSetPositional: `kubectl config set PROPERTY VALUE`
// writes credential material as a bare positional. kubectl's own help documents
// `config set users.cluster-admin.client-key-data cert_data_here`.
func TestAuditRedactsConfigSetPositional(t *testing.T) {
	for _, args := range [][]string{
		{"--context=dev-cluster", "config", "set", "users.admin.token", theSecret},
		{"--context=dev-cluster", "config", "set", "users.admin.password", theSecret},
		{"--context=dev-cluster", "config", "set", "users.cluster-admin.client-key-data", theSecret},
	} {
		_, _, _, audit := runGuardBin(t, "protected_contexts:\n  - prod-*\naudit_mode: all\n", args...)
		if strings.Contains(audit, theSecret) {
			t.Errorf("audit leaked a config-set secret for %v:\n%s", args, audit)
		}
		if !strings.Contains(audit, "***") {
			t.Errorf("audit should mark the redaction for %v, got:\n%s", args, audit)
		}
	}
}

// TestConfigSetNonCredentialLegible: only credential properties are redacted;
// ordinary kubeconfig settings stay readable in the audit log.
func TestConfigSetNonCredentialLegible(t *testing.T) {
	_, _, _, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "config", "set", "current-context", "prod")

	if strings.Contains(audit, "***") {
		t.Errorf("config set current-context must not be redacted, got:\n%s", audit)
	}
	if !strings.Contains(audit, "config set current-context prod") {
		t.Errorf("audit should record the setting verbatim, got:\n%s", audit)
	}
}

// TestConfirmPromptDoesNotLeakOverrides: the confirm/block message is built
// from GetCommandDescription, which prints a positional token. An unconsumed
// --overrides value used to land there and print the secret verbatim.
func TestConfirmPromptDoesNotLeakOverrides(t *testing.T) {
	_, stderr, _, _ := runGuardBin(t,
		"protected_contexts:\n  - dev-*\naudit_mode: all\n",
		"--context=dev-cluster", "create", "-f", "x", "--overrides", `{"p":"`+theSecret+`"}`)

	if strings.Contains(stderr, theSecret) {
		t.Errorf("the confirm/warning message leaked the --overrides body:\n%s", stderr)
	}
}

// TestJSONResourceFieldDoesNotLeak: JSONForResult's `resource` field is derived
// from a positional token; it must come from the redacted args.
func TestJSONResourceFieldDoesNotLeak(t *testing.T) {
	dir := t.TempDir()
	manifest := dir + "/prot.yaml"
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code, _ := runGuardBin(t,
		"protected_resources:\n  - secret\n",
		"--json", "create", "-f", manifest, "--overrides", `{"p":"`+theSecret+`"}`)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (blocked)", code)
	}
	if strings.Contains(stderr, theSecret) {
		t.Fatalf("--json output leaked the --overrides body:\n%s", stderr)
	}
	line := strings.TrimSpace(stderr)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	var jr struct {
		Command  string `json:"command"`
		Resource string `json:"resource"`
	}
	if err := json.Unmarshal([]byte(line), &jr); err != nil {
		t.Fatalf("stderr is not a JSON decision object: %v\nstderr=%q", err, stderr)
	}
	if strings.Contains(jr.Resource, theSecret) || strings.Contains(jr.Command, theSecret) {
		t.Errorf("json fields leaked the secret: command=%q resource=%q", jr.Command, jr.Resource)
	}
}

// TestVerbShiftConfigSetAuditRedacted: a stray leading positional makes
// ExtractCommand resolve `config set` via its fallback; the value must still be
// redacted in the audit log.
func TestVerbShiftConfigSetAuditRedacted(t *testing.T) {
	_, _, _, audit := runGuardBin(t,
		"protected_contexts:\n  - dev-*\naudit_mode: all\n",
		"--context=dev-cluster", "foo", "config", "set", "users.a.token", theSecret)

	if strings.Contains(audit, theSecret) {
		t.Errorf("audit leaked a config-set secret under a verb shift:\n%s", audit)
	}
}

// TestLogsPreviousFlagNotRedacted: -p is --patch on `patch` but the boolean
// --previous on `logs`. A global alias would swallow the pod name and corrupt
// the audit record.
func TestLogsPreviousFlagNotRedacted(t *testing.T) {
	_, _, _, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "logs", "-p", "nginx")

	if strings.Contains(audit, "***") {
		t.Errorf("logs -p is boolean; nothing should be redacted, got:\n%s", audit)
	}
	if !strings.Contains(audit, "logs -p nginx") {
		t.Errorf("audit should record `logs -p nginx` verbatim, got:\n%s", audit)
	}
}

// TestPatchSecretStillReachesKubectl: the patch body must still be delivered.
func TestPatchSecretStillReachesKubectl(t *testing.T) {
	stdout, _, _, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "patch", "deploy", "web", "-p", `{"spec":{"replicas":3}}`)

	if !strings.Contains(stdout, `{"spec":{"replicas":3}}`) {
		t.Errorf("kubectl must receive the REAL patch body, got stdout=%q", stdout)
	}
}

// TestSetImageNotRedacted: positional KEY=VALUE redaction is scoped to
// `set env`; `set image` must stay legible in the audit log.
func TestSetImageNotRedacted(t *testing.T) {
	_, _, _, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "set", "image", "deploy/x", "nginx=nginx:latest")

	if strings.Contains(audit, "***") {
		t.Errorf("set image must not be redacted, got:\n%s", audit)
	}
	if !strings.Contains(audit, "nginx=nginx:latest") {
		t.Errorf("set image should be logged verbatim, got:\n%s", audit)
	}
}

// TestNonSecretCommandLoggedUnchanged: redaction must not touch ordinary
// commands — the audit log stays a faithful record.
func TestNonSecretCommandLoggedUnchanged(t *testing.T) {
	_, _, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "get", "pods", "-n", "kube-system")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(audit, "***") {
		t.Errorf("non-secret command must be logged unchanged, got:\n%s", audit)
	}
	if !strings.Contains(audit, `--context=dev-cluster get pods -n kube-system`) {
		t.Errorf("audit should record the full command, got:\n%s", audit)
	}
}

// TestSecretStillReachesKubectl: redaction is for the guard's own surfaces. The
// real command, with its real secret, must still be handed to kubectl intact —
// otherwise the guard would break every `create secret` it allows.
func TestSecretStillReachesKubectl(t *testing.T) {
	stdout, _, code, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "create", "secret", "generic", "db", "--from-literal=password="+theSecret)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "--from-literal=password="+theSecret) {
		t.Errorf("kubectl must receive the REAL command, got stdout=%q", stdout)
	}
}
