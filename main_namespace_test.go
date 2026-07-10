package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeNamespacedKubectl installs a fake kubectl for COMMAND EXECUTION: it
// echoes any forwarded invocation to stdout so it is observable. Since issue #31
// the guard resolves the context namespace from the kubeconfig via clientcmd
// (see writeKubeconfig), not from this fake — the retained `config
// current-context`/`config view` answers are only a harmless legacy-path
// fallback and are ignored on the clientcmd path.
func writeNamespacedKubectl(t *testing.T, ns string) string {
	t.Helper()
	dir := t.TempDir()
	// Scan every arg (not just $1/$2) so a leading --context=/--kubeconfig=
	// prefix on the guard's internal lookups is handled.
	script := `#!/bin/sh
for a in "$@"; do
  if [ "$a" = "current-context" ]; then echo "fake-context"; exit 0; fi
  if [ "$a" = "view" ]; then printf '%s' "` + ns + `"; exit 0; fi
done
echo "$@"
`
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestBlockMessageUsesContextDerivedNamespace: when a state-altering command is
// hard-blocked because the resolved CONTEXT's namespace is protected (no -n
// flag), the block message must name that namespace ("kube-system"), not the
// tier-1 fallback ("default"). Guards the tier-2 message fix.
func TestBlockMessageUsesContextDerivedNamespace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_namespaces:\n  - kube-system\nnamespace_mode: block\n")
	// The namespace must come from the CURRENT context (tier 2): clientcmd reads
	// it from this kubeconfig, so bake kube-system into fake-context.
	writeKubeconfig(t, home, "fake-context", map[string]string{"fake-context": "kube-system"})
	kubectlDir := writeNamespacedKubectl(t, "kube-system")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// No -n flag: the namespace must come from the context (tier 2).
	cmd := exec.CommandContext(ctx, bin, "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	out, _ := cmd.CombinedOutput()
	code := 0
	if ee, ok := ctxErr(cmd); ok {
		code = ee
	}

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (block mode)", code)
	}
	got := string(out)
	if !strings.Contains(got, `protected namespace "kube-system"`) {
		t.Errorf("block message did not name the context-derived namespace; got:\n%s", got)
	}
	if strings.Contains(got, `"default"`) {
		t.Errorf("block message wrongly showed the tier-1 default namespace; got:\n%s", got)
	}
}

// ctxErr returns the process exit code and whether it exited non-zero.
func ctxErr(cmd *exec.Cmd) (int, bool) {
	if cmd.ProcessState == nil {
		return 0, false
	}
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return code, true
	}
	return 0, false
}
