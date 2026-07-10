package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runRootArgs drives the modeled root command in-process and captures its output.
func runRootArgs(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCommand()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

// TestCompletionGeneration: `completion <shell>` emits a non-empty script that
// includes the config subtree, for every supported shell. #39.
func TestCompletionGeneration(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		out, err := runRootArgs(t, "completion", sh)
		if err != nil {
			t.Fatalf("completion %s: %v", sh, err)
		}
		if len(out) == 0 {
			t.Errorf("completion %s produced empty output", sh)
		}
		// The scripts are generic runtime drivers (subcommands are discovered via
		// __complete, not embedded), so assert the program name is wired in; the
		// config-subcommand completion itself is covered by the dynamic tests below.
		if !strings.Contains(out, "kubectl-guard") {
			t.Errorf("completion %s script not wired to kubectl-guard", sh)
		}
	}
}

// TestRootSubcommandsPresent: the modeled root exposes the guard's own
// subcommands, so completion covers them. #39.
func TestRootSubcommandsPresent(t *testing.T) {
	root := newRootCommand()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"config", "doctor", "explain"} {
		if !names[want] {
			t.Errorf("root missing subcommand %q", want)
		}
	}
	// The config subtree is reachable and populated.
	var configCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "config" {
			configCmd = c
		}
	}
	if configCmd == nil || len(configCmd.Commands()) == 0 {
		t.Fatalf("config command has no subcommands")
	}
}

// TestDynamicCompletionRemoveContext: `config remove-context <TAB>` completes
// from the currently-protected contexts (stretch AC). #39.
func TestDynamicCompletionRemoveContext(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECTL_GUARD_CONFIG", "")
	if err := os.WriteFile(filepath.Join(home, ".kubectl-guard.yaml"),
		[]byte("protected_contexts:\n  - prod-*\n  - staging-*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runRootArgs(t, cobra.ShellCompRequestCmd, "config", "remove-context", "")
	if err != nil {
		t.Fatalf("__complete remove-context: %v", err)
	}
	if !strings.Contains(out, "prod-*") || !strings.Contains(out, "staging-*") {
		t.Errorf("remove-context completion missing protected contexts, got:\n%s", out)
	}
}

// TestDynamicCompletionAddResource: `config add-resource <TAB>` offers common
// kinds. #39.
func TestDynamicCompletionAddResource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECTL_GUARD_CONFIG", "")
	out, err := runRootArgs(t, cobra.ShellCompRequestCmd, "config", "add-resource", "")
	if err != nil {
		t.Fatalf("__complete add-resource: %v", err)
	}
	if !strings.Contains(out, "secret") || !strings.Contains(out, "configmap") {
		t.Errorf("add-resource completion missing common kinds, got:\n%s", out)
	}
}

// TestInvokedAsGuard: the completion dispatch treats invocation by our own name
// as the guard's completion, but the `kubectl` shim name as kubectl's own
// (pass-through), so a shim user's real kubectl tab-completion is not hijacked.
// #39.
func TestInvokedAsGuard(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()
	cases := []struct {
		arg0 string
		want bool
	}{
		{"/usr/local/bin/kubectl-guard", true},
		{"kubectl-guard", true},
		{"/tmp/build/kubectl-guard-test", true},
		{"/usr/local/bin/kubectl", false},
		{"kubectl", false},
	}
	for _, c := range cases {
		os.Args = []string{c.arg0}
		if got := invokedAsGuard(); got != c.want {
			t.Errorf("invokedAsGuard(%q) = %v, want %v", c.arg0, got, c.want)
		}
	}
}

// TestFirstArgCompleteSecondArg: firstArgComplete offers nothing once the first
// positional arg is present (these commands take exactly one). #39.
func TestFirstArgCompleteSecondArg(t *testing.T) {
	got, _ := firstArgComplete(func() []string { return []string{"a", "b"} })(nil, []string{"already"}, "")
	if len(got) != 0 {
		t.Errorf("expected no completions once the first arg is set, got %v", got)
	}
}

// TestShimDoesNotHijackKubectlCompletion drives the real run() dispatch through a
// `kubectl`-named symlink and asserts a __complete request is FORWARDED to the
// real kubectl (native completion preserved), not served by the guard — the
// load-bearing back-compat behavior for shim users. It also confirms an
// own-name invocation DOES serve the guard's completion. #39.
func TestShimDoesNotHijackKubectlCompletion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t) // built as ".../kubectl-guard-test"

	// A `kubectl`-named symlink to the guard: argv[0] basename is "kubectl", so
	// run() must treat __complete/completion as kubectl's, not the guard's.
	shimDir := t.TempDir()
	shim := filepath.Join(shimDir, "kubectl")
	if err := os.Symlink(bin, shim); err != nil {
		t.Fatal(err)
	}

	// A fake REAL kubectl later in PATH that answers __complete distinctively.
	realDir := t.TempDir()
	realScript := "#!/bin/sh\n" +
		"if [ \"$1\" = \"config\" ] && [ \"$2\" = \"current-context\" ]; then echo devctx\n" +
		"elif [ \"$1\" = \"__complete\" ]; then echo REAL_KUBECTL_COMPLETE; echo :4\n" +
		"else echo \"$@\"; fi\n"
	if err := os.WriteFile(filepath.Join(realDir, "kubectl"), []byte(realScript), 0o755); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	writeConfig(t, home, "{}\n") // empty config: reads pass through

	// Invoked as the `kubectl` shim: __complete must reach REAL kubectl.
	shimCmd := exec.Command(shim, "__complete", "get", "")
	shimCmd.Env = []string{"HOME=" + home, "PATH=" + shimDir + ":" + realDir + ":/usr/bin:/bin"}
	shimOut, _ := shimCmd.CombinedOutput()
	if !strings.Contains(string(shimOut), "REAL_KUBECTL_COMPLETE") {
		t.Errorf("shim did not forward __complete to real kubectl; got:\n%s", shimOut)
	}
	if strings.Contains(string(shimOut), "add-context") {
		t.Errorf("shim hijacked kubectl completion with the guard's own; got:\n%s", shimOut)
	}

	// Invoked by its own name: __complete IS the guard's completion.
	guardCmd := exec.Command(bin, "__complete", "config", "")
	guardCmd.Env = []string{"HOME=" + home, "PATH=" + realDir + ":/usr/bin:/bin"}
	guardOut, _ := guardCmd.CombinedOutput()
	if !strings.Contains(string(guardOut), "add-context") {
		t.Errorf("own-name __complete did not serve guard completion; got:\n%s", guardOut)
	}
}
