package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

func TestExtractCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCmd    string
		wantSubCmd string
	}{
		{
			name:       "simple command",
			args:       []string{"get", "pods"},
			wantCmd:    "get",
			wantSubCmd: "pods",
		},
		{
			name:       "command with flags first",
			args:       []string{"-n", "default", "get", "pods"},
			wantCmd:    "get",
			wantSubCmd: "pods",
		},
		{
			name:       "command with flags in middle",
			args:       []string{"get", "-n", "default", "pods"},
			wantCmd:    "get",
			wantSubCmd: "pods",
		},
		{
			name:       "rollout subcommand",
			args:       []string{"rollout", "restart", "deployment/nginx"},
			wantCmd:    "rollout",
			wantSubCmd: "restart",
		},
		{
			name:       "empty args",
			args:       []string{},
			wantCmd:    "",
			wantSubCmd: "",
		},
		{
			name:       "only flags",
			args:       []string{"-n", "default", "--context", "prod"},
			wantCmd:    "",
			wantSubCmd: "",
		},
		{
			name:       "long flags",
			args:       []string{"--namespace=default", "delete", "pod", "nginx"},
			wantCmd:    "delete",
			wantSubCmd: "pod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, subCmd := ExtractCommand(tt.args)
			if cmd != tt.wantCmd {
				t.Errorf("ExtractCommand() cmd = %q, want %q", cmd, tt.wantCmd)
			}
			if subCmd != tt.wantSubCmd {
				t.Errorf("ExtractCommand() subCmd = %q, want %q", subCmd, tt.wantSubCmd)
			}
		})
	}
}

func TestIsSafeCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		safe bool
	}{
		// Safe commands
		{"get pods", []string{"get", "pods"}, true},
		{"describe pod", []string{"describe", "pod", "nginx"}, true},
		{"logs", []string{"logs", "nginx"}, true},
		{"top nodes", []string{"top", "nodes"}, true},
		{"explain", []string{"explain", "pods"}, true},
		{"api-resources", []string{"api-resources"}, true},
		{"api-versions", []string{"api-versions"}, true},
		{"version", []string{"version"}, true},
		{"cluster-info", []string{"cluster-info"}, true},
		{"wait", []string{"wait", "--for=condition=ready", "pod/nginx"}, true},
		{"diff", []string{"diff", "-f", "deployment.yaml"}, true},
		// config/auth are conditional: read-only subcommands are safe.
		{"config get-contexts", []string{"config", "get-contexts"}, true},
		{"config view", []string{"config", "view"}, true},
		{"config current-context", []string{"config", "current-context"}, true},
		{"config use-context", []string{"config", "use-context", "prod"}, false},
		{"config set-context", []string{"config", "set-context", "--current"}, false},
		{"auth can-i", []string{"auth", "can-i", "get", "pods"}, true},
		{"auth whoami", []string{"auth", "whoami"}, true},
		{"auth reconcile", []string{"auth", "reconcile", "-f", "rbac.yaml"}, false},

		// Rollout safe subcommands
		{"rollout status", []string{"rollout", "status", "deployment/nginx"}, true},
		{"rollout history", []string{"rollout", "history", "deployment/nginx"}, true},

		// State-altering commands are not safe
		{"apply", []string{"apply", "-f", "deployment.yaml"}, false},
		{"create", []string{"create", "deployment", "nginx"}, false},
		{"delete", []string{"delete", "pod", "nginx"}, false},
		{"rollout restart", []string{"rollout", "restart", "deployment/nginx"}, false},

		// Edge cases
		{"empty", []string{}, true},
		{"flags only", []string{"-n", "default"}, true},
		{"get with flags", []string{"-n", "default", "get", "pods"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSafeCommand(tt.args)
			if got != tt.safe {
				t.Errorf("IsSafeCommand(%v) = %v, want %v", tt.args, got, tt.safe)
			}
		})
	}
}

func TestIsStateAltering(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		altering bool
	}{
		// State-altering commands
		{"apply", []string{"apply", "-f", "deployment.yaml"}, true},
		{"create", []string{"create", "deployment", "nginx"}, true},
		{"delete", []string{"delete", "pod", "nginx"}, true},
		{"patch", []string{"patch", "deployment", "nginx", "-p", `{"spec":{}}`}, true},
		{"replace", []string{"replace", "-f", "deployment.yaml"}, true},
		{"edit", []string{"edit", "deployment", "nginx"}, true},
		{"scale", []string{"scale", "deployment", "nginx", "--replicas=3"}, true},
		{"rollout restart", []string{"rollout", "restart", "deployment/nginx"}, true},
		{"rollout undo", []string{"rollout", "undo", "deployment/nginx"}, true},
		{"rollout pause", []string{"rollout", "pause", "deployment/nginx"}, true},
		{"rollout resume", []string{"rollout", "resume", "deployment/nginx"}, true},
		{"autoscale", []string{"autoscale", "deployment", "nginx", "--min=2"}, true},
		{"expose", []string{"expose", "deployment", "nginx", "--port=80"}, true},
		{"run", []string{"run", "nginx", "--image=nginx"}, true},
		{"set image", []string{"set", "image", "deployment/nginx", "nginx=nginx:latest"}, true},
		{"label", []string{"label", "pod", "nginx", "env=prod"}, true},
		{"annotate", []string{"annotate", "pod", "nginx", "description=test"}, true},
		{"taint", []string{"taint", "node", "node1", "key=value:NoSchedule"}, true},
		{"drain", []string{"drain", "node1"}, true},
		{"cordon", []string{"cordon", "node1"}, true},
		{"uncordon", []string{"uncordon", "node1"}, true},
		{"exec", []string{"exec", "nginx", "--", "ls"}, true},
		{"cp", []string{"cp", "nginx:/tmp/file", "./file"}, true},
		{"debug", []string{"debug", "nginx"}, true},
		{"attach", []string{"attach", "nginx"}, true},

		// config/auth mutating subcommands are state-altering
		{"config use-context", []string{"config", "use-context", "prod"}, true},
		{"config delete-context", []string{"config", "delete-context", "prod"}, true},
		{"config set-credentials", []string{"config", "set-credentials", "admin"}, true},
		{"config unset", []string{"config", "unset", "users.foo"}, true},
		{"auth reconcile", []string{"auth", "reconcile", "-f", "rbac.yaml"}, true},

		// config/auth read-only subcommands are not state-altering
		{"config view", []string{"config", "view"}, false},
		{"config get-contexts", []string{"config", "get-contexts"}, false},
		{"config current-context", []string{"config", "current-context"}, false},
		{"auth can-i", []string{"auth", "can-i", "get", "pods"}, false},
		{"auth whoami", []string{"auth", "whoami"}, false},

		// Safe commands are not state-altering
		{"get", []string{"get", "pods"}, false},
		{"describe", []string{"describe", "pod", "nginx"}, false},
		{"logs", []string{"logs", "nginx"}, false},
		{"rollout status", []string{"rollout", "status", "deployment/nginx"}, false},
		{"rollout history", []string{"rollout", "history", "deployment/nginx"}, false},

		// Edge cases
		{"empty", []string{}, false},
		{"delete with flags", []string{"-n", "default", "delete", "pod", "nginx"}, true},
		{"apply with context", []string{"--context=prod", "apply", "-f", "file.yaml"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsStateAltering(tt.args)
			if got != tt.altering {
				t.Errorf("IsStateAltering(%v) = %v, want %v", tt.args, got, tt.altering)
			}
		})
	}
}

func TestGetCommandDescription(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"get", "pods"}, "get pods"},
		{[]string{"rollout", "restart", "deployment"}, "rollout restart"},
		{[]string{"-n", "default", "delete", "pod"}, "delete pod"},
		{[]string{"apply"}, "apply"},
		{[]string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetCommandDescription(tt.args)
			if got != tt.want {
				t.Errorf("GetCommandDescription(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestPositionalArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"simple", []string{"get", "pods"}, []string{"get", "pods"}},
		{"short flag with value", []string{"-n", "default", "get", "pods"}, []string{"get", "pods"}},
		{"long flag with value", []string{"get", "--namespace", "x", "pods"}, []string{"get", "pods"}},
		{"equals flag", []string{"--namespace=x", "get", "pods"}, []string{"get", "pods"}},
		{"stops at --", []string{"exec", "nginx", "--", "get", "pods"}, []string{"exec", "nginx", "get", "pods"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PositionalArgs(tt.args)
			if !equalStrings(got, tt.want) {
				t.Errorf("PositionalArgs(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestExtractResourceCandidates(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"get secret", []string{"get", "secret"}, []string{"secret"}},
		{"get named secret", []string{"get", "secret", "mysecret"}, []string{"secret", "mysecret"}},
		{"create secret", []string{"create", "secret", "generic", "x"}, []string{"secret", "generic", "x"}},
		{"slash form", []string{"delete", "secret/mysecret"}, []string{"secret/mysecret"}},
		{"verb only", []string{"get"}, nil},
		{"filename value skipped", []string{"apply", "-f", "secret.yaml"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractResourceCandidates(tt.args)
			if !equalStrings(got, tt.want) {
				t.Errorf("ExtractResourceCandidates(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestExtractFilenames(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"short", []string{"apply", "-f", "a.yaml"}, []string{"a.yaml"}},
		{"long", []string{"apply", "--filename", "a.yaml"}, []string{"a.yaml"}},
		{"equals", []string{"apply", "--filename=a.yaml"}, []string{"a.yaml"}},
		{"multiple", []string{"apply", "-f", "a.yaml", "-f", "b.yaml"}, []string{"a.yaml", "b.yaml"}},
		{"none", []string{"get", "pods"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFilenames(tt.args)
			if !equalStrings(got, tt.want) {
				t.Errorf("ExtractFilenames(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// fakeChecker implements ProtectedResourceChecker for testing.
type fakeChecker struct{ match map[string]bool }

func (f fakeChecker) IsResourceProtected(candidate string) bool {
	return f.match[candidate] || f.match[config.NormalizeResource(candidate)]
}

func (f fakeChecker) HasProtectedResources() bool { return len(f.match) > 0 }

func TestMatchesProtectedResource(t *testing.T) {
	checker := fakeChecker{match: map[string]bool{"secret": true}}

	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"get secret", []string{"get", "secret"}, true},
		{"get secrets plural", []string{"get", "secrets"}, true},
		{"describe secret named", []string{"describe", "secret", "mysecret"}, true},
		{"create secret", []string{"create", "secret", "tls", "tls"}, true},
		{"delete pod", []string{"delete", "pod", "nginx"}, false},
		{"get pods", []string{"get", "pods"}, false},
		// S3: un-inspectable sources are blocked when resource protection is active.
		{"stdin source", []string{"apply", "-f", "-"}, true},
		{"url source", []string{"apply", "-f", "https://x/secret.yaml"}, true},
		{"kustomize source", []string{"apply", "-k", "./dir"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesProtectedResource(checker, tt.args)
			if got != tt.want {
				t.Errorf("MatchesProtectedResource(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}

	// When no protected resources are configured, un-inspectable sources pass.
	empty := fakeChecker{match: map[string]bool{}}
	if MatchesProtectedResource(empty, []string{"apply", "-f", "-"}) {
		t.Error("un-inspectable source should not match when no resources are protected")
	}
}

func TestMatchesProtectedResourceShortNames(t *testing.T) {
	// S4: protecting configmap must also block its short name "cm".
	checker := fakeChecker{match: map[string]bool{"configmap": true}}
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"get", "configmap"}, true},
		{[]string{"get", "cm"}, true},
		{[]string{"get", "cms"}, true},
		{[]string{"get", "ConfigMap"}, true},
		{[]string{"get", "secret"}, false},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			if got := MatchesProtectedResource(checker, c.args); got != c.want {
				t.Errorf("MatchesProtectedResource(%v) = %v, want %v", c.args, got, c.want)
			}
		})
	}
}

// TestMatchesProtectedResourceComma locks down G5: comma-separated resource
// lists (e.g. "secret,configmap") must match if any part is protected.
func TestMatchesProtectedResourceComma(t *testing.T) {
	checker := fakeChecker{match: map[string]bool{"secret": true}}
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"get", "secret,configmap"}, true},
		{[]string{"get", "configmap,secret"}, true},
		{[]string{"get", "pods,secret,services"}, true},
		{[]string{"get", "pod,configmap"}, false},
		{[]string{"get", "secret,"}, true}, // trailing comma ignored
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			if got := MatchesProtectedResource(checker, c.args); got != c.want {
				t.Errorf("MatchesProtectedResource(%v) = %v, want %v", c.args, got, c.want)
			}
		})
	}
}

// TestMatchesProtectedResourceAll locks down G7: "all" / "*" span every
// resource type and are blocked when any resource is protected.
func TestMatchesProtectedResourceAll(t *testing.T) {
	protected := fakeChecker{match: map[string]bool{"secret": true}}
	none := fakeChecker{match: map[string]bool{}}
	for _, args := range [][]string{{"get", "all"}, {"get", "ALL"}, {"get", "*"}, {"delete", "all"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if !MatchesProtectedResource(protected, args) {
				t.Errorf("MatchesProtectedResource(%v) = false, want true (all/* with protected resources)", args)
			}
		})
	}
	// With no protected resources, "all" must not match.
	if MatchesProtectedResource(none, []string{"get", "all"}) {
		t.Error(`MatchesProtectedResource(get all) = true with no protected resources`)
	}
}

// TestMatchesProtectedResourceAfterDoubleDash locks down H4: resource tokens
// placed after "--" are still positional to kubectl and must be matched.
func TestMatchesProtectedResourceAfterDoubleDash(t *testing.T) {
	checker := fakeChecker{match: map[string]bool{"secret": true}}
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"get", "--", "secret"}, true},
		{[]string{"delete", "--", "secret", "db"}, true},
		{[]string{"get", "pods", "--", "secret"}, true},
		{[]string{"get", "--", "configmap"}, false},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			if got := MatchesProtectedResource(checker, c.args); got != c.want {
				t.Errorf("MatchesProtectedResource(%v) = %v, want %v", c.args, got, c.want)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want ParsedArgs
	}{
		{
			name: "context kubeconfig filename kustomize",
			args: []string{"--context=prod", "--kubeconfig", "/k.yaml", "apply", "-f", "a.yaml", "-k", "dir"},
			want: ParsedArgs{
				Positional: []string{"apply"}, Context: "prod", Kubeconfig: "/k.yaml",
				Filenames: []string{"a.yaml"}, Kustomize: "dir", ExplicitContext: true,
			},
		},
		{
			name: "double dash: flags stop, positionals collected",
			args: []string{"get", "pod", "--", "--context=dev"},
			want: ParsedArgs{Positional: []string{"get", "pod", "--context=dev"}},
		},
		{
			name: "value taking flag skipped",
			args: []string{"-n", "default", "get", "pods"},
			want: ParsedArgs{Positional: []string{"get", "pods"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseArgs(tt.args)
			if !equalStrings(got.Positional, tt.want.Positional) {
				t.Errorf("Positional = %v, want %v", got.Positional, tt.want.Positional)
			}
			if got.Context != tt.want.Context {
				t.Errorf("Context = %q, want %q", got.Context, tt.want.Context)
			}
			if got.Kubeconfig != tt.want.Kubeconfig {
				t.Errorf("Kubeconfig = %q, want %q", got.Kubeconfig, tt.want.Kubeconfig)
			}
			if got.Kustomize != tt.want.Kustomize {
				t.Errorf("Kustomize = %q, want %q", got.Kustomize, tt.want.Kustomize)
			}
			if !equalStrings(got.Filenames, tt.want.Filenames) {
				t.Errorf("Filenames = %v, want %v", got.Filenames, tt.want.Filenames)
			}
			if got.ExplicitContext != tt.want.ExplicitContext {
				t.Errorf("ExplicitContext = %v, want %v", got.ExplicitContext, tt.want.ExplicitContext)
			}
		})
	}
}

// TestParseArgsShortCluster locks down G1: clustered short flags carrying a
// manifest source (-f/-k) must be recognized so the file/dir is scanned. Each
// case below failed before the cluster-aware parser was added.
func TestParseArgsShortCluster(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantFilenames   []string
		wantKustomize   string
		wantPositional  []string
	}{
		// -Rf dir: -R (boolean) then -f dir -> recursive apply of dir.
		{"-Rf dir", []string{"apply", "-Rf", "dir"}, []string{"dir"}, "", []string{"apply"}},
		// -fR is -f with attached value "R" (pflag: rest of token is the value).
		{"-fR attached", []string{"apply", "-fR"}, []string{"R"}, "", []string{"apply"}},
		// -nf x: -n takes value "f" (namespace), x is positional; no source.
		{"-nf consumes namespace", []string{"apply", "-nf", "x"}, nil, "", []string{"apply", "x"}},
		// -k bundled: -Rk dir.
		{"-Rk dir", []string{"apply", "-Rk", "dir"}, nil, "dir", []string{"apply"}},
		// standalone still works.
		{"-f dir", []string{"apply", "-f", "dir"}, []string{"dir"}, "", []string{"apply"}},
		{"-k dir", []string{"apply", "-k", "dir"}, nil, "dir", []string{"apply"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseArgs(tt.args)
			if !equalStrings(got.Filenames, tt.wantFilenames) {
				t.Errorf("Filenames = %v, want %v", got.Filenames, tt.wantFilenames)
			}
			if got.Kustomize != tt.wantKustomize {
				t.Errorf("Kustomize = %q, want %q", got.Kustomize, tt.wantKustomize)
			}
			if !equalStrings(got.Positional, tt.wantPositional) {
				t.Errorf("Positional = %v, want %v", got.Positional, tt.wantPositional)
			}
		})
	}
}

func TestMatchesProtectedResourceFile(t *testing.T) {
	checker := fakeChecker{match: map[string]bool{"secret": true}}

	secretManifest := []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n")
	deployManifest := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n")
	multiDoc := []byte("kind: ConfigMap\n---\nkind: Secret\n")

	files := map[string][]byte{
		"secret.yaml":  secretManifest,
		"deploy.yaml":  deployManifest,
		"multi.yaml":   multiDoc,
	}

	for name, content := range files {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
	}
		files[name] = []byte(path) // reuse map to hold the real path
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"secret file", string(files["secret.yaml"]), true},
		{"deploy file", string(files["deploy.yaml"]), false},
		{"multi doc with secret", string(files["multi.yaml"]), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fileContainsProtectedKind(c.path, checker)
			if got != c.want {
				t.Errorf("fileContainsProtectedKind(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}

	// End-to-end via MatchesProtectedResource with -f
	if !MatchesProtectedResource(checker, []string{"apply", "-f", string(files["secret.yaml"])}) {
		t.Error("apply -f secret.yaml should match")
	}
	if MatchesProtectedResource(checker, []string{"apply", "-f", string(files["deploy.yaml"])}) {
		t.Error("apply -f deploy.yaml should not match")
	}

	// G1 (directory aspect): -f dir and -Rf dir must be scanned recursively.
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	// A secret nested in a subdirectory.
	if err := os.WriteFile(filepath.Join(sub, "secret.yaml"), secretManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	// A clean file at the top level.
	if err := os.WriteFile(filepath.Join(dir, "deploy.yaml"), deployManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if !MatchesProtectedResource(checker, []string{"apply", "-f", dir}) {
		t.Error("apply -f <dir with nested secret> should match")
	}
	if !MatchesProtectedResource(checker, []string{"apply", "-Rf", dir}) {
		t.Error("apply -Rf <dir with nested secret> should match")
	}
	// A clean directory must not match.
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "deploy.yaml"), deployManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if MatchesProtectedResource(checker, []string{"apply", "-f", clean}) {
		t.Error("apply -f <clean dir> should not match")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
