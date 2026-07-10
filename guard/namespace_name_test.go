package guard

import (
	"reflect"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// --- extraction: which namespace NAMES does a command address? ---

func TestNamespaceTargetsFrom(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantKind  bool
		wantNames []string
		wantWide  bool
	}{
		// The forms kubectl documents: `delete TYPE [(NAME | -l label | --all)]`.
		{"bare kind, one name", []string{"delete", "namespace", "kube-system"}, true, []string{"kube-system"}, false},
		{"short name kind", []string{"delete", "ns", "kube-system"}, true, []string{"kube-system"}, false},
		{"plural kind", []string{"delete", "namespaces", "kube-system"}, true, []string{"kube-system"}, false},
		{"several names", []string{"delete", "namespace", "a", "b", "c"}, true, []string{"a", "b", "c"}, false},
		{"type/name token", []string{"delete", "ns/kube-system"}, true, []string{"kube-system"}, false},
		{"long type/name token", []string{"delete", "namespace/kube-system"}, true, []string{"kube-system"}, false},
		{"several type/name tokens", []string{"delete", "ns/a", "ns/b"}, true, []string{"a", "b"}, false},
		{"uppercase verb and kind", []string{"DELETE", "NS", "kube-system"}, true, []string{"kube-system"}, false},

		// kubectl's own example is `kubectl delete pod,service baz foo`: a comma
		// TYPE list applies each NAME to EVERY type. So `ns,pod foo` deletes the
		// namespace named foo.
		{"comma type list including ns", []string{"delete", "ns,pod", "foo"}, true, []string{"foo"}, false},
		{"comma type list, ns second", []string{"delete", "pod,namespace", "foo"}, true, []string{"foo"}, false},

		// A type/name token names its own kind wherever it appears, so a
		// namespace target hiding behind another kind's leading token is caught.
		{"type/name mixed with other kinds", []string{"delete", "pod/x", "ns/kube-system"}, true, []string{"kube-system"}, false},

		// Wide scope: kubectl accepts NAME *or* -l *or* --all. With no names, the
		// affected namespaces are not knowable from argv.
		{"kind with --all", []string{"delete", "namespace", "--all"}, true, nil, true},
		{"kind with selector", []string{"delete", "ns", "-l", "env=prod"}, true, nil, true},
		{"kind with long selector", []string{"delete", "ns", "--selector", "env=prod"}, true, nil, true},
		{"kind with inline selector", []string{"delete", "ns", "--selector=env=prod"}, true, nil, true},
		{"kind with --all=false is not wide", []string{"delete", "namespace", "--all=false"}, true, nil, false},
		// --field-selector also stands in for a NAME. It was a real bypass:
		// `delete namespace --field-selector metadata.name=kube-system` deletes
		// kube-system but names it nowhere the guard could check.
		{"kind with field-selector", []string{"delete", "namespace", "--field-selector", "metadata.name=kube-system"}, true, nil, true},
		{"kind with inline field-selector", []string{"delete", "ns", "--field-selector=metadata.name=kube-system"}, true, nil, true},

		// Tokens after "--" are STILL resource targets for a resource verb; "--"
		// only ends flag parsing. This was a real bypass (`delete namespace --
		// kube-system` deletes kube-system, verified against kubectl v1.33).
		{"name after separator", []string{"delete", "namespace", "--", "kube-system"}, true, []string{"kube-system"}, false},
		{"kind and name after separator", []string{"delete", "--", "namespace", "kube-system"}, true, []string{"kube-system"}, false},
		{"short kind and name after separator", []string{"delete", "--", "ns", "kube-system"}, true, []string{"kube-system"}, false},

		// Not namespace-kind commands.
		{"pod delete", []string{"delete", "pod", "nginx"}, false, nil, false},
		{"pod type/name", []string{"delete", "pod/nginx"}, false, nil, false},
		{"a pod named ns", []string{"delete", "pod", "ns"}, false, nil, false},
		{"configmap kind", []string{"delete", "cm", "kube-system"}, false, nil, false},
		{"no positionals after verb", []string{"delete", "-f", "x.yaml"}, false, nil, false},
		{"bare kind, no names, no wide flags", []string{"delete", "namespace"}, true, nil, false},
		{"no verb at all", []string{"--kubeconfig", "/x"}, false, nil, false},

		// Tokens after "--" are a foreign command's payload ONLY for the
		// exec-family verbs, and must not be read as kubectl targets there.
		{"ns token in exec payload", []string{"exec", "pod", "--", "kubectl", "delete", "ns/kube-system"}, false, nil, false},
		{"ns token in run payload", []string{"run", "x", "--image=y", "--", "kubectl", "delete", "namespace", "kube-system"}, false, nil, false},
		{"ns token in debug payload", []string{"debug", "pod", "--", "kubectl", "delete", "ns/kube-system"}, false, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := namespaceTargetsFrom(ParseArgs(tt.args))
			if got.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if !reflect.DeepEqual(got.Names, tt.wantNames) {
				t.Errorf("Names = %#v, want %#v", got.Names, tt.wantNames)
			}
			if got.Wide != tt.wantWide {
				t.Errorf("Wide = %v, want %v", got.Wide, tt.wantWide)
			}
		})
	}
}

// --- ParseArgs: the two flags this ticket had to start capturing ---

func TestParseArgsAllFlag(t *testing.T) {
	if p := ParseArgs([]string{"delete", "pods", "--all"}); !p.All {
		t.Error("--all not captured")
	}
	if p := ParseArgs([]string{"delete", "pods", "--all=true"}); !p.All {
		t.Error("--all=true not captured")
	}
	if p := ParseArgs([]string{"delete", "pods", "--all=false"}); p.All {
		t.Error("--all=false must not set All")
	}
	// --all is boolean: it must never consume the following token, or a verb
	// after it would be hidden from classification.
	p := ParseArgs([]string{"--all", "delete", "pod", "x"})
	if cmd, _ := ExtractCommand([]string{"--all", "delete", "pod", "x"}); cmd != "delete" {
		t.Errorf("--all swallowed the verb: ExtractCommand = %q", cmd)
	}
	if !p.All {
		t.Error("--all not captured in leading position")
	}
	// --all-namespaces must not be mistaken for --all.
	if p := ParseArgs([]string{"get", "pods", "--all-namespaces"}); p.All {
		t.Error("--all-namespaces must not set All")
	}
}

func TestParseArgsSelector(t *testing.T) {
	cases := [][]string{
		{"delete", "pods", "-l", "env=prod"},
		{"delete", "pods", "-lenv=prod"},
		{"delete", "pods", "--selector", "env=prod"},
		{"delete", "pods", "--selector=env=prod"},
		{"delete", "pods", "-Rl", "env=prod"}, // clustered with a boolean
	}
	for _, args := range cases {
		if p := ParseArgs(args); !p.HasSelector {
			t.Errorf("selector not captured for %v", args)
		}
	}
	if p := ParseArgs([]string{"delete", "pods", "nginx"}); p.HasSelector {
		t.Error("HasSelector set with no selector flag")
	}
	// -l takes a value; it must still consume it so the value cannot land in
	// verb position and hide the real verb.
	if cmd, _ := ExtractCommand([]string{"-l", "delete", "delete", "pod", "x"}); cmd != "delete" {
		t.Errorf("ExtractCommand = %q; -l must consume its value", cmd)
	}
}

// --- the decision: does the guard gate a protected namespace named as an object? ---

// TestDeleteProtectedNamespaceByName is the ticket's headline case. The context
// is UNPROTECTED and there is no -n flag, so before this change the target
// namespace resolved to "default" and the command sailed through — despite
// kube-system being protected by name.
func TestDeleteProtectedNamespaceByName(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	for _, args := range [][]string{
		{"delete", "namespace", "kube-system"},
		{"delete", "ns", "kube-system"},
		{"delete", "namespaces", "kube-system"},
		{"delete", "ns/kube-system"},
		{"delete", "namespace/kube-system"},
		{"edit", "namespace", "kube-system"},
		{"patch", "ns", "kube-system", "-p", "{}"},
		{"label", "ns", "kube-system", "a=b"},
		{"delete", "pod/x", "ns/kube-system"},
		{"delete", "ns,pod", "kube-system"},
	} {
		res, _, _, _ := checkWith(args, staticContext("dev-unprotected"))
		if res != RequireConfirmation {
			t.Errorf("checkWith(%v) = %v, want RequireConfirmation", args, res)
		}
	}
}

// TestDeleteNamespaceGlobByName: protected namespace patterns are globs, and
// they apply to the namespace-name target too.
func TestDeleteNamespaceGlobByName(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"prod-*"}})
	defer cleanup()

	if res, _, _, _ := checkWith([]string{"delete", "ns/prod-app"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("delete ns/prod-app = %v, want RequireConfirmation", res)
	}
	if res, _, _, _ := checkWith([]string{"delete", "ns/staging-app"}, staticContext("dev")); res != Allow {
		t.Errorf("delete ns/staging-app = %v, want Allow", res)
	}
}

// TestUnprotectedNamespaceByNameNotGated: the gate must be a scalpel, not a
// blanket. Deleting an UNprotected namespace on an unprotected context passes.
func TestUnprotectedNamespaceByNameNotGated(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	for _, args := range [][]string{
		{"delete", "namespace", "scratch"},
		{"delete", "ns/scratch"},
		{"delete", "pod", "nginx"},
		{"delete", "pod", "ns"}, // a POD named "ns" is not the namespace kind
		{"create", "namespace", "scratch"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Allow {
			t.Errorf("checkWith(%v) = %v, want Allow", args, res)
		}
	}
}

// TestReadOfProtectedNamespaceByNameNotGated: the ticket scopes this to
// state-altering verbs. Reads of a protected namespace object still pass —
// blocking reads is what protected_resources is for.
func TestReadOfProtectedNamespaceByNameNotGated(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	for _, args := range [][]string{
		{"get", "namespace", "kube-system"},
		{"describe", "ns", "kube-system"},
		{"get", "ns/kube-system", "-o", "yaml"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Allow {
			t.Errorf("checkWith(%v) = %v, want Allow (reads are not gated by namespace protection)", args, res)
		}
	}
}

// TestWideNamespaceKindFailsClosed: `delete namespace --all` and
// `delete ns -l env=prod` name no namespace the guard can check. kubectl's usage
// is `TYPE (NAME | -l label | --all)`, so the targets are genuinely unknowable
// from argv — the guard must not prove a negative and let them through.
func TestWideNamespaceKindFailsClosed(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	for _, args := range [][]string{
		{"delete", "namespace", "--all"},
		{"delete", "ns", "-l", "env=prod"},
		{"delete", "ns", "--selector=env=prod"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != RequireConfirmation {
			t.Errorf("checkWith(%v) = %v, want RequireConfirmation (targets unknowable)", args, res)
		}
	}

	// ...but only when namespace protection is actually configured.
	cleanup2 := withTempHome(t, &config.Config{})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"delete", "namespace", "--all"}, staticContext("dev")); res != Allow {
		t.Errorf("delete namespace --all with no protection = %v, want Allow", res)
	}
}

// TestNamespaceNameComposesWithFlagAndContext: the ticket requires the new match
// to COMPOSE with the existing -n / -A / context resolution (any match gates),
// not replace it.
func TestNamespaceNameComposesWithFlagAndContext(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	// -n still gates, on a non-namespace kind.
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x", "-n", "kube-system"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("-n gating regressed: %v", res)
	}
	// -A still gates.
	if res, _, _, _ := checkWith([]string{"delete", "pods", "-A"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("-A gating regressed: %v", res)
	}
	// A namespace-name target gates even when -n points somewhere unprotected.
	if res, _, _, _ := checkWith([]string{"delete", "namespace", "kube-system", "-n", "default"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("namespace-name target must gate regardless of -n: %v", res)
	}
	// Context protection still gates independently.
	cleanup2 := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"delete", "namespace", "scratch"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("context gating regressed: %v", res)
	}
}

// TestNamespaceNameBlockMode: namespace_mode=block hard-refuses, and the
// namespace-name route is no exception.
func TestNamespaceNameBlockMode(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedNamespaces: []string{"kube-system"},
		NamespaceMode:       config.NamespaceModeBlock,
	})
	defer cleanup()

	if res, _, _, _ := checkWith([]string{"delete", "namespace", "kube-system"}, staticContext("dev")); res != Blocked {
		t.Errorf("delete namespace kube-system under block mode = %v, want Blocked", res)
	}
}

// TestNamespaceNamePayloadAfterSeparator: an "ns/kube-system" token inside an
// exec payload is a foreign command's argument, not a kubectl target, and must
// not be matched. (`exec` itself gates on protected contexts; here the context
// is unprotected, so any gating would have to come from the payload token.)
func TestNamespaceNamePayloadAfterSeparator(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	// exec-family verbs: "--" is a foreign-command boundary; must NOT gate.
	for _, args := range [][]string{
		{"exec", "mypod", "--", "sh", "-c", "rm -rf ns/kube-system"},
		{"exec", "mypod", "--", "kubectl", "delete", "namespace", "kube-system"},
		{"run", "x", "--image=y", "--", "kubectl", "delete", "ns/kube-system"},
		{"debug", "pod", "--", "kubectl", "delete", "ns/kube-system"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Allow {
			t.Errorf("payload token after -- must not be a namespace target: %v -> %v", args, res)
		}
	}
}

// TestDeleteNamespaceAfterSeparatorGated is the regression for a confirmed
// bypass: for a RESOURCE verb, "--" only ends flag parsing, so
// `kubectl delete -- namespace kube-system` really deletes kube-system (verified
// against kubectl v1.33). It must gate, exactly like the form without "--".
func TestDeleteNamespaceAfterSeparatorGated(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	for _, args := range [][]string{
		{"delete", "namespace", "--", "kube-system"},
		{"delete", "--", "namespace", "kube-system"},
		{"delete", "--", "ns", "kube-system"},
		{"edit", "--", "namespace", "kube-system"},
		{"delete", "-n", "default", "--", "namespace", "kube-system"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev-unprotected")); res != RequireConfirmation {
			t.Errorf("checkWith(%v) = %v, want RequireConfirmation (post-'--' targets are real)", args, res)
		}
	}
}

// TestFieldSelectorNamespaceFailsClosed is the regression for a confirmed
// bypass: `delete namespace --field-selector metadata.name=kube-system` names no
// namespace positionally, so like -l/--all the affected namespaces are
// unknowable from argv. It must fail closed when namespace protection is set.
func TestFieldSelectorNamespaceFailsClosed(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()

	for _, args := range [][]string{
		{"delete", "namespace", "--field-selector", "metadata.name=kube-system"},
		{"delete", "ns", "--field-selector=metadata.name=kube-system"},
		{"delete", "namespace", "--field-selector", "status.phase=Active"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != RequireConfirmation {
			t.Errorf("checkWith(%v) = %v, want RequireConfirmation (field-selector targets unknowable)", args, res)
		}
	}

	// ...but not when no namespace protection is configured.
	cleanup2 := withTempHome(t, &config.Config{})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"delete", "namespace", "--field-selector", "metadata.name=x"}, staticContext("dev")); res != Allow {
		t.Errorf("field-selector delete with no protection = %v, want Allow", res)
	}

	// A field-selector on a NON-namespace command must not be dragged into the
	// namespace path.
	cleanup3 := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup3()
	if res, _, _, _ := checkWith([]string{"delete", "pod", "--field-selector", "status.phase=Failed"}, staticContext("dev")); res != Allow {
		t.Errorf("field-selector on pods must not gate via the namespace path: %v", res)
	}
}

// TestProtectedNamespaceNameTargetForMessaging pins the exported helper that
// user-facing messages use, so `delete namespace kube-system` reports
// "kube-system" and not the meaningless "default" it would otherwise resolve.
func TestProtectedNamespaceNameTargetForMessaging(t *testing.T) {
	cfg := &config.Config{ProtectedNamespaces: []string{"kube-system", "prod-*"}}

	if got, ok := ProtectedNamespaceNameTarget(cfg, []string{"delete", "namespace", "kube-system"}); !ok || got != "kube-system" {
		t.Errorf("got (%q, %v), want (\"kube-system\", true)", got, ok)
	}
	if got, ok := ProtectedNamespaceNameTarget(cfg, []string{"delete", "ns/prod-app"}); !ok || got != "prod-app" {
		t.Errorf("got (%q, %v), want (\"prod-app\", true)", got, ok)
	}
	if got, ok := ProtectedNamespaceNameTarget(cfg, []string{"delete", "namespace", "--all"}); !ok || got != "all namespaces" {
		t.Errorf("got (%q, %v), want (\"all namespaces\", true)", got, ok)
	}
	if _, ok := ProtectedNamespaceNameTarget(cfg, []string{"delete", "pod", "nginx"}); ok {
		t.Error("a pod delete must not report a namespace-name target")
	}
	if _, ok := ProtectedNamespaceNameTarget(cfg, []string{"delete", "namespace", "scratch"}); ok {
		t.Error("an unprotected namespace name must not report a target")
	}
	if _, ok := ProtectedNamespaceNameTarget(nil, []string{"delete", "namespace", "kube-system"}); ok {
		t.Error("nil config must not report a target")
	}
}

// TestNamespaceNameTargetsExported covers the small exported surface.
func TestNamespaceNameTargetsExported(t *testing.T) {
	if got := NamespaceNameTargets([]string{"delete", "ns", "a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("NamespaceNameTargets = %#v", got)
	}
	if got := NamespaceNameTargets([]string{"delete", "pod", "a"}); got != nil {
		t.Errorf("NamespaceNameTargets on a pod = %#v, want nil", got)
	}
	if !NamespaceKindIsWide([]string{"delete", "ns", "--all"}) {
		t.Error("NamespaceKindIsWide(delete ns --all) = false")
	}
	if NamespaceKindIsWide([]string{"delete", "ns", "kube-system"}) {
		t.Error("NamespaceKindIsWide with an explicit name = true")
	}
}
