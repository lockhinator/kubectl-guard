package guard

import (
	"strings"
	"testing"
)

// TestRedactCommand is the table the #89 acceptance criteria call for: every
// secret-bearing flag, in both "=" and space forms, with the value replaced and
// the flag name kept.
func TestRedactCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		// --from-literal keeps the key, redacts the value.
		{
			"from-literal inline",
			[]string{"create", "secret", "generic", "db", "--from-literal=password=hunter2"},
			"create secret generic db --from-literal=password=***",
		},
		{
			"from-literal space",
			[]string{"create", "secret", "generic", "db", "--from-literal", "password=hunter2"},
			"create secret generic db --from-literal password=***",
		},
		{
			"from-literal no equals in value",
			[]string{"create", "secret", "generic", "db", "--from-literal=bogus"},
			"create secret generic db --from-literal=***",
		},
		{
			"multiple from-literal",
			[]string{"create", "secret", "generic", "db", "--from-literal=user=admin", "--from-literal=password=hunter2"},
			"create secret generic db --from-literal=user=*** --from-literal=password=***",
		},

		// --token, both forms.
		{"token inline", []string{"get", "pods", "--token=eyJhbGciOi"}, "get pods --token=***"},
		{"token space", []string{"get", "pods", "--token", "eyJhbGciOi"}, "get pods --token ***"},

		// docker-registry secrets.
		{
			"docker-password inline",
			[]string{"create", "secret", "docker-registry", "regcred", "--docker-password=s3cr3t"},
			"create secret docker-registry regcred --docker-password=***",
		},
		{
			"docker-password space",
			[]string{"create", "secret", "docker-registry", "regcred", "--docker-password", "s3cr3t"},
			"create secret docker-registry regcred --docker-password ***",
		},
		{
			"docker-email is PII",
			[]string{"create", "secret", "docker-registry", "r", "--docker-email=a@b.com"},
			"create secret docker-registry r --docker-email=***",
		},

		// Key material / credentials.
		{"password", []string{"get", "pods", "--password", "pw"}, "get pods --password ***"},
		{"client-key", []string{"get", "pods", "--client-key=/k.pem"}, "get pods --client-key=***"},
		{"client-certificate", []string{"get", "pods", "--client-certificate", "/c.pem"}, "get pods --client-certificate ***"},
		{"certificate-authority", []string{"get", "pods", "--certificate-authority=/ca.pem"}, "get pods --certificate-authority=***"},
		{"tls-private-key", []string{"get", "pods", "--tls-private-key=/tls.key"}, "get pods --tls-private-key=***"},

		// Environment variables are a primary carrier of credentials. --env is
		// used by `run` and `set env`; the key survives, the value does not.
		{"run --env inline", []string{"run", "x", "--image=nginx", "--env=DB_PASSWORD=hunter2"}, "run x --image=nginx --env=DB_PASSWORD=***"},
		{"run --env space", []string{"run", "x", "--env", "API_KEY=hunter2"}, "run x --env API_KEY=***"},
		{"set env --env inline", []string{"set", "env", "deployment/web", "--env=DB_PASSWORD=hunter2"}, "set env deployment/web --env=DB_PASSWORD=***"},
		{"--env from stdin keeps the dash", []string{"set", "env", "deployment/web", "--env", "-"}, "set env deployment/web --env -"},

		// `set env NAME KEY=VALUE` carries the secret in a POSITIONAL, with no
		// flag in front of it. This is kubectl's documented form.
		{"set env positional", []string{"set", "env", "deployment/web", "DB_PASSWORD=hunter2"}, "set env deployment/web DB_PASSWORD=***"},
		{"set env multiple positionals", []string{"set", "env", "deploy/w", "A=1", "B=2"}, "set env deploy/w A=*** B=***"},
		{"set env removal syntax untouched", []string{"set", "env", "deploy/w", "DB_PASSWORD-"}, "set env deploy/w DB_PASSWORD-"},
		{"set env uppercase subcommand", []string{"set", "ENV", "deploy/w", "DB_PASSWORD=hunter2"}, "set ENV deploy/w DB_PASSWORD=***"},

		// `-e` is --env's shorthand on `set env`. pflag accepts the attached
		// forms, so a long-flag-only redactor leaks them.
		{"set env -e space", []string{"set", "env", "deploy/x", "-e", "PASSWORD=hunter2"}, "set env deploy/x -e PASSWORD=***"},
		{"set env -e attached equals", []string{"set", "env", "deploy/x", "-e=PASSWORD=hunter2"}, "set env deploy/x -e=PASSWORD=***"},
		{"set env -e attached", []string{"set", "env", "deploy/x", "-ePASSWORD=hunter2"}, "set env deploy/x -ePASSWORD=***"},

		// --patch/--overrides embed secret material in a JSON blob; the guard
		// cannot prove the blob is safe, so the whole value is redacted.
		{"patch -p space", []string{"patch", "secret", "db", "-p", `{"stringData":{"password":"hunter2"}}`}, "patch secret db -p ***"},
		{"patch -p attached", []string{"patch", "secret", "db", `-p{"stringData":{"password":"hunter2"}}`}, "patch secret db -p***"},
		{"patch --patch inline", []string{"patch", "secret", "db", `--patch={"stringData":{"password":"hunter2"}}`}, "patch secret db --patch=***"},
		{"run --overrides", []string{"run", "x", "--image=n", `--overrides={"env":"hunter2"}`}, "run x --image=n --overrides=***"},
		{"exec-arg", []string{"config", "set-credentials", "u", "--exec-arg=--token=hunter2"}, "config set-credentials u --exec-arg=***"},

		// -p is --patch on `patch` but the BOOLEAN --previous on `logs`. A global
		// alias would swallow "nginx" and corrupt the record.
		{"logs -p is boolean previous", []string{"logs", "-p", "nginx"}, "logs -p nginx"},
		{"logs -p with container", []string{"logs", "-p", "-c", "app", "nginx"}, "logs -p -c app nginx"},

		// -e is not a valid shorthand on `run`, so it must not be treated as --env.
		{"run -e not an alias", []string{"run", "x", "-e", "something"}, "run x -e something"},

		// -f/-k are value-taking manifest sources. A short-cluster walk must stop
		// at them, or it binds the following token to the alias behind them and
		// redacts the target resource out of the audit record.
		{"set env -fe", []string{"set", "env", "-fe", "deploy/web", "FOO=bar"}, "set env -fe deploy/web FOO=***"},
		{"set env -Rfe", []string{"set", "env", "-Rfe", "deploy/web", "FOO=bar"}, "set env -Rfe deploy/web FOO=***"},
		{"set env -ke", []string{"set", "env", "-ke", "somedir", "FOO=bar"}, "set env -ke somedir FOO=***"},
		{"patch -fp", []string{"patch", "-fp", "pods", "foo"}, "patch -fp pods foo"},
		// -c swallows the 'e'; -n and -R do not.
		{"set env -ce", []string{"set", "env", "-ce", "app", "FOO=bar"}, "set env -ce app FOO=***"},
		{"set env -Re", []string{"set", "env", "-Re", "FOO=bar"}, "set env -Re FOO=***"},

		// `kubectl config set PROPERTY_NAME PROPERTY_VALUE` writes credential
		// material as a bare positional. kubectl's own help documents
		// `config set users.cluster-admin.client-key-data cert_data_here`.
		{"config set token", []string{"config", "set", "users.admin.token", "hunter2"}, "config set users.admin.token ***"},
		{"config set password", []string{"config", "set", "users.admin.password", "hunter2"}, "config set users.admin.password ***"},
		{"config set client-key-data", []string{"config", "set", "users.cluster-admin.client-key-data", "hunter2"}, "config set users.cluster-admin.client-key-data ***"},
		{"config set client-secret", []string{"config", "set", "users.x.auth-provider.config.client-secret", "hunter2"}, "config set users.x.auth-provider.config.client-secret ***"},
		{"config set with kubeconfig flag between", []string{"config", "set", "--kubeconfig", "/p", "users.admin.token", "hunter2"}, "config set --kubeconfig /p users.admin.token ***"},
		// A flag VALUE that happens to contain a secret-property fragment must not
		// be mistaken for the property name. Scanning raw tokens for the fragment
		// blanked the property and let the real value through.
		{"kubeconfig path contains 'secrets'", []string{"config", "set", "--kubeconfig", "/vault/secrets/kc", "users.x.token", "hunter2"}, "config set --kubeconfig /vault/secrets/kc users.x.token ***"},
		{"kubeconfig path contains 'token'", []string{"config", "set", "--kubeconfig", "/home/token-dir/kc", "users.x.token", "hunter2"}, "config set --kubeconfig /home/token-dir/kc users.x.token ***"},
		{"property with trailing set-raw-bytes", []string{"config", "set", "users.x.client-key-data", "hunter2", "--set-raw-bytes", "true"}, "config set users.x.client-key-data *** --set-raw-bytes true"},
		{"uppercase property", []string{"config", "set", "users.X.TOKEN", "hunter2"}, "config set users.X.TOKEN ***"},
		{"property with no value", []string{"config", "set", "users.x.token"}, "config set users.x.token"},
		// kubectl rejects the single-token form, but the attempt must not be
		// audited in cleartext.
		{"config set PROPERTY=VALUE", []string{"config", "set", "users.x.token=hunter2"}, "config set users.x.token=***"},
		{"config set non-secret PROPERTY=VALUE", []string{"config", "set", "current-context=prod"}, "config set current-context=prod"},
		// A value that contains a fragment must not arm anything for a later token.
		{"server url containing 'token'", []string{"config", "set", "clusters.x.server", "https://token.example.com"}, "config set clusters.x.server https://token.example.com"},
		// Non-credential properties stay legible.
		{"config set current-context", []string{"config", "set", "current-context", "prod"}, "config set current-context prod"},
		{"config set server", []string{"config", "set", "clusters.x.server", "https://api.example.com"}, "config set clusters.x.server https://api.example.com"},
		{"config set CA data is public", []string{"config", "set", "clusters.x.certificate-authority-data", "abc123"}, "config set clusters.x.certificate-authority-data abc123"},
		// `config view` is not `config set`; nothing is armed.
		{"config view untouched", []string{"config", "view"}, "config view"},

		// kubeconfig credential material.
		{"exec-env", []string{"config", "set-credentials", "u", "--exec-env=TOKEN=hunter2"}, "config set-credentials u --exec-env=TOKEN=***"},
		{"auth-provider-arg", []string{"config", "set-credentials", "u", "--auth-provider-arg=client-secret=hunter2"}, "config set-credentials u --auth-provider-arg=client-secret=***"},

		// Positional KEY=VALUE redaction is scoped to `set env` only: other
		// verbs' key=value positionals are not secrets and must stay legible.
		{"set image untouched", []string{"set", "image", "deploy/x", "nginx=nginx:latest"}, "set image deploy/x nginx=nginx:latest"},
		{"annotate untouched", []string{"annotate", "pod", "nginx", "owner=team-a"}, "annotate pod nginx owner=team-a"},

		// Non-secret commands are untouched.
		{"plain get", []string{"get", "pods"}, "get pods"},
		{"delete with flags", []string{"--context=prod", "delete", "pod", "nginx", "-n", "default"}, "--context=prod delete pod nginx -n default"},
		{"apply", []string{"apply", "-f", "deploy.yaml"}, "apply -f deploy.yaml"},
		{"docker-username not redacted", []string{"create", "secret", "docker-registry", "r", "--docker-username=me"}, "create secret docker-registry r --docker-username=me"},
		{"a resource named token", []string{"get", "pod", "token"}, "get pod token"},
		{"key=value positional untouched", []string{"label", "pod", "nginx", "env=prod"}, "label pod nginx env=prod"},
		{"empty", []string{}, ""},

		// Secrets in an exec payload after "--" are still redacted: the audit log
		// must never carry them, even though they are positional to kubectl.
		{
			"payload after separator",
			[]string{"exec", "pod", "--", "app", "--token", "abc"},
			"exec pod -- app --token ***",
		},

		// A dangling secret flag with no value must not panic or invent one.
		{"trailing token flag", []string{"get", "pods", "--token"}, "get pods --token"},
		{"trailing from-literal", []string{"create", "secret", "generic", "x", "--from-literal"}, "create secret generic x --from-literal"},

		// pflag treats the next token as the value even if it looks like a flag,
		// so the guard must redact it rather than print it.
		{"token swallows next flag", []string{"get", "pods", "--token", "--json"}, "get pods --token ***"},

		// Empty inline value: still redacted, so no length/emptiness is leaked.
		{"empty inline token", []string{"get", "pods", "--token="}, "get pods --token=***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactCommand(tt.args); got != tt.want {
				t.Errorf("RedactCommand(%v)\n got = %q\nwant = %q", tt.args, got, tt.want)
			}
		})
	}
}

// TestRedactCommandLeaksNoSecretValue is the property the ticket really wants:
// for every secret-bearing form, the cleartext value must not appear anywhere
// in the output.
func TestRedactCommandLeaksNoSecretValue(t *testing.T) {
	const secret = "hunter2-s3cr3t-value"
	forms := [][]string{
		{"create", "secret", "generic", "db", "--from-literal=password=" + secret},
		{"create", "secret", "generic", "db", "--from-literal", "password=" + secret},
		{"get", "pods", "--token=" + secret},
		{"get", "pods", "--token", secret},
		{"get", "pods", "--password", secret},
		{"get", "pods", "--password=" + secret},
		{"create", "secret", "docker-registry", "r", "--docker-password", secret},
		{"create", "secret", "docker-registry", "r", "--docker-password=" + secret},
		{"get", "pods", "--client-key", secret},
		{"get", "pods", "--client-certificate=" + secret},
		{"get", "pods", "--certificate-authority", secret},
		{"get", "pods", "--tls-private-key=" + secret},
		{"exec", "pod", "--", "app", "--token", secret},
		{"run", "x", "--image=nginx", "--env=DB_PASSWORD=" + secret},
		{"run", "x", "--env", "DB_PASSWORD=" + secret},
		{"set", "env", "deployment/web", "--env=DB_PASSWORD=" + secret},
		{"set", "env", "deployment/web", "DB_PASSWORD=" + secret},
		{"config", "set-credentials", "u", "--exec-env=TOKEN=" + secret},
		{"config", "set-credentials", "u", "--auth-provider-arg=client-secret=" + secret},
		{"config", "set-credentials", "u", "--exec-arg=--token=" + secret},
		{"set", "env", "deploy/x", "-e", "PASSWORD=" + secret},
		{"set", "env", "deploy/x", "-e=PASSWORD=" + secret},
		{"set", "env", "deploy/x", "-ePASSWORD=" + secret},
		{"patch", "secret", "db", "-p", `{"stringData":{"password":"` + secret + `"}}`},
		{"patch", "secret", "db", "--patch", `{"stringData":{"password":"` + secret + `"}}`},
		{"patch", "secret", "db", `--patch={"stringData":{"password":"` + secret + `"}}`},
		{"run", "x", "--image=n", `--overrides={"env":"` + secret + `"}`},
		{"config", "set", "users.admin.token", secret},
		{"config", "set", "users.admin.password", secret},
		{"config", "set", "users.cluster-admin.client-key-data", secret},
		{"config", "set", "--kubeconfig", "/p", "users.admin.token", secret},
		{"config", "set", "--kubeconfig", "/vault/secrets/kc", "users.x.token", secret},
		{"config", "set", "--kubeconfig", "/home/token-dir/kc", "users.x.password", secret},
		{"config", "set", "users.x.token=" + secret},
		{"config", "set", "users.x.client-key-data", secret, "--set-raw-bytes", "true"},
	}
	for _, args := range forms {
		got := RedactCommand(args)
		if strings.Contains(got, secret) {
			t.Errorf("RedactCommand(%v) leaked the secret value: %q", args, got)
		}
		if !strings.Contains(got, redactedValue) {
			t.Errorf("RedactCommand(%v) = %q, expected a %q marker", args, got, redactedValue)
		}
	}
}

// TestSecretFlagValuesNeverBecomePositionals is the structural fix behind three
// leaks: a secret flag whose value ParseArgs does not consume lands in the
// positional stream, where GetCommandDescription (the confirm prompt) and
// JSONForResult's "resource" field print it verbatim — never having passed
// through RedactCommand.
func TestSecretFlagValuesNeverBecomePositionals(t *testing.T) {
	const secret = "hunter2"
	for _, args := range [][]string{
		{"create", "-f", "x", "--overrides", `{"p":"` + secret + `"}`},
		{"patch", "secret", "db", "--patch", `{"stringData":{"password":"` + secret + `"}}`},
		{"config", "set-credentials", "u", "--exec-arg", "--token=" + secret},
		{"create", "secret", "generic", "db", "--from-literal", "password=" + secret},
		{"run", "x", "--env", "PASSWORD=" + secret},
		{"config", "set-credentials", "u", "--exec-env", "TOKEN=" + secret},
		{"config", "set-credentials", "u", "--auth-provider-arg", "client-secret=" + secret},
		{"create", "secret", "docker-registry", "r", "--docker-password", secret},
	} {
		p := ParseArgs(args)
		for _, pos := range p.Positional {
			if strings.Contains(pos, secret) {
				t.Errorf("ParseArgs(%v) left a secret in Positional: %q", args, pos)
			}
		}
		for _, cand := range p.ResourceCandidates() {
			if strings.Contains(cand, secret) {
				t.Errorf("ParseArgs(%v) left a secret in ResourceCandidates: %q", args, cand)
			}
		}
		// The command description feeds the confirm prompt.
		if desc := GetCommandDescription(args); strings.Contains(desc, secret) {
			t.Errorf("GetCommandDescription(%v) = %q leaks the secret", args, desc)
		}
	}
}

// TestConfigSetVerbShiftStillRedacts: ExtractCommand may resolve `config set`
// from a later positional (the verb-shift fallback). Indexing the property from
// a hardcoded pos[0] then reads "set" as the property, redacts nothing, and
// leaks the value.
func TestConfigSetVerbShiftStillRedacts(t *testing.T) {
	for _, args := range [][]string{
		{"foo", "config", "set", "users.a.token", "hunter2"},
		{"--future-flag", "x", "config", "set", "users.a.password", "hunter2"},
		{"someplugin", "config", "set", "users.cluster-admin.client-key-data", "hunter2"},
	} {
		got := RedactCommand(args)
		if strings.Contains(got, "hunter2") {
			t.Errorf("RedactCommand(%v) = %q leaks the secret under a verb shift", args, got)
		}
	}
}

// TestVerbPositionalIndex pins the single source of truth for "which positional
// is the verb", which both ExtractCommand and configSetRedactions rely on.
func TestVerbPositionalIndex(t *testing.T) {
	tests := []struct {
		pos  []string
		want int
	}{
		{nil, -1},
		{[]string{"get", "pods"}, 0},
		{[]string{"config", "set", "x", "y"}, 0},
		{[]string{"3", "port-forward", "svc/x"}, 1},
		{[]string{"x", "config", "set"}, 1},
		{[]string{"completion", "bash"}, -1},
		{[]string{"DELETE", "pod"}, 0},
	}
	for _, tt := range tests {
		if got := verbPositionalIndex(tt.pos); got != tt.want {
			t.Errorf("verbPositionalIndex(%v) = %d, want %d", tt.pos, got, tt.want)
		}
	}
}

// TestPositionalIndexesInvariant: PositionalIndexes must index back into args
// for every positional, or configSetRedactions redacts the wrong token.
func TestPositionalIndexesInvariant(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"get", "pods"},
		{"--context", "prod", "delete", "pod", "nginx"},
		{"exec", "nginx", "--", "ls", "/tmp"},
		{"--", "get", "pods"},
		{"get", "pods", "--"},
		{"--context", "--", "get", "pods"},
		{"apply", "-Rf", "dir"},
		{"get", "--raw", "/healthz"},
		{"config", "set", "--kubeconfig", "/p", "users.a.token", "v"},
		{"-v", "3", "port-forward", "svc/x", "1:1"},
	} {
		p := ParseArgs(args)
		if len(p.PositionalIndexes) != len(p.Positional) {
			t.Fatalf("ParseArgs(%v): len(PositionalIndexes)=%d != len(Positional)=%d",
				args, len(p.PositionalIndexes), len(p.Positional))
		}
		for i, idx := range p.PositionalIndexes {
			if idx < 0 || idx >= len(args) || args[idx] != p.Positional[i] {
				t.Errorf("ParseArgs(%v): PositionalIndexes[%d]=%d does not map to Positional[%d]=%q",
					args, i, idx, i, p.Positional[i])
			}
		}
	}
}

// TestRedactArgsDoesNotMutate: kubectl is exec'd with the raw args, so the
// redactor must never write through its input.
func TestRedactArgsDoesNotMutate(t *testing.T) {
	args := []string{"patch", "secret", "db", "-p", `{"password":"hunter2"}`}
	before := append([]string(nil), args...)
	out := RedactArgs(args)
	for i := range before {
		if args[i] != before[i] {
			t.Fatalf("RedactArgs mutated args[%d]: %q -> %q", i, before[i], args[i])
		}
	}
	if strings.Contains(strings.Join(out, " "), "hunter2") {
		t.Error("RedactArgs did not redact the patch body")
	}
}

// TestExecPayloadRedactionBoundary documents exactly how far redaction reaches
// into an `exec`/`run` payload after "--". kubectl's OWN credential flags are
// redacted there. An application's flag names and inline env assignments are
// not: the payload is an arbitrary foreign command line, and a keyword
// heuristic would blank ordinary args (`--tokenizer`, `MONKEY=1`) while still
// missing unusual ones. This is a documented caveat, not an oversight.
func TestExecPayloadRedactionBoundary(t *testing.T) {
	redacted := [][]string{
		{"exec", "pod", "--", "app", "--token", "hunter2"},
		{"exec", "pod", "--", "app", "--password", "hunter2"},
	}
	for _, args := range redacted {
		if got := RedactCommand(args); strings.Contains(got, "hunter2") {
			t.Errorf("kubectl credential flag in a payload must redact: %v -> %q", args, got)
		}
	}

	// Known, accepted gap. If a future change starts redacting these, that is a
	// behavior change to make deliberately (and to document), not silently.
	notRedacted := [][]string{
		{"exec", "pod", "--", "env", "PASSWORD=hunter2", "app"},
		{"exec", "pod", "--", "app", "--db-password=hunter2"},
		{"exec", "pod", "--", "sh", "-c", "export TOKEN=hunter2"},
	}
	for _, args := range notRedacted {
		if got := RedactCommand(args); !strings.Contains(got, "hunter2") {
			t.Errorf("payload redaction boundary moved for %v -> %q; update the README caveat", args, got)
		}
	}
}

// TestRedactCommandPreservesFlagNames: the record must stay useful — the flag
// name and the --from-literal key survive redaction.
func TestRedactCommandPreservesFlagNames(t *testing.T) {
	got := RedactCommand([]string{"create", "secret", "generic", "db", "--from-literal=password=hunter2"})
	for _, want := range []string{"create", "secret", "generic", "db", "--from-literal", "password"} {
		if !strings.Contains(got, want) {
			t.Errorf("RedactCommand dropped %q from %q", want, got)
		}
	}
}

// TestRedactCommandDoesNotMutateArgs: RedactCommand must not modify the slice
// that is later handed to kubectl, or the guard would exec a redacted command.
func TestRedactCommandDoesNotMutateArgs(t *testing.T) {
	args := []string{"get", "pods", "--token", "eyJhbGciOi", "--from-literal=password=hunter2"}
	before := append([]string(nil), args...)
	_ = RedactCommand(args)
	for i := range before {
		if args[i] != before[i] {
			t.Fatalf("RedactCommand mutated args[%d]: %q -> %q", i, before[i], args[i])
		}
	}
}
