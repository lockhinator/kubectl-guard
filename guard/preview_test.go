package guard

import (
	"reflect"
	"testing"
)

func TestPreviewArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string // nil => no preview
	}{
		{
			name: "delete with label selector",
			args: []string{"delete", "pod", "-l", "app=web"},
			want: []string{"get", "pod", "--selector", "app=web", "-o", "name"},
		},
		{
			name: "delete clustered short selector",
			args: []string{"delete", "pod", "-lapp=web"},
			want: []string{"get", "pod", "--selector", "app=web", "-o", "name"},
		},
		{
			name: "delete explicit names",
			args: []string{"delete", "pod", "web-1", "web-2"},
			want: []string{"get", "pod", "web-1", "web-2", "-o", "name"},
		},
		{
			name: "delete type/name",
			args: []string{"delete", "pod/web-1"},
			want: []string{"get", "pod/web-1", "-o", "name"},
		},
		{
			name: "scale target inline replicas",
			args: []string{"scale", "deploy/web", "--replicas=0"},
			want: []string{"get", "deploy/web", "-o", "name"},
		},
		{
			name: "scale target space-form replicas (value must not leak)",
			args: []string{"scale", "--replicas", "0", "deploy/web"},
			want: []string{"get", "deploy/web", "-o", "name"},
		},
		{
			name: "drain node gets the implicit nodes type",
			args: []string{"drain", "node-1", "--ignore-daemonsets"},
			want: []string{"get", "nodes", "node-1", "-o", "name"},
		},
		{
			name: "cordon node",
			args: []string{"cordon", "node-1"},
			want: []string{"get", "nodes", "node-1", "-o", "name"},
		},
		{
			name: "drain by node selector",
			args: []string{"drain", "-l", "role=worker"},
			want: []string{"get", "nodes", "--selector", "role=worker", "-o", "name"},
		},
		{
			name: "label removal form stops target collection",
			args: []string{"label", "pods", "foo", "bar-"},
			want: []string{"get", "pods", "foo", "-o", "name"},
		},
		{
			name: "taint removal form stops at key:effect-",
			args: []string{"taint", "nodes", "n1", "dedicated:NoSchedule-"},
			want: []string{"get", "nodes", "n1", "-o", "name"},
		},
		{
			name: "taint value-less add form stops at key:effect",
			args: []string{"taint", "nodes", "foo", "bar:NoSchedule"},
			want: []string{"get", "nodes", "foo", "-o", "name"},
		},
		{
			name: "delete --all preserves the type",
			args: []string{"delete", "pods", "--all"},
			want: []string{"get", "pods", "-o", "name"},
		},
		{
			name: "field selector and all-namespaces and namespace and context",
			args: []string{"delete", "pods", "--field-selector", "status.phase=Failed", "-A", "-n", "x", "--context", "c1"},
			// -A wins as --all-namespaces; both are forwarded verbatim like kubectl.
			want: []string{"get", "pods", "--field-selector", "status.phase=Failed", "--namespace", "x", "--all-namespaces", "--context", "c1", "-o", "name"},
		},
		{
			name: "label stops target collection at the KEY=VALUE assignment",
			args: []string{"label", "pods", "-l", "app=x", "team=a"},
			want: []string{"get", "pods", "--selector", "app=x", "-o", "name"},
		},
		{
			name: "taint node stops at the KEY=VALUE:EFFECT assignment",
			args: []string{"taint", "nodes", "n1", "key=val:NoSchedule"},
			want: []string{"get", "nodes", "n1", "-o", "name"},
		},
		{
			name: "set is not previewable (subcommand in positional)",
			args: []string{"set", "image", "deploy/web", "nginx=img"},
			want: nil,
		},
		// No preview:
		{name: "manifest delete -f", args: []string{"delete", "-f", "m.yaml"}, want: nil},
		{name: "kustomize", args: []string{"delete", "-k", "dir/"}, want: nil},
		{name: "raw", args: []string{"delete", "--raw", "/api/v1/x"}, want: nil},
		{name: "non-previewable create", args: []string{"create", "-f", "m.yaml"}, want: nil},
		{name: "non-previewable exec", args: []string{"exec", "pod", "--", "sh"}, want: nil},
		{name: "read verb", args: []string{"get", "pods"}, want: nil},
		{name: "delete with no target or selector", args: []string{"delete"}, want: nil},
		// Identity / API-server overrides the preview cannot faithfully reproduce:
		// skip rather than resolve against the wrong cluster/identity.
		{name: "skip on --server", args: []string{"delete", "pods", "-l", "x", "--server", "https://evil:6443"}, want: nil},
		{name: "skip on --cluster", args: []string{"delete", "pods", "-l", "x", "--cluster", "prod"}, want: nil},
		{name: "skip on --as", args: []string{"delete", "pods", "-l", "x", "--as", "system:masters"}, want: nil},
		{name: "skip on --token", args: []string{"delete", "pods", "-l", "x", "--token", "t"}, want: nil},
		{name: "skip on --user", args: []string{"delete", "pods", "-l", "x", "--user", "admin"}, want: nil},
		{name: "skip on --username", args: []string{"delete", "pods", "-l", "x", "--username", "bob"}, want: nil},
		{name: "skip on --password", args: []string{"delete", "pods", "-l", "x", "--password", "p"}, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PreviewArgs(tc.args)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("PreviewArgs(%v)\n got  %v\n want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestParseArgsCapturesSelectorValues pins the selector-value capture the preview
// depends on (previously only HasSelector was recorded).
func TestParseArgsCapturesSelectorValues(t *testing.T) {
	p := ParseArgs([]string{"delete", "pod", "-l", "app=web", "--field-selector", "status.phase=Failed"})
	if p.Selector != "app=web" {
		t.Errorf("Selector = %q, want app=web", p.Selector)
	}
	if p.FieldSelector != "status.phase=Failed" {
		t.Errorf("FieldSelector = %q, want status.phase=Failed", p.FieldSelector)
	}
	// Inline forms.
	p = ParseArgs([]string{"delete", "pod", "--selector=env=prod", "-lapp=x"})
	// --selector then -l: -l wins as the last write, matching kubectl's last-flag-wins.
	if p.Selector != "app=x" {
		t.Errorf("Selector = %q, want app=x (last -l wins)", p.Selector)
	}
}
