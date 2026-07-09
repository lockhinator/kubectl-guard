package guard

import (
	"reflect"
	"testing"
)

func TestIsDiffable(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"apply -f", []string{"apply", "-f", "deploy.yaml"}, true},
		{"create -f", []string{"create", "-f", "deploy.yaml"}, true},
		{"replace -f", []string{"replace", "-f", "deploy.yaml"}, true},
		{"apply -k", []string{"apply", "-k", "overlays/prod"}, true},
		{"apply with context and -f", []string{"--context=prod", "apply", "-f", "deploy.yaml"}, true},
		{"delete (not diffable)", []string{"delete", "pod", "nginx"}, false},
		{"scale (not diffable)", []string{"scale", "deploy", "api", "--replicas=3"}, false},
		{"exec (not diffable)", []string{"exec", "pod", "x", "--", "ls"}, false},
		{"patch (no manifest, not diffable)", []string{"patch", "deploy", "x", "-p", `{}`}, false},
		{"apply without source (not diffable)", []string{"apply"}, false},
		{"get (read-only)", []string{"get", "pods"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDiffable(tt.args); got != tt.want {
				t.Errorf("IsDiffable(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestDiffArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"swap verb", []string{"apply", "-f", "deploy.yaml"}, []string{"diff", "-f", "deploy.yaml"}},
		{"preserve leading global flag", []string{"--context=prod", "apply", "-f", "x.yaml"}, []string{"--context=prod", "diff", "-f", "x.yaml"}},
		{"create -f", []string{"create", "-f", "x.yaml", "-n", "kube-system"}, []string{"diff", "-f", "x.yaml", "-n", "kube-system"}},
		{"verb after short flag value", []string{"-n", "prod", "apply", "-f", "x.yaml"}, []string{"-n", "prod", "diff", "-f", "x.yaml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := append([]string(nil), tt.args...)
			got := DiffArgs(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DiffArgs(%v) = %v, want %v", tt.args, got, tt.want)
			}
			// must not mutate the input slice
			if !reflect.DeepEqual(tt.args, orig) {
				t.Errorf("DiffArgs mutated input: %v -> %v", orig, tt.args)
			}
		})
	}
}

// TestDiffArgsNoVerb returns nil when there is no verb before "--".
func TestDiffArgsNoVerb(t *testing.T) {
	if got := DiffArgs([]string{"--", "apply"}); got != nil {
		t.Errorf("DiffArgs after -- = %v, want nil", got)
	}
}
