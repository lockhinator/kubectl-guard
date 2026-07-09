package guard

import "testing"

func TestStripNoPrompt(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantArgs []string
		want     bool
	}{
		{"none", []string{"get", "pods"}, []string{"get", "pods"}, false},
		{"leading", []string{"--no-prompt", "get", "pods"}, []string{"get", "pods"}, true},
		{"trailing", []string{"get", "pods", "--no-prompt"}, []string{"get", "pods"}, true},
		{"eq true", []string{"--no-prompt=true", "get"}, []string{"get"}, true},
		{"eq false disables", []string{"--no-prompt=false", "get"}, []string{"get"}, false},
		{"mid-args", []string{"--context", "prod", "--no-prompt", "delete", "pod", "x"}, []string{"--context", "prod", "delete", "pod", "x"}, true},
		{"after -- is positional", []string{"exec", "pod", "--", "--no-prompt"}, []string{"exec", "pod", "--", "--no-prompt"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs, got := StripNoPrompt(tt.args)
			if got != tt.want {
				t.Errorf("noPrompt = %v, want %v", got, tt.want)
			}
			if !equalStringSlices(gotArgs, tt.wantArgs) {
				t.Errorf("filtered args = %v, want %v", gotArgs, tt.wantArgs)
			}
		})
	}
}
