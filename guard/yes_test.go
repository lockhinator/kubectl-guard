package guard

import "testing"

func TestStripYes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantArgs []string
		want     bool
	}{
		{"none", []string{"get", "pods"}, []string{"get", "pods"}, false},
		{"leading", []string{"--yes", "delete", "pod", "x"}, []string{"delete", "pod", "x"}, true},
		{"trailing", []string{"delete", "pod", "x", "--yes"}, []string{"delete", "pod", "x"}, true},
		{"eq true", []string{"--yes=true", "delete"}, []string{"delete"}, true},
		{"eq false disables", []string{"--yes=false", "delete"}, []string{"delete"}, false},
		{"mid-args", []string{"--context", "prod", "--yes", "delete", "pod", "x"}, []string{"--context", "prod", "delete", "pod", "x"}, true},
		{"after -- is positional", []string{"exec", "pod", "--", "--yes"}, []string{"exec", "pod", "--", "--yes"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs, got := StripYes(tt.args)
			if got != tt.want {
				t.Errorf("yes = %v, want %v", got, tt.want)
			}
			if !equalStringSlices(gotArgs, tt.wantArgs) {
				t.Errorf("filtered args = %v, want %v", gotArgs, tt.wantArgs)
			}
		})
	}
}
