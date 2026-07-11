package guard

import (
	"reflect"
	"testing"
)

// TestStripReason covers parsing the guard-only --reason flag in both forms,
// honoring the "--" separator. #95.
func TestStripReason(t *testing.T) {
	cases := []struct {
		name         string
		in           []string
		wantFiltered []string
		wantReason   string
		wantHas      bool
	}{
		{"two-token", []string{"--reason", "hotfix", "delete", "pod"}, []string{"delete", "pod"}, "hotfix", true},
		{"equals-form", []string{"--reason=hotfix INC", "delete"}, []string{"delete"}, "hotfix INC", true},
		{"absent", []string{"delete", "pod"}, []string{"delete", "pod"}, "", false},
		{"empty-value", []string{"--reason"}, nil, "", true},
		{"after-sep-untouched", []string{"delete", "--", "--reason", "x"}, []string{"delete", "--", "--reason", "x"}, "", false},
		// The two-token form must not swallow the "--" separator or another flag as
		// the value (a forgotten value); those tokens are preserved.
		{"no-eat-separator", []string{"--reason", "--", "delete"}, []string{"--", "delete"}, "", true},
		{"no-eat-flag", []string{"--reason", "--force", "delete"}, []string{"--force", "delete"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			filtered, reason, has := StripReason(c.in)
			if !reflect.DeepEqual(filtered, c.wantFiltered) {
				t.Errorf("filtered = %v, want %v", filtered, c.wantFiltered)
			}
			if reason != c.wantReason {
				t.Errorf("reason = %q, want %q", reason, c.wantReason)
			}
			if has != c.wantHas {
				t.Errorf("has = %v, want %v", has, c.wantHas)
			}
		})
	}
}
