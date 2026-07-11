package guard

import "testing"

// TestParseArgsOutputFormat covers capture of -o / --output in every accepted
// form, LOWERCASED, across the short and long paths. It is the parse-side half of
// the #108 redaction gate: OutputFormat must equal "json"/"yaml" for the gate to
// engage, and must NOT equal them for a templated form (jsonpath=...) so those are
// correctly excluded.
func TestParseArgsOutputFormat(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"short space", []string{"get", "pods", "-o", "json"}, "json"},
		{"short attached", []string{"get", "pods", "-ojson"}, "json"},
		{"short equals", []string{"get", "pods", "-o=json"}, "json"},
		{"short yaml", []string{"get", "pods", "-o", "yaml"}, "yaml"},
		{"long space", []string{"get", "pods", "--output", "json"}, "json"},
		{"long equals", []string{"get", "pods", "--output=yaml"}, "yaml"},
		{"uppercase lowercased", []string{"get", "pods", "-o", "JSON"}, "json"},
		{"wide", []string{"get", "pods", "-o", "wide"}, "wide"},
		{"name", []string{"get", "pods", "-o", "name"}, "name"},
		{"jsonpath templated", []string{"get", "pods", "-o", "jsonpath={.items}"}, "jsonpath={.items}"},
		{"jsonpath attached", []string{"get", "pods", "-ojsonpath={.items}"}, "jsonpath={.items}"},
		{"custom-columns", []string{"get", "pods", "--output=custom-columns=NAME:.metadata.name"}, "custom-columns=name:.metadata.name"},
		{"none", []string{"get", "pods"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseArgs(tt.args).OutputFormat; got != tt.want {
				t.Errorf("OutputFormat = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseArgsOutputFormatDoesNotShiftVerb guards that capturing -o's value never
// leaves it in verb/positional position: `get -o json pods` still resolves verb
// "get" and positional ["get","pods"], with json consumed as the format.
func TestParseArgsOutputFormatDoesNotShiftVerb(t *testing.T) {
	p := ParseArgs([]string{"get", "-o", "json", "pods"})
	if p.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want json", p.OutputFormat)
	}
	if len(p.Positional) != 2 || p.Positional[0] != "get" || p.Positional[1] != "pods" {
		t.Errorf("Positional = %v, want [get pods]", p.Positional)
	}
}

// TestParseArgsWatch covers -w / --watch capture, including that --watch=false is
// NOT a watch and that a watch never consumes the next token as a value.
func TestParseArgsWatch(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"short", []string{"get", "pods", "-w"}, true},
		{"long", []string{"get", "pods", "--watch"}, true},
		{"long true", []string{"get", "pods", "--watch=true"}, true},
		{"long false", []string{"get", "pods", "--watch=false"}, false},
		{"none", []string{"get", "pods"}, false},
		{"watch then output", []string{"get", "pods", "-w", "-o", "yaml"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseArgs(tt.args).Watch; got != tt.want {
				t.Errorf("Watch = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseArgsWatchDoesNotConsumeVerb: a bare --watch must not swallow a
// following token — `--watch get pods` (unusual order) keeps get in the stream.
func TestParseArgsWatchDoesNotConsumeVerb(t *testing.T) {
	p := ParseArgs([]string{"get", "--watch", "pods"})
	if !p.Watch {
		t.Errorf("Watch = false, want true")
	}
	if len(p.Positional) != 2 || p.Positional[1] != "pods" {
		t.Errorf("Positional = %v, want [get pods]", p.Positional)
	}
}
