package config

import "testing"

// TestRedactOutputMode: the accessor returns "structured" ONLY for the exact
// value, and off for the empty default, an invalid value, and a nil config — so
// the redaction path is unreachable unless explicitly opted in.
func TestRedactOutputMode(t *testing.T) {
	cases := []struct {
		field string
		want  string
	}{
		{"", RedactOutputOff},
		{RedactOutputOff, RedactOutputOff},
		{RedactOutputStructured, RedactOutputStructured},
		{"bogus", RedactOutputOff},
		{"Structured", RedactOutputOff}, // case-sensitive; not the exact value
	}
	for _, tc := range cases {
		c := &Config{RedactOutput: tc.field}
		if got := c.RedactOutputMode(); got != tc.want {
			t.Errorf("RedactOutput=%q: mode = %q, want %q", tc.field, got, tc.want)
		}
	}
	var nilCfg *Config
	if got := nilCfg.RedactOutputMode(); got != RedactOutputOff {
		t.Errorf("nil config mode = %q, want %q", got, RedactOutputOff)
	}
}

func TestSetRedactOutputMode(t *testing.T) {
	c := &Config{}
	if !c.SetRedactOutputMode(RedactOutputStructured) || c.RedactOutput != RedactOutputStructured {
		t.Errorf("SetRedactOutputMode(structured) failed: %q", c.RedactOutput)
	}
	if !c.SetRedactOutputMode(RedactOutputOff) || c.RedactOutput != RedactOutputOff {
		t.Errorf("SetRedactOutputMode(off) failed: %q", c.RedactOutput)
	}
	if c.SetRedactOutputMode("bogus") {
		t.Errorf("SetRedactOutputMode(bogus) should fail")
	}
	if c.RedactOutput != RedactOutputOff {
		t.Errorf("invalid set mutated the field: %q", c.RedactOutput)
	}
}

// TestRedactOutputValidate: a non-empty, unrecognized value is a reported problem
// (fail closed); "", off, and structured are accepted.
func TestRedactOutputValidate(t *testing.T) {
	for _, v := range []string{"", RedactOutputOff, RedactOutputStructured} {
		if p := (&Config{RedactOutput: v}).Validate(); hasRedactProblem(p) {
			t.Errorf("RedactOutput=%q should validate, got problems %v", v, p)
		}
	}
	if p := (&Config{RedactOutput: "bogus"}).Validate(); !hasRedactProblem(p) {
		t.Errorf("RedactOutput=bogus should be reported, got %v", p)
	}
}

func hasRedactProblem(problems []string) bool {
	for _, p := range problems {
		if len(p) >= 13 && p[:13] == "redact_output" {
			return true
		}
	}
	return false
}
