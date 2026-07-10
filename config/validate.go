package config

import (
	"fmt"
	"strings"
)

// Validate reports every problem with the configuration as a list of
// human-readable messages (empty when the config is valid). It is pure: it reads
// the config and allocates messages, changing nothing.
//
// For a security tool, a silently-ignored misconfiguration is dangerous: a typo
// like `confirm_mode: typname` or `context_mode: blck` is not one of the
// recognized values, so the runtime falls back to the WEAKER default (simple
// confirm / confirm instead of block) while the user believes they configured
// the stronger one. Validate surfaces these so they can fail closed at runtime
// (see guard.Check) and be listed by `kubectl-guard config validate`.
//
// Empty mode values are NOT problems: ApplyDefaults fills them with the correct
// default. Only a non-empty, unrecognized value is reported.
func (c *Config) Validate() []string {
	var problems []string

	if c.ConfirmMode != "" && !validConfirmMode(c.ConfirmMode) {
		problems = append(problems, fmt.Sprintf(
			"confirm_mode: %q is not valid (want %q, %q, or %q)",
			c.ConfirmMode, ConfirmModeSimple, ConfirmModeTypeName, ConfirmModeAgentRelay))
	}
	if c.AuditMode != "" && !validAuditMode(c.AuditMode) {
		problems = append(problems, fmt.Sprintf(
			"audit_mode: %q is not valid (want %q, %q, or %q)",
			c.AuditMode, AuditModeAll, AuditModeGated, AuditModeOff))
	}
	if c.ContextMode != "" && !validContextMode(c.ContextMode) {
		problems = append(problems, fmt.Sprintf(
			"context_mode: %q is not valid (want %q or %q)",
			c.ContextMode, ContextModeConfirm, ContextModeBlock))
	}
	if c.NamespaceMode != "" && !validNamespaceMode(c.NamespaceMode) {
		problems = append(problems, fmt.Sprintf(
			"namespace_mode: %q is not valid (want %q or %q)",
			c.NamespaceMode, NamespaceModeConfirm, NamespaceModeBlock))
	}
	if c.InCluster != "" && !validInClusterMode(c.InCluster) {
		problems = append(problems, fmt.Sprintf(
			"in_cluster: %q is not valid (want %q, %q, or %q)",
			c.InCluster, InClusterNamespace, InClusterDeny, InClusterAllow))
	}
	if c.SensitiveAccess != "" && !validSensitiveAccessMode(c.SensitiveAccess) {
		problems = append(problems, fmt.Sprintf(
			"sensitive_access: %q is not valid (want %q, %q, or %q)",
			c.SensitiveAccess, SensitiveAccessOff, SensitiveAccessGate, SensitiveAccessBlock))
	}
	for i, v := range c.SensitiveVerbs {
		if strings.TrimSpace(v) == "" {
			problems = append(problems, fmt.Sprintf("sensitive_verbs: entry %d is empty", i))
		}
	}
	if c.BlastRadius != "" && !validBlastRadiusMode(c.BlastRadius) {
		problems = append(problems, fmt.Sprintf(
			"blast_radius: %q is not valid (want %q, %q, or %q)",
			c.BlastRadius, BlastRadiusOff, BlastRadiusGate, BlastRadiusBlock))
	}
	for i, ap := range c.ActorPolicies {
		if strings.TrimSpace(ap.Actor) == "" {
			problems = append(problems, fmt.Sprintf("actor_policies: entry %d has an empty actor", i))
		} else if err := validateGlobPattern(ap.Actor); err != nil {
			problems = append(problems, fmt.Sprintf("actor_policies: actor %q %v", ap.Actor, err))
		}
		if ap.ContextMode != "" && !validContextMode(ap.ContextMode) {
			problems = append(problems, fmt.Sprintf(
				"actor_policies[%d].context_mode: %q is not valid (want %q or %q)",
				i, ap.ContextMode, ContextModeConfirm, ContextModeBlock))
		}
		if ap.NamespaceMode != "" && !validNamespaceMode(ap.NamespaceMode) {
			problems = append(problems, fmt.Sprintf(
				"actor_policies[%d].namespace_mode: %q is not valid (want %q or %q)",
				i, ap.NamespaceMode, NamespaceModeConfirm, NamespaceModeBlock))
		}
	}

	for _, p := range c.ProtectedContexts {
		if err := validateGlobPattern(p); err != nil {
			problems = append(problems, fmt.Sprintf("protected_contexts: pattern %q %v", p, err))
		}
	}
	for _, p := range c.ProtectedNamespaces {
		if err := validateGlobPattern(p); err != nil {
			problems = append(problems, fmt.Sprintf("protected_namespaces: pattern %q %v", p, err))
		}
	}

	for i, r := range c.ProtectedResources {
		if strings.TrimSpace(r) == "" {
			problems = append(problems, fmt.Sprintf("protected_resources: entry %d is empty", i))
		}
	}

	if c.ConfirmTimeoutSeconds < 0 {
		problems = append(problems, fmt.Sprintf(
			"confirm_timeout_seconds: %d is negative (use 0 to wait forever, or a positive number of seconds)",
			c.ConfirmTimeoutSeconds))
	} else if c.ConfirmTimeoutSeconds > MaxConfirmTimeoutSeconds {
		// A finite timeout above the ceiling is rejected rather than silently
		// accepted, because `time.Duration(n) * time.Second` overflows int64
		// nanoseconds around n=9.2e9 and wraps NEGATIVE — which readLine treats as
		// "wait forever", silently defeating the fail-safe the value was meant to
		// provide. The ceiling is far below the overflow point and far above any
		// real prompt timeout; use 0 to wait forever deliberately.
		problems = append(problems, fmt.Sprintf(
			"confirm_timeout_seconds: %d is too large (max %d; use 0 to wait forever)",
			c.ConfirmTimeoutSeconds, MaxConfirmTimeoutSeconds))
	}

	return problems
}

func validConfirmMode(m string) bool {
	switch m {
	case ConfirmModeSimple, ConfirmModeTypeName, ConfirmModeAgentRelay:
		return true
	}
	return false
}

func validAuditMode(m string) bool {
	switch m {
	case AuditModeAll, AuditModeGated, AuditModeOff:
		return true
	}
	return false
}

func validContextMode(m string) bool {
	switch m {
	case ContextModeConfirm, ContextModeBlock:
		return true
	}
	return false
}

func validNamespaceMode(m string) bool {
	switch m {
	case NamespaceModeConfirm, NamespaceModeBlock:
		return true
	}
	return false
}

func validInClusterMode(m string) bool {
	switch m {
	case InClusterNamespace, InClusterDeny, InClusterAllow:
		return true
	}
	return false
}

func validSensitiveAccessMode(m string) bool {
	switch m {
	case SensitiveAccessOff, SensitiveAccessGate, SensitiveAccessBlock:
		return true
	}
	return false
}

func validBlastRadiusMode(m string) bool {
	switch m {
	case BlastRadiusOff, BlastRadiusGate, BlastRadiusBlock:
		return true
	}
	return false
}

// validateGlobPattern reports whether a context/namespace pattern is well-formed
// for matchGlob, returning a descriptive error for a likely typo.
//
// matchGlob (glob.go) is deliberately TOTAL: it never errors, and a malformed
// pattern degrades to a literal match — the fail-safe runtime behavior. That
// leniency, though, means a typo like `prod-[abc` (an unterminated character
// class the user meant as a class) silently matches only the literal string
// "prod-[abc" and protects nothing they intended. This validator is the strict
// counterpart, run at config time, so the typo is reported instead of shipping
// as a silent protection gap. The two must stay consistent: a pattern this
// function accepts is one matchGlob interprets as the user expects.
func validateGlobPattern(pattern string) error {
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			// An escape must have a character to escape.
			if i == len(runes)-1 {
				return fmt.Errorf("ends with a dangling '\\' escape")
			}
			i++ // skip the escaped character
		case '[':
			end, err := scanClose(runes, i)
			if err != nil {
				return err
			}
			i = end
		}
	}
	return nil
}

// scanClose finds the index of the ']' that closes the character class opened at
// runes[open] (which is '['), mirroring matchClass's parsing: an optional '^'
// negation, a leading ']' that is a literal member, and '\'-escaped members. It
// returns an error if the class is never closed.
func scanClose(runes []rune, open int) (int, error) {
	i := open + 1
	if i < len(runes) && runes[i] == '^' {
		i++
	}
	// A ']' immediately here is a literal member, not the terminator.
	first := true
	for i < len(runes) {
		switch {
		case runes[i] == ']' && !first:
			return i, nil
		case runes[i] == '\\' && i+1 < len(runes):
			i += 2
		default:
			i++
		}
		first = false
	}
	return 0, fmt.Errorf("has an unterminated '[' character class")
}
