package guard

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// safeCommands are read-only top-level commands that don't modify cluster
// state and have no subcommand nuance.
var safeCommands = map[string]bool{
	"get":           true,
	"describe":      true,
	"logs":          true,
	"top":           true,
	"explain":       true,
	"api-resources": true,
	"api-versions":  true,
	"version":       true,
	"cluster-info":  true,
	"wait":          true,
	"diff":          true,
}

// stateAlteringCommands modify cluster state and require confirmation on
// protected contexts.
var stateAlteringCommands = map[string]bool{
	"apply":     true,
	"create":    true,
	"delete":    true,
	"patch":     true,
	"replace":   true,
	"edit":      true,
	"scale":     true,
	"autoscale": true,
	"expose":    true,
	"run":       true,
	"set":       true,
	"label":     true,
	"annotate":  true,
	"taint":     true,
	"drain":     true,
	"cordon":    true,
	"uncordon":  true,
	"exec":      true,
	"cp":        true,
	"debug":     true,
	"attach":    true,
}

// safeSubcommands maps a command to the subset of its subcommands that are
// read-only. Any other subcommand of these commands is treated as
// state-altering. A bare invocation (no subcommand) only prints help and is
// treated as safe.
//
// Notably this makes kubectl "config use-context" and "auth reconcile"
// state-altering, while keeping "config view"/"config get-contexts" and
// "auth can-i" read-only.
var safeSubcommands = map[string]map[string]bool{
	"rollout": {"status": true, "history": true},
	"config":  {"view": true, "get-contexts": true, "current-context": true},
	"auth":    {"can-i": true, "whoami": true},
}

// shortTakesValue lists single-letter kubectl flags that consume a value
// (the rest of the token, or the next argument). f and k are manifest sources
// handled specially by parseShortCluster. Every other short flag is treated as
// boolean. This replaces the old exact-match knownShortFlags set, which could
// not recognize clustered flags like "-Rf" or "-nf" (the G1 gap).
var shortTakesValue = map[byte]bool{
	'n': true, 'l': true, 'o': true, 'c': true, 's': true, 'p': true,
}

// knownLongFlags are kubectl long flags that take a separate value
// (not --flag=value style). --context/--kubeconfig/--filename/--kustomize are
// handled explicitly in ParseArgs and intentionally omitted here.
var knownLongFlags = map[string]bool{
	"--selector": true,
	"--output":   true, "--container": true,
	"--cluster": true, "--user": true,
}

// ProtectedResourceChecker is satisfied by *config.Config; kept as an interface
// so command classification stays testable without shelling out.
type ProtectedResourceChecker interface {
	IsResourceProtected(candidate string) bool
	HasProtectedResources() bool
}

// ParsedArgs is the single, consistent view of a kubectl argument list. All
// extraction (command, resources, context, filenames) derives from one
// ParseArgs pass so the pieces can never disagree about flag boundaries or
// the "--" separator.
type ParsedArgs struct {
	Positional      []string
	Context         string // value of --context
	Kubeconfig      string // value of --kubeconfig
	Filenames       []string
	Kustomize       string // value of -k / --kustomize
	ExplicitContext bool
	// VerbIndex is the index of the kubectl verb (first positional) in the
	// original args, or -1 if none was found before the "--" separator.
	VerbIndex int

	// Targeting & identity flags. --server points at a different API server
	// (a different cluster) the guard cannot map to a context; --as* impersonate
	// another identity; --token overrides credentials. Captured so the guard
	// can fail closed on --server and attribute impersonation in the audit log.
	Server    string // --server / -s
	HasServer bool
	AsUser    string   // --as
	AsGroups  []string // --as-group (repeatable)
	AsUID     string   // --as-uid
	HasAs     bool     // any --as / --as-group / --as-uid present
	Token     string   // --token
	HasToken  bool

	// DryRun captures --dry-run (client|server|none). A bare --dry-run is
	// treated as client. State-altering commands in dry-run mode change no
	// cluster state and skip context/namespace gating.
	DryRun    string
	HasDryRun bool

	// Namespace targeting. --namespace/-n sets an explicit namespace;
	// --all-namespaces/-A spans every namespace (gated when any namespace is
	// protected, like "get all" spans resources).
	Namespace     string
	HasNamespace  bool
	AllNamespaces bool
}

// HasImpersonation reports whether any --as / --as-group / --as-uid flag is
// set, i.e. the command impersonates another identity.
func (p ParsedArgs) HasImpersonation() bool {
	return p.HasAs
}

// IsDryRun reports whether the command runs in dry-run mode, mirroring
// kubectl's own --dry-run parsing (cmdutil.GetDryRunStrategy). Anything kubectl
// treats as a real mutation must NOT be treated as a dry-run here, or the guard
// would skip gating on a command that actually changes cluster state.
//
// kubectl parses the flag with strconv.ParseBool first: any boolean-false form
// (false/f/F/0/False/FALSE/...) means DryRunNone -> a REAL mutation. Only
// "client", "server", "unchanged" (bare --dry-run), and boolean-true forms are
// genuine dry-runs. "none" and any invalid value gate normally (kubectl rejects
// invalid values, so nothing runs anyway; failing closed is correct).
func (p ParsedArgs) IsDryRun() bool {
	if !p.HasDryRun {
		return false
	}
	if b, err := strconv.ParseBool(p.DryRun); err == nil {
		// true (client) is a dry-run; false is a real mutation.
		return b
	}
	switch strings.ToLower(p.DryRun) {
	case "client", "server", "unchanged":
		return true
	default: // "none" or an invalid value: gate normally.
		return false
	}
}

// ImpersonationString summarizes the impersonation identity (--as / --as-group
// / --as-uid) for the audit log, or "" when none is set. It combines all three
// so that group- or uid-only impersonation (e.g. --as-group=system:masters with
// no --as) is still attributed, not silently dropped.
func (p ParsedArgs) ImpersonationString() string {
	if !p.HasAs {
		return ""
	}
	var parts []string
	if p.AsUser != "" {
		parts = append(parts, p.AsUser)
	}
	for _, g := range p.AsGroups {
		parts = append(parts, "group:"+g)
	}
	if p.AsUID != "" {
		parts = append(parts, "uid:"+p.AsUID)
	}
	return strings.Join(parts, ",")
}

// ResolvedNamespace returns the namespace a command targets, for protection
// decisions. An explicit --namespace/-n wins; otherwise kubectl's default
// ("default") is assumed. (Resolving the namespace baked into a context would
// require parsing kubeconfig and is not done here.)
func (p ParsedArgs) ResolvedNamespace() string {
	if p.HasNamespace && p.Namespace != "" {
		return p.Namespace
	}
	return "default"
}

// ResourceCandidates returns the positional arguments after the verb. Any may
// be a resource type or "type/name" token.
func (p ParsedArgs) ResourceCandidates() []string {
	if len(p.Positional) <= 1 {
		return nil
	}
	return p.Positional[1:]
}

// InspectableFilenames returns -f targets we can open and scan: local files
// only (never "-" stdin or http(s) URLs).
func (p ParsedArgs) InspectableFilenames() []string {
	var out []string
	for _, f := range p.Filenames {
		if isInspectableFile(f) {
			out = append(out, f)
		}
	}
	return out
}

// HasUninspectableSource reports whether the command reads manifests from a
// source we cannot scan (stdin "-", a URL, or a kustomize directory).
func (p ParsedArgs) HasUninspectableSource() bool {
	if p.Kustomize != "" {
		return true
	}
	for _, f := range p.Filenames {
		if !isInspectableFile(f) {
			return true
		}
	}
	return false
}

func isInspectableFile(f string) bool {
	return f != "-" && !strings.HasPrefix(f, "http://") && !strings.HasPrefix(f, "https://")
}

// splitLong splits "--name" or "--name=value" into (name, value, hasInline).
func splitLong(arg string) (name, val string, hasInline bool) {
	if eq := strings.IndexByte(arg, '='); eq >= 0 {
		return arg[:eq], arg[eq+1:], true
	}
	return arg, "", false
}

// addSource records a manifest source: 'f' -> filename, 'k' -> kustomize dir.
func (p *ParsedArgs) addSource(c byte, val string) {
	if c == 'f' {
		p.Filenames = append(p.Filenames, val)
	} else {
		p.Kustomize = val
	}
}

// parseShortCluster walks a bundled short-flag token (e.g. "-Rf", "-nf",
// "-fn") the way pflag does, recording any -f/-k source it finds and reporting
// whether the next argument is consumed as a value. This closes the G1 gap
// where a clustered source flag (e.g. "apply -Rf dir") was neither recognized
// nor scanned.
//
// Walk semantics: a value-taking flag consumes the rest of the token (or the
// next argument); a boolean flag (e.g. -R) is skipped and the walk continues.
// f and k are sources whose value becomes a filename/kustomize target.
func (p *ParsedArgs) parseShortCluster(arg string, rest []string) (consumeNext bool) {
	shorthands := arg[1:] // strip leading "-"
	for len(shorthands) > 0 {
		c := shorthands[0]
		switch {
		case c == 'f' || c == 'k':
			if len(shorthands) > 1 {
				p.addSource(c, strings.TrimPrefix(shorthands[1:], "="))
				return false
			}
			if len(rest) > 0 {
				p.addSource(c, rest[0])
				return true
			}
			return false
		case c == 's':
			// -s / --server points at a different API server; capture it so the
			// guard can fail closed when context protection is configured.
			p.HasServer = true
			if len(shorthands) > 1 {
				p.Server = strings.TrimPrefix(shorthands[1:], "=")
				return false
			}
			if len(rest) > 0 {
				p.Server = rest[0]
				return true
			}
			return false
		case c == 'n':
			// -n / --namespace sets the target namespace.
			p.HasNamespace = true
			if len(shorthands) > 1 {
				p.Namespace = strings.TrimPrefix(shorthands[1:], "=")
				return false
			}
			if len(rest) > 0 {
				p.Namespace = rest[0]
				return true
			}
			return false
		case shortTakesValue[c]:
			// consumes the rest of the token, or the next argument.
			if len(shorthands) > 1 {
				return false
			}
			return len(rest) > 0
		default:
			// boolean short flag. -A / --all-namespaces spans every namespace.
			if c == 'A' {
				p.AllNamespaces = true
			}
			shorthands = shorthands[1:]
		}
	}
	return false
}

// ParseArgs performs one pass over a kubectl argument list, honoring the "--"
// separator consistently for every consumer. It stops interpreting flags at
// "--", so a trailing "--context=dev" can no longer trick context resolution
// (the S1 bypass), and it stops positional collection there to match kubectl.
func ParseArgs(args []string) ParsedArgs {
	var p ParsedArgs
	p.VerbIndex = -1
	skipNext := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
			// kubectl treats everything after "--" as positional (resource names,
			// exec args, etc.). Flags stop here, so a trailing "--context=dev"
			// cannot spoof context resolution (S1); but resource tokens after
			// "--" must still be matched (H4).
			p.Positional = append(p.Positional, args[i+1:]...)
			break
		}
		switch {
		case strings.HasPrefix(arg, "--"):
			name, val, hasInline := splitLong(arg)
			switch name {
			case "--context":
				p.ExplicitContext = true
				if hasInline {
					p.Context = val
				} else if i+1 < len(args) {
					p.Context = args[i+1]
					skipNext = true
				}
			case "--kubeconfig":
				if hasInline {
					p.Kubeconfig = val
				} else if i+1 < len(args) {
					p.Kubeconfig = args[i+1]
					skipNext = true
				}
			case "--filename":
				if hasInline {
					p.Filenames = append(p.Filenames, val)
				} else if i+1 < len(args) {
					p.Filenames = append(p.Filenames, args[i+1])
					skipNext = true
				}
			case "--kustomize":
				if hasInline {
					p.Kustomize = val
				} else if i+1 < len(args) {
					p.Kustomize = args[i+1]
					skipNext = true
				}
			case "--server":
				p.HasServer = true
				if hasInline {
					p.Server = val
				} else if i+1 < len(args) {
					p.Server = args[i+1]
					skipNext = true
				}
			case "--as":
				p.HasAs = true
				if hasInline {
					p.AsUser = val
				} else if i+1 < len(args) {
					p.AsUser = args[i+1]
					skipNext = true
				}
			case "--as-group":
				p.HasAs = true
				if hasInline {
					p.AsGroups = append(p.AsGroups, val)
				} else if i+1 < len(args) {
					p.AsGroups = append(p.AsGroups, args[i+1])
					skipNext = true
				}
			case "--as-uid":
				p.HasAs = true
				if hasInline {
					p.AsUID = val
				} else if i+1 < len(args) {
					p.AsUID = args[i+1]
					skipNext = true
				}
			case "--token":
				p.HasToken = true
				if hasInline {
					p.Token = val
				} else if i+1 < len(args) {
					p.Token = args[i+1]
					skipNext = true
				}
			case "--namespace":
				p.HasNamespace = true
				if hasInline {
					p.Namespace = val
				} else if i+1 < len(args) {
					p.Namespace = args[i+1]
					skipNext = true
				}
			case "--all-namespaces":
				// Honor an explicit boolean value: --all-namespaces=false does
				// NOT span namespaces (matches kubectl), so it must not be gated
				// as if it did. A bare --all-namespaces or a non-boolean value
				// means true.
				if hasInline {
					if b, err := strconv.ParseBool(val); err == nil {
						p.AllNamespaces = b
					} else {
						p.AllNamespaces = true
					}
				} else {
					p.AllNamespaces = true
				}
			case "--dry-run":
				p.HasDryRun = true
				if hasInline {
					p.DryRun = val
				} else {
					p.DryRun = "true" // bare --dry-run behaves as client
				}
			default:
				// Other long flag: skip its value if it's a known value-taker.
				if !hasInline && knownLongFlags[arg] {
					skipNext = true
				}
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			// Single-dash short flags, possibly clustered (e.g. "-Rf", "-nf").
			if p.parseShortCluster(arg, args[i+1:]) {
				skipNext = true
			}
		default:
			if p.VerbIndex < 0 {
				p.VerbIndex = i
			}
			p.Positional = append(p.Positional, arg)
		}
	}
	return p
}

// StripGuardFlags removes guard-only flags from args and reports whether the
// --json flag was requested. These flags belong to the guard, not kubectl, and
// must never be forwarded. --json is recognized as "--json", "--json=true",
// or "--json=false" and is only honored before the "--" separator (after it,
// tokens are positional kubectl args such as exec payloads).
func StripGuardFlags(args []string) (filtered []string, jsonMode bool) {
	seenSep := false
	for _, a := range args {
		if a == "--" {
			seenSep = true
			filtered = append(filtered, a)
			continue
		}
		if !seenSep {
			switch a {
			case "--json", "--json=true":
				jsonMode = true
				continue
			case "--json=false":
				jsonMode = false
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered, jsonMode
}

// StripNoPrompt removes the guard-only --no-prompt flag from args and reports
// whether headless/no-prompt mode was requested. Like --json, it belongs to the
// guard and must never be forwarded to kubectl. Recognized as "--no-prompt",
// "--no-prompt=true", or "--no-prompt=false", and only before the "--"
// separator (after it, tokens are positional kubectl args).
func StripNoPrompt(args []string) (filtered []string, noPrompt bool) {
	seenSep := false
	for _, a := range args {
		if a == "--" {
			seenSep = true
			filtered = append(filtered, a)
			continue
		}
		if !seenSep {
			switch a {
			case "--no-prompt", "--no-prompt=true":
				noPrompt = true
				continue
			case "--no-prompt=false":
				noPrompt = false
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered, noPrompt
}

// StripYes removes the guard-only --yes flag from args and reports whether
// audited auto-confirm was requested. Like --json/--no-prompt, it belongs to
// the guard and must never be forwarded to kubectl. Recognized as "--yes",
// "--yes=true", or "--yes=false", and only before the "--" separator.
func StripYes(args []string) (filtered []string, yes bool) {
	seenSep := false
	for _, a := range args {
		if a == "--" {
			seenSep = true
			filtered = append(filtered, a)
			continue
		}
		if !seenSep {
			switch a {
			case "--yes", "--yes=true":
				yes = true
				continue
			case "--yes=false":
				yes = false
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered, yes
}

// PositionalArgs returns the non-flag arguments before "--". Thin wrapper over
// ParseArgs kept for callers/tests.
func PositionalArgs(args []string) []string {
	return ParseArgs(args).Positional
}

// ExtractCommand extracts the kubectl command and its first subcommand from
// args, ignoring flags. The verb is normalized to lowercase to prevent
// uppercase bypass (e.g., "DELETE" should match "delete").
func ExtractCommand(args []string) (cmd string, subCmd string) {
	pos := PositionalArgs(args)
	if len(pos) >= 1 {
		cmd = strings.ToLower(pos[0])
	}
	if len(pos) >= 2 {
		subCmd = pos[1]
	}
	return
}

// ExtractResourceCandidates returns the positional arguments after the verb.
func ExtractResourceCandidates(args []string) []string {
	return ParseArgs(args).ResourceCandidates()
}

// ExtractFilenames returns the paths supplied via -f / --filename (in any
// form). Directories, "-" (stdin), and URLs are returned verbatim.
func ExtractFilenames(args []string) []string {
	return ParseArgs(args).Filenames
}

// IsSafeCommand returns true if the command is read-only.
func IsSafeCommand(args []string) bool {
	if len(args) == 0 {
		return true
	}

	cmd, subCmd := ExtractCommand(args)
	if cmd == "" {
		return true
	}

	if subs, ok := safeSubcommands[cmd]; ok {
		if subCmd == "" {
			return true // bare command prints help
		}
		return subs[subCmd]
	}

	return safeCommands[cmd]
}

// IsDryRun reports whether args run kubectl in dry-run mode (--dry-run=client
// or =server, or a bare --dry-run). --dry-run=none/=false are not dry-runs.
func IsDryRun(args []string) bool {
	return ParseArgs(args).IsDryRun()
}

// IsStateAltering returns true if the command modifies cluster state.
func IsStateAltering(args []string) bool {
	if len(args) == 0 {
		return false
	}

	cmd, subCmd := ExtractCommand(args)
	if cmd == "" {
		return false
	}

	if subs, ok := safeSubcommands[cmd]; ok {
		if subCmd == "" {
			return false // bare command prints help
		}
		_, safe := subs[subCmd]
		return !safe
	}

	return stateAlteringCommands[cmd]
}

// IsDiffable reports whether a command can be previewed with `kubectl diff`:
// it must apply a manifest (apply/create/replace with a -f/-k source), so there
// is something to diff. delete/scale/exec/patch have no manifest to diff and
// are skipped.
func IsDiffable(args []string) bool {
	cmd, _ := ExtractCommand(args)
	switch cmd {
	case "apply", "create", "replace":
	default:
		return false
	}
	p := ParseArgs(args)
	return len(p.Filenames) > 0 || p.Kustomize != ""
}

// DiffArgs returns a copy of args with the kubectl verb replaced by "diff",
// preserving global flags (--context, -n, -f, ...), suitable for `kubectl diff`.
// It returns nil if no verb token is found before the "--" separator.
func DiffArgs(args []string) []string {
	p := ParseArgs(args)
	if p.VerbIndex < 0 {
		return nil
	}
	out := make([]string, len(args))
	copy(out, args)
	out[p.VerbIndex] = "diff"
	return out
}

// GetCommandDescription returns a human-readable description of the command.
func GetCommandDescription(args []string) string {
	cmd, subCmd := ExtractCommand(args)
	if subCmd != "" {
		return cmd + " " + subCmd
	}
	return cmd
}

// HasUninspectableSource reports whether args read manifests from stdin, a
// URL, or a kustomize directory (sources the guard cannot scan).
func HasUninspectableSource(args []string) bool {
	return ParseArgs(args).HasUninspectableSource()
}

// MatchesProtectedResource reports whether args target a protected resource,
// either via an explicit resource token, an inspectable -f file/dir whose kind
// is protected, or an un-inspectable source (-f -, URL, -k) when resource
// protection is active (we cannot prove it is safe, so we block).
func MatchesProtectedResource(cfg ProtectedResourceChecker, args []string) bool {
	if cfg == nil || !cfg.HasProtectedResources() {
		return false
	}
	p := ParseArgs(args)
	for _, cand := range p.ResourceCandidates() {
		// G5: kubectl accepts comma-separated resource lists like
		// "secret,configmap"; match each part independently.
		for _, part := range strings.Split(cand, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// G7: "all" / "*" span every resource type, including protected
			// ones, so they are blocked when any resource is protected.
			lc := strings.ToLower(part)
			if lc == "all" || lc == "*" {
				return true
			}
			if cfg.IsResourceProtected(part) {
				return true
			}
		}
	}
	for _, f := range p.InspectableFilenames() {
		if pathContainsProtectedKind(f, cfg) {
			return true
		}
	}
	// Conservative: an active resource block plus an un-scannable source must
	// be treated as a potential match.
	if p.HasUninspectableSource() {
		return true
	}
	return false
}

// pathContainsProtectedKind reports whether the given path (a regular file or
// a directory, the latter covering "-f dir" / "-Rf dir") contains a manifest
// whose kind is protected. Directories are walked recursively so that a secret
// nested in an applied directory is caught.
//
// NOTE: there is an inherent TOCTOU window between this scan and kubectl's own
// read (kubectl re-opens the file after we exec it). The threat model is
// accidental commands, not a determined adversary who swaps a symlink between
// the two reads; a full fix would require buffering and re-injecting the file
// contents, which is out of scope.
func pathContainsProtectedKind(path string, cfg ProtectedResourceChecker) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		found := false
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if fileContainsProtectedKind(p, cfg) {
				found = true
				return filepath.SkipAll
			}
			return nil
		})
		return found
	}
	return fileContainsProtectedKind(path, cfg)
}

// fileContainsProtectedKind reports whether a single regular file is a
// YAML/JSON manifest (possibly multi-document) whose kind is protected.
func fileContainsProtectedKind(path string, cfg ProtectedResourceChecker) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, doc := range bytes.Split(data, []byte("\n---")) {
		var meta struct {
			Kind string `yaml:"kind"`
		}
		if yaml.Unmarshal(doc, &meta) == nil && meta.Kind != "" {
			if cfg.IsResourceProtected(meta.Kind) {
				return true
			}
		}
	}
	return false
}
