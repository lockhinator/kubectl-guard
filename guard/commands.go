package guard

import (
	"bytes"
	"os"
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

// knownShortFlags are kubectl flags that take a value.
var knownShortFlags = map[string]bool{
	"-n": true, "-l": true, "-f": true, "-o": true, "-c": true,
	"-s": true, "-p": true, "-k": true, "-R": true,
}

// knownLongFlags are kubectl long flags that take a separate value
// (not --flag=value style). --context/--kubeconfig/--filename/--kustomize are
// handled explicitly in ParseArgs and intentionally omitted here.
var knownLongFlags = map[string]bool{
	"--namespace": true, "--selector": true,
	"--output": true, "--container": true,
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

// ParseArgs performs one pass over a kubectl argument list, honoring the "--"
// separator consistently for every consumer. It stops interpreting flags at
// "--", so a trailing "--context=dev" can no longer trick context resolution
// (the S1 bypass), and it stops positional collection there to match kubectl.
func ParseArgs(args []string) ParsedArgs {
	var p ParsedArgs
	skipNext := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
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
			default:
				// Other long flag: skip its value if it's a known value-taker.
				if !hasInline && knownLongFlags[arg] {
					skipNext = true
				}
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			switch arg {
			case "-f":
				if i+1 < len(args) {
					p.Filenames = append(p.Filenames, args[i+1])
					skipNext = true
				}
			case "-k":
				if i+1 < len(args) {
					p.Kustomize = args[i+1]
					skipNext = true
				}
			default:
				if knownShortFlags[arg] {
					skipNext = true
				}
			}
		default:
			p.Positional = append(p.Positional, arg)
		}
	}
	return p
}

// PositionalArgs returns the non-flag arguments before "--". Thin wrapper over
// ParseArgs kept for callers/tests.
func PositionalArgs(args []string) []string {
	return ParseArgs(args).Positional
}

// ExtractCommand extracts the kubectl command and its first subcommand from
// args, ignoring flags.
func ExtractCommand(args []string) (cmd string, subCmd string) {
	pos := PositionalArgs(args)
	if len(pos) >= 1 {
		cmd = pos[0]
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
// either via an explicit resource token, an inspectable -f file whose kind is
// protected, or an un-inspectable source (-f -, URL, -k) when resource
// protection is active (we cannot prove it is safe, so we block).
func MatchesProtectedResource(cfg ProtectedResourceChecker, args []string) bool {
	if cfg == nil || !cfg.HasProtectedResources() {
		return false
	}
	p := ParseArgs(args)
	for _, cand := range p.ResourceCandidates() {
		if cfg.IsResourceProtected(cand) {
			return true
		}
	}
	for _, f := range p.InspectableFilenames() {
		if fileContainsProtectedKind(f, cfg) {
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

// fileContainsProtectedKind reports whether the given file is a regular
// YAML/JSON manifest (possibly multi-document) whose kind is protected.
//
// NOTE: there is an inherent TOCTOU window between this scan and kubectl's own
// read (kubectl re-opens the file after we exec it). The threat model is
// accidental commands, not a determined adversary who swaps a symlink between
// the two reads; a full fix would require buffering and re-injecting the file
// contents, which is out of scope.
func fileContainsProtectedKind(path string, cfg ProtectedResourceChecker) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
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
