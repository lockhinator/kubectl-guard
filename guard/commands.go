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
// (not --flag=value style).
var knownLongFlags = map[string]bool{
	"--context": true, "--namespace": true, "--selector": true,
	"--filename": true, "--output": true, "--container": true,
	"--kubeconfig": true, "--cluster": true, "--user": true,
}

// ProtectedResourceChecker is satisfied by *config.Config; kept as an interface
// so command classification stays testable without shelling out.
type ProtectedResourceChecker interface {
	IsResourceProtected(candidate string) bool
}

// PositionalArgs returns the non-flag arguments, skipping values consumed by
// value-taking flags, and stopping at the "--" separator. It is the basis for
// command, subcommand, and resource extraction.
func PositionalArgs(args []string) []string {
	var pos []string
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "--") {
			if !strings.Contains(arg, "=") && knownLongFlags[arg] {
				skipNext = true
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if knownShortFlags[arg] {
				skipNext = true
			}
			continue
		}
		pos = append(pos, arg)
	}
	return pos
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
// Any of these may be a resource type or "type/name" token (e.g. for
// "get secret x", "delete pod nginx", "create secret generic y").
func ExtractResourceCandidates(args []string) []string {
	pos := PositionalArgs(args)
	if len(pos) <= 1 {
		return nil
	}
	return pos[1:]
}

// ExtractFilenames returns the paths supplied via -f / --filename (in any of
// the forms -f x, --filename x, --filename=x). Directories and URLs are
// returned as-is; callers stat them before reading.
func ExtractFilenames(args []string) []string {
	var files []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-f" || arg == "--filename":
			if i+1 < len(args) {
				files = append(files, args[i+1])
				i++
			}
		case strings.HasPrefix(arg, "--filename="):
			files = append(files, strings.TrimPrefix(arg, "--filename="))
		}
	}
	return files
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

// MatchesProtectedResource reports whether args target a protected resource,
// either via an explicit resource token on the command line or via a -f file
// whose kind is protected.
func MatchesProtectedResource(cfg ProtectedResourceChecker, args []string) bool {
	if cfg == nil {
		return false
	}
	for _, cand := range ExtractResourceCandidates(args) {
		if cfg.IsResourceProtected(cand) {
			return true
		}
	}
	for _, f := range ExtractFilenames(args) {
		if fileContainsProtectedKind(f, cfg) {
			return true
		}
	}
	return false
}

// fileContainsProtectedKind reports whether the given file is a regular
// YAML/JSON manifest (possibly multi-document) whose kind is protected.
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
