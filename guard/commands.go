package guard

import "strings"

// safeCommands are read-only commands that don't modify cluster state.
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
	"config":        true,
	"auth":          true,
	"wait":          true,
	"diff":          true,
}

// stateAlteringCommands modify cluster state and require confirmation.
var stateAlteringCommands = map[string]bool{
	"apply":     true,
	"create":    true,
	"delete":    true,
	"patch":     true,
	"replace":   true,
	"edit":      true,
	"scale":     true,
	"rollout":   true,
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

// safeRolloutSubcommands are rollout subcommands that don't modify state.
var safeRolloutSubcommands = map[string]bool{
	"status":  true,
	"history": true,
}

// knownShortFlags are kubectl flags that take a value.
var knownShortFlags = map[string]bool{
	"-n": true, "-l": true, "-f": true, "-o": true, "-c": true,
	"-s": true, "-p": true, "-k": true, "-R": true,
}

// knownLongFlags are kubectl long flags that take a separate value (not --flag=value style).
var knownLongFlags = map[string]bool{
	"--context": true, "--namespace": true, "--selector": true,
	"--filename": true, "--output": true, "--container": true,
	"--kubeconfig": true, "--cluster": true, "--user": true,
}

// ExtractCommand extracts the kubectl command from args, ignoring flags.
// Returns the command name and any subcommand.
func ExtractCommand(args []string) (cmd string, subCmd string) {
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		// Skip long flags (--flag or --flag=value)
		if strings.HasPrefix(arg, "--") {
			// If it doesn't contain = and is a known flag that takes a value, skip next arg
			if !strings.Contains(arg, "=") && knownLongFlags[arg] {
				skipNext = true
			}
			continue
		}

		// Skip short flags
		if strings.HasPrefix(arg, "-") {
			// Check if this flag takes a value
			if knownShortFlags[arg] {
				skipNext = true
			}
			continue
		}

		if cmd == "" {
			cmd = arg
		} else {
			subCmd = arg
			break
		}
	}
	return
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

	// Special case: rollout status/history are safe
	if cmd == "rollout" && safeRolloutSubcommands[subCmd] {
		return true
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

	// Special case: rollout status/history are safe
	if cmd == "rollout" && safeRolloutSubcommands[subCmd] {
		return false
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
