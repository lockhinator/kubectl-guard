package guard

import "testing"

func TestExtractCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCmd    string
		wantSubCmd string
	}{
		{
			name:       "simple command",
			args:       []string{"get", "pods"},
			wantCmd:    "get",
			wantSubCmd: "pods",
		},
		{
			name:       "command with flags first",
			args:       []string{"-n", "default", "get", "pods"},
			wantCmd:    "get",
			wantSubCmd: "pods",
		},
		{
			name:       "command with flags in middle",
			args:       []string{"get", "-n", "default", "pods"},
			wantCmd:    "get",
			wantSubCmd: "pods",
		},
		{
			name:       "rollout subcommand",
			args:       []string{"rollout", "restart", "deployment/nginx"},
			wantCmd:    "rollout",
			wantSubCmd: "restart",
		},
		{
			name:       "empty args",
			args:       []string{},
			wantCmd:    "",
			wantSubCmd: "",
		},
		{
			name:       "only flags",
			args:       []string{"-n", "default", "--context", "prod"},
			wantCmd:    "",
			wantSubCmd: "",
		},
		{
			name:       "long flags",
			args:       []string{"--namespace=default", "delete", "pod", "nginx"},
			wantCmd:    "delete",
			wantSubCmd: "pod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, subCmd := ExtractCommand(tt.args)
			if cmd != tt.wantCmd {
				t.Errorf("ExtractCommand() cmd = %q, want %q", cmd, tt.wantCmd)
			}
			if subCmd != tt.wantSubCmd {
				t.Errorf("ExtractCommand() subCmd = %q, want %q", subCmd, tt.wantSubCmd)
			}
		})
	}
}

func TestIsSafeCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		safe bool
	}{
		// Safe commands
		{"get pods", []string{"get", "pods"}, true},
		{"describe pod", []string{"describe", "pod", "nginx"}, true},
		{"logs", []string{"logs", "nginx"}, true},
		{"top nodes", []string{"top", "nodes"}, true},
		{"explain", []string{"explain", "pods"}, true},
		{"api-resources", []string{"api-resources"}, true},
		{"api-versions", []string{"api-versions"}, true},
		{"version", []string{"version"}, true},
		{"cluster-info", []string{"cluster-info"}, true},
		{"config get-contexts", []string{"config", "get-contexts"}, true},
		{"auth can-i", []string{"auth", "can-i", "get", "pods"}, true},
		{"wait", []string{"wait", "--for=condition=ready", "pod/nginx"}, true},
		{"diff", []string{"diff", "-f", "deployment.yaml"}, true},

		// Rollout safe subcommands
		{"rollout status", []string{"rollout", "status", "deployment/nginx"}, true},
		{"rollout history", []string{"rollout", "history", "deployment/nginx"}, true},

		// State-altering commands are not safe
		{"apply", []string{"apply", "-f", "deployment.yaml"}, false},
		{"create", []string{"create", "deployment", "nginx"}, false},
		{"delete", []string{"delete", "pod", "nginx"}, false},
		{"rollout restart", []string{"rollout", "restart", "deployment/nginx"}, false},

		// Edge cases
		{"empty", []string{}, true},
		{"flags only", []string{"-n", "default"}, true},
		{"get with flags", []string{"-n", "default", "get", "pods"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSafeCommand(tt.args)
			if got != tt.safe {
				t.Errorf("IsSafeCommand(%v) = %v, want %v", tt.args, got, tt.safe)
			}
		})
	}
}

func TestIsStateAltering(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		altering bool
	}{
		// State-altering commands
		{"apply", []string{"apply", "-f", "deployment.yaml"}, true},
		{"create", []string{"create", "deployment", "nginx"}, true},
		{"delete", []string{"delete", "pod", "nginx"}, true},
		{"patch", []string{"patch", "deployment", "nginx", "-p", `{"spec":{}}`}, true},
		{"replace", []string{"replace", "-f", "deployment.yaml"}, true},
		{"edit", []string{"edit", "deployment", "nginx"}, true},
		{"scale", []string{"scale", "deployment", "nginx", "--replicas=3"}, true},
		{"rollout restart", []string{"rollout", "restart", "deployment/nginx"}, true},
		{"rollout undo", []string{"rollout", "undo", "deployment/nginx"}, true},
		{"rollout pause", []string{"rollout", "pause", "deployment/nginx"}, true},
		{"rollout resume", []string{"rollout", "resume", "deployment/nginx"}, true},
		{"autoscale", []string{"autoscale", "deployment", "nginx", "--min=2"}, true},
		{"expose", []string{"expose", "deployment", "nginx", "--port=80"}, true},
		{"run", []string{"run", "nginx", "--image=nginx"}, true},
		{"set image", []string{"set", "image", "deployment/nginx", "nginx=nginx:latest"}, true},
		{"label", []string{"label", "pod", "nginx", "env=prod"}, true},
		{"annotate", []string{"annotate", "pod", "nginx", "description=test"}, true},
		{"taint", []string{"taint", "node", "node1", "key=value:NoSchedule"}, true},
		{"drain", []string{"drain", "node1"}, true},
		{"cordon", []string{"cordon", "node1"}, true},
		{"uncordon", []string{"uncordon", "node1"}, true},
		{"exec", []string{"exec", "nginx", "--", "ls"}, true},
		{"cp", []string{"cp", "nginx:/tmp/file", "./file"}, true},
		{"debug", []string{"debug", "nginx"}, true},
		{"attach", []string{"attach", "nginx"}, true},

		// Safe commands are not state-altering
		{"get", []string{"get", "pods"}, false},
		{"describe", []string{"describe", "pod", "nginx"}, false},
		{"logs", []string{"logs", "nginx"}, false},
		{"rollout status", []string{"rollout", "status", "deployment/nginx"}, false},
		{"rollout history", []string{"rollout", "history", "deployment/nginx"}, false},

		// Edge cases
		{"empty", []string{}, false},
		{"delete with flags", []string{"-n", "default", "delete", "pod", "nginx"}, true},
		{"apply with context", []string{"--context=prod", "apply", "-f", "file.yaml"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsStateAltering(tt.args)
			if got != tt.altering {
				t.Errorf("IsStateAltering(%v) = %v, want %v", tt.args, got, tt.altering)
			}
		})
	}
}

func TestGetCommandDescription(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"get", "pods"}, "get pods"},
		{[]string{"rollout", "restart", "deployment"}, "rollout restart"},
		{[]string{"-n", "default", "delete", "pod"}, "delete pod"},
		{[]string{"apply"}, "apply"},
		{[]string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetCommandDescription(tt.args)
			if got != tt.want {
				t.Errorf("GetCommandDescription(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}
