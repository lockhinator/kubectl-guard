package guard

import "testing"

func TestParseContextLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected KubectlContext
	}{
		{
			name: "current context with all fields",
			line: "*         prod-cluster       prod-cluster       admin       default",
			expected: KubectlContext{
				Name:      "prod-cluster",
				Cluster:   "prod-cluster",
				AuthInfo:  "admin",
				Namespace: "default",
				Current:   true,
			},
		},
		{
			name: "non-current context with all fields",
			line: "          staging            staging-cluster    developer   staging",
			expected: KubectlContext{
				Name:      "staging",
				Cluster:   "staging-cluster",
				AuthInfo:  "developer",
				Namespace: "staging",
				Current:   false,
			},
		},
		{
			name: "context without namespace",
			line: "          minikube           minikube           minikube",
			expected: KubectlContext{
				Name:     "minikube",
				Cluster:  "minikube",
				AuthInfo: "minikube",
				Current:  false,
			},
		},
		{
			name: "minimal context",
			line: "          docker-desktop",
			expected: KubectlContext{
				Name:    "docker-desktop",
				Current: false,
			},
		},
		{
			name: "eks arn context",
			line: "*         arn:aws:eks:us-east-1:123456789:cluster/prod   arn:aws:eks:us-east-1:123456789:cluster/prod   admin",
			expected: KubectlContext{
				Name:     "arn:aws:eks:us-east-1:123456789:cluster/prod",
				Cluster:  "arn:aws:eks:us-east-1:123456789:cluster/prod",
				AuthInfo: "admin",
				Current:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseContextLine(tt.line)
			if got.Name != tt.expected.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.expected.Name)
			}
			if got.Cluster != tt.expected.Cluster {
				t.Errorf("Cluster = %q, want %q", got.Cluster, tt.expected.Cluster)
			}
			if got.AuthInfo != tt.expected.AuthInfo {
				t.Errorf("AuthInfo = %q, want %q", got.AuthInfo, tt.expected.AuthInfo)
			}
			if got.Namespace != tt.expected.Namespace {
				t.Errorf("Namespace = %q, want %q", got.Namespace, tt.expected.Namespace)
			}
			if got.Current != tt.expected.Current {
				t.Errorf("Current = %v, want %v", got.Current, tt.expected.Current)
			}
		})
	}
}
