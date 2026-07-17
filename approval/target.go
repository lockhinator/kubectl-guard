package approval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type TargetSnapshot struct {
	Context               string `json:"context"`
	Server                string `json:"server"`
	Namespace             string `json:"namespace"`
	KubeconfigFingerprint string `json:"kubeconfig_fingerprint"`
	KubectlPath           string `json:"kubectl_path"`
	KubectlSHA256         string `json:"kubectl_sha256"`
}

func FileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func KubeconfigFingerprint(explicit string) (string, error) {
	value := explicit
	if value == "" {
		value = os.Getenv("KUBECONFIG")
	}
	if value == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		value = filepath.Join(home, ".kube", "config")
	}
	h := sha256.New()
	var n [8]byte
	for _, raw := range filepath.SplitList(value) {
		path, err := filepath.Abs(raw)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("fingerprinting kubeconfig %s: %w", path, err)
		}
		for _, part := range []string{path, string(data)} {
			binary.BigEndian.PutUint64(n[:], uint64(len(part)))
			_, _ = h.Write(n[:])
			_, _ = h.Write([]byte(part))
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s TargetSnapshot) Equal(other TargetSnapshot) bool {
	return s.Context == other.Context && strings.TrimSuffix(strings.ToLower(s.Server), "/") == strings.TrimSuffix(strings.ToLower(other.Server), "/") && s.Namespace == other.Namespace && s.KubeconfigFingerprint == other.KubeconfigFingerprint && s.KubectlPath == other.KubectlPath && s.KubectlSHA256 == other.KubectlSHA256
}
