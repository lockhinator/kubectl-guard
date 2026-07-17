package approval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tempHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestRequestFileSecurityAndIntegrity(t *testing.T) {
	tempHome(t)
	r, err := Create([]string{"delete", "pod", "api"}, "delete pod api", "prod", "", "", "", TargetSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	path, _ := requestPath(r.ID)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(r.ID); err == nil {
		t.Fatal("group/world-readable request loaded")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var stored Request
	if err := json.Unmarshal(b, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Args = []string{"delete", "namespace", "prod"}
	b, _ = json.Marshal(stored)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(r.ID); err == nil {
		t.Fatal("request with argv/digest mismatch loaded")
	}
}

func TestRequestSymlinkAndMalformedJSONRejected(t *testing.T) {
	tempHome(t)
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id := "A1B2C3D4E5F60718293A4B5C6D7E8F90"
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	path, _ := requestPath(id)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(id); err == nil {
		t.Fatal("symlink request loaded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`not-json`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(id); err == nil {
		t.Fatal("malformed request loaded")
	}
}

func TestCreateRejectsUnsafeOrSymlinkedApprovalDirectory(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsafe-mode", true: "symlink"}[symlink], func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			dir, _ := Dir()
			if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
				t.Fatal(err)
			}
			if symlink {
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Create([]string{"delete", "pod", "api"}, "", "", "", "", "", TargetSnapshot{}); err == nil {
				t.Fatal("request created in untrusted directory")
			}
		})
	}
}

func TestConsumeIsAtomicUnderConcurrency(t *testing.T) {
	tempHome(t)
	r, err := Create([]string{"delete", "pod", "api"}, "delete pod api", "prod", "", "", "", TargetSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 16
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- Consume(r.ID) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful consumers=%d, want exactly 1", success)
	}
}

func TestRequestExactMatchAndSingleUse(t *testing.T) {
	tempHome(t)
	args := []string{"delete", "pod", "api", "--context", "prod"}
	r, err := Create(args, "delete pod api", "prod", "protected context", "prod", "agent", TargetSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(loaded, args); err != nil {
		t.Fatal(err)
	}
	if err := Verify(loaded, append(args, "--all")); err == nil {
		t.Fatal("modified command matched")
	}
	if err := Consume(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(r.ID); err == nil {
		t.Fatal("consumed request still loads")
	}
}

func TestDigestHasArgumentBoundaries(t *testing.T) {
	if Digest([]string{"ab", "c"}) == Digest([]string{"a", "bc"}) {
		t.Fatal("digest ignored argv boundaries")
	}
}

func TestExpiredRequestRejected(t *testing.T) {
	tempHome(t)
	original := now
	defer func() { now = original }()
	base := time.Now()
	now = func() time.Time { return base }
	r, err := Create([]string{"delete", "pod", "x"}, "delete pod x", "prod", "", "", "", TargetSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	now = func() time.Time { return base.Add(DefaultTTL + time.Second) }
	if _, err := Load(r.ID); err == nil {
		t.Fatal("expired request loaded")
	}
	path, _ := requestPath(r.ID)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired request not removed: %v", err)
	}
	_ = os.RemoveAll(os.Getenv("HOME"))
}

func TestClaimRevalidatesExpiryAtAtomicBoundary(t *testing.T) {
	tempHome(t)
	original := now
	defer func() { now = original }()
	base := time.Now()
	now = func() time.Time { return base }
	r, err := Create([]string{"delete", "pod", "x"}, "delete pod x", "prod", "", "", "", TargetSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(r.ID); err != nil {
		t.Fatal(err)
	}
	now = func() time.Time { return base.Add(DefaultTTL + time.Second) }
	if _, err := Claim(r.ID); err == nil {
		t.Fatal("claim accepted a request that expired after its initial load")
	}
	if _, err := Load(r.ID); err == nil {
		t.Fatal("expired claimed request remained reusable")
	}
}
