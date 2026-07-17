package approval

import (
	"os"
	"testing"
	"time"
)

func tempHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestRequestExactMatchAndSingleUse(t *testing.T) {
	tempHome(t)
	args := []string{"delete", "pod", "api", "--context", "prod"}
	r, err := Create(args, "delete pod api", "prod", "protected context", "prod", "agent")
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
	r, err := Create([]string{"delete", "pod", "x"}, "delete pod x", "prod", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	now = func() time.Time { return base.Add(DefaultTTL + time.Second) }
	if _, err := Load(r.ID); err == nil {
		t.Fatal("expired request loaded")
	}
	_ = os.RemoveAll(os.Getenv("HOME"))
}
