// Package approval implements short-lived, command-bound approval requests.
// Requests are short-lived and mode 0600. Raw argv is retained so the human can
// approve by opaque ID without copying agent-controlled text into a shell.
package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultTTL = 10 * time.Minute

type Request struct {
	ID             string         `json:"id"`
	Digest         string         `json:"digest"`
	Command        string         `json:"command"`
	Context        string         `json:"context,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Target         string         `json:"target,omitempty"`
	Actor          string         `json:"actor,omitempty"`
	Args           []string       `json:"args"`
	TargetSnapshot TargetSnapshot `json:"target_snapshot"`
	CreatedAt      string         `json:"created_at"`
	ExpiresAt      string         `json:"expires_at"`
}

var now = time.Now

func Digest(args []string) string {
	h := sha256.New()
	var n [8]byte
	for _, arg := range args {
		binary.BigEndian.PutUint64(n[:], uint64(len(arg)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(arg))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".kubectl-guard", "approvals"), nil
}

func Create(args []string, command, context, reason, target, actor string, snapshot TargetSnapshot) (Request, error) {
	dir, err := Dir()
	if err != nil {
		return Request{}, err
	}
	if err := ensureSecureDir(dir); err != nil {
		return Request{}, err
	}
	if err := PruneExpired(); err != nil {
		return Request{}, err
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Request{}, err
	}
	t := now().UTC()
	r := Request{
		ID: strings.ToUpper(hex.EncodeToString(nonce[:])), Digest: Digest(args),
		Command: command, Context: context, Reason: reason, Target: target, Actor: actor,
		Args: append([]string(nil), args...), TargetSnapshot: snapshot,
		CreatedAt: t.Format(time.RFC3339), ExpiresAt: t.Add(DefaultTTL).Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Request{}, err
	}
	tmp, err := os.CreateTemp(dir, ".request-*")
	if err != nil {
		return Request{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return Request{}, err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return Request{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Request{}, err
	}
	if err := tmp.Close(); err != nil {
		return Request{}, err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, r.ID+".json")); err != nil {
		return Request{}, err
	}
	return r, nil
}

func Load(id string) (Request, error) {
	path, err := requestPath(id)
	if err != nil {
		return Request{}, err
	}
	return loadRequestFile(path, normalizeID(id), true)
}

func loadRequestFile(path, expectedID string, removeExpired bool) (Request, error) {
	if err := checkSecureFile(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Request{}, fmt.Errorf("approval request %q was not found or was already consumed", expectedID)
		}
		return Request{}, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Request{}, fmt.Errorf("approval request %q was not found or was already consumed", expectedID)
	}
	if err != nil {
		return Request{}, err
	}
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return Request{}, fmt.Errorf("invalid approval request: %w", err)
	}
	if r.ID != expectedID {
		return Request{}, errors.New("approval request ID does not match its file")
	}
	expires, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil || !now().Before(expires) {
		if removeExpired {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				return Request{}, fmt.Errorf("approval request %s expired but could not be removed: %w", r.ID, removeErr)
			}
		}
		return Request{}, fmt.Errorf("approval request %s has expired", r.ID)
	}
	if Digest(r.Args) != r.Digest {
		return Request{}, errors.New("approval request digest does not match stored argv")
	}
	return r, nil
}

func PruneExpired() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 || e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if checkSecureFile(path) != nil {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var r Request
		if json.Unmarshal(b, &r) != nil {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("removing malformed approval request %s: %w", path, err)
			}
			continue
		}
		expires, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err == nil && !now().Before(expires) {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("removing expired approval request %s: %w", path, err)
			}
		}
	}
	return nil
}

// Claim atomically takes a request, validates its contents and expiry at the
// single-use boundary, then removes the claimed artifact.
func Claim(id string) (Request, error) {
	path, err := requestPath(id)
	if err != nil {
		return Request{}, err
	}
	claimed := path + ".consumed"
	if err := os.Rename(path, claimed); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Request{}, fmt.Errorf("approval request %q was already consumed", id)
		}
		return Request{}, err
	}
	defer os.Remove(claimed)
	r, err := loadRequestFile(claimed, normalizeID(id), false)
	if err != nil {
		return Request{}, err
	}
	if err := os.Remove(claimed); err != nil {
		return Request{}, err
	}
	return r, nil
}

func Consume(id string) error {
	_, err := Claim(id)
	return err
}

func Verify(r Request, args []string) error {
	if Digest(args) != r.Digest {
		return errors.New("the supplied command does not exactly match the requested command")
	}
	return nil
}

func requestPath(id string) (string, error) {
	id = normalizeID(id)
	if len(id) != 32 {
		return "", errors.New("invalid approval request ID")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", errors.New("invalid approval request ID")
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, id+".json"), nil
}

func normalizeID(id string) string { return strings.ToUpper(strings.TrimSpace(id)) }
