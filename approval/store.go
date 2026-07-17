// Package approval implements short-lived, command-bound approval requests.
// Requests contain only a digest and a redacted display string: raw argv may
// carry credentials and is supplied again only when the approval is consumed.
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
	ID        string `json:"id"`
	Digest    string `json:"digest"`
	Command   string `json:"command"`
	Context   string `json:"context,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Target    string `json:"target,omitempty"`
	Actor     string `json:"actor,omitempty"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
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

func Create(args []string, command, context, reason, target, actor string) (Request, error) {
	dir, err := Dir()
	if err != nil {
		return Request{}, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Request{}, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return Request{}, err
	}

	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Request{}, err
	}
	t := now().UTC()
	r := Request{
		ID: strings.ToUpper(hex.EncodeToString(nonce[:])), Digest: Digest(args),
		Command: command, Context: context, Reason: reason, Target: target, Actor: actor,
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
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Request{}, fmt.Errorf("approval request %q was not found or was already consumed", id)
	}
	if err != nil {
		return Request{}, err
	}
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return Request{}, fmt.Errorf("invalid approval request: %w", err)
	}
	if r.ID != normalizeID(id) {
		return Request{}, errors.New("approval request ID does not match its file")
	}
	expires, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil || !now().Before(expires) {
		return Request{}, fmt.Errorf("approval request %s has expired", r.ID)
	}
	return r, nil
}

// Consume atomically claims and removes a request. Calling it before exec makes
// an approval single-use even when kubectl cannot subsequently start.
func Consume(id string) error {
	path, err := requestPath(id)
	if err != nil {
		return err
	}
	claimed := path + ".consumed"
	if err := os.Rename(path, claimed); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("approval request %q was already consumed", id)
		}
		return err
	}
	return os.Remove(claimed)
}

func Verify(r Request, args []string) error {
	if Digest(args) != r.Digest {
		return errors.New("the supplied command does not exactly match the requested command")
	}
	return nil
}

func requestPath(id string) (string, error) {
	id = normalizeID(id)
	if len(id) != 12 {
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
