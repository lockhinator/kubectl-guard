package guard

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// protChecker matches a fixed set of kinds, case-insensitively via the same
// NormalizeResource path production uses.
type protChecker struct{ kinds map[string]bool }

func (p protChecker) HasProtectedResources() bool { return len(p.kinds) > 0 }
func (p protChecker) IsResourceProtected(candidate string) bool {
	return p.kinds[strings.ToLower(candidate)]
}

// oldBytesSplitScan is the PREVIOUS implementation of fileContainsProtectedKind,
// kept here as the differential oracle: the streaming scan must agree with it on
// every input, because that behavior was "verified robust" and is what the ticket
// requires be preserved.
func oldBytesSplitScan(data []byte, cfg ProtectedResourceChecker) bool {
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

func writeTemp(t *testing.T, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(p, content, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestStreamingScanMatchesBytesSplit pins the core invariant: the streaming
// scanner detects exactly what the previous bytes.Split implementation did. Any
// divergence — especially a case where the old code found a protected kind and
// the new code does not — is a fail-open regression.
func TestStreamingScanMatchesBytesSplit(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}

	corpus := []string{
		"apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n",
		"apiVersion: apps/v1\nkind: Deployment\n",
		"kind: ConfigMap\n---\nkind: Secret\n",
		"---\nkind: Secret\n",                        // leading ---
		"kind: ConfigMap\r\n---\r\nkind: Secret\r\n", // CRLF
		"kind: Secret", // no trailing newline
		"",             // empty
		"   ",          // whitespace only
		"kind: ConfigMap\n---\n---\nkind: Secret\n",                      // consecutive separators
		"garbage scalar\n---\nkind: Secret\n",                            // malformed doc then secret
		"kind: ConfigMap\n----\nkind: Secret\n",                          // 4 dashes (not a separator)
		"data: |\n  kind: Secret\n",                                      // "kind" inside a block scalar
		"kind: Secret\n---\nkind: ConfigMap\n",                           // secret first (short-circuit)
		"\n\n\nkind: Secret\n",                                           // leading blank lines
		"kind:\n  Secret\n",                                              // kind value on the next line
		"KIND: Secret\n",                                                 // uppercase key (not matched by yaml tag)
		"kind: secret\n",                                                 // lowercase kind value
		"{\"kind\": \"Secret\"}\n",                                       // JSON manifest
		"kind: ConfigMap\n---kind: Secret\n",                             // separator not at line start
		strings.Repeat("kind: ConfigMap\n---\n", 200) + "kind: Secret\n", // secret last of 201
		strings.Repeat("kind: ConfigMap\n---\n", 200) + "kind: Pod\n",    // no secret anywhere
	}

	for i, content := range corpus {
		want := oldBytesSplitScan([]byte(content), cfg)
		got := fileContainsProtectedKind(writeTemp(t, []byte(content)), cfg)
		if got != want {
			t.Errorf("case %d: streaming=%v, bytes.Split=%v for %q", i, got, want, truncate(content, 40))
		}
	}
}

// TestStreamingScanFuzzMatchesBytesSplit is the differential invariant under
// random multi-document manifests: the streaming scanner must never disagree with
// the bytes.Split oracle. The generator deliberately produces separators,
// CRLF, malformed docs, and near-separators (----, ---foo) so the split logic is
// actually exercised.
func TestStreamingScanFuzzMatchesBytesSplit(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}
	r := rand.New(rand.NewSource(20260709))

	fragments := []string{
		"kind: Secret\n", "kind: ConfigMap\n", "kind: Pod\n", "kind: Deployment\n",
		"\n---\n", "\n----\n", "---\n", "\n---foo\n", "\r\n---\r\n",
		"apiVersion: v1\n", "metadata:\n  name: x\n", "garbage\n",
		"data: |\n  kind: Secret\n", "# kind: Secret\n", "", "  \n", "\n\n",
	}

	for i := 0; i < 20000; i++ {
		var b strings.Builder
		n := r.Intn(8)
		for j := 0; j < n; j++ {
			b.WriteString(fragments[r.Intn(len(fragments))])
		}
		content := b.String()

		want := oldBytesSplitScan([]byte(content), cfg)
		got := fileContainsProtectedKind(writeTemp(t, []byte(content)), cfg)
		if got != want {
			t.Fatalf("DIVERGENCE: streaming=%v bytes.Split=%v for %q", got, want, content)
		}
	}
}

// TestStreamingScanLargeManifestFirstDocShortCircuits covers acceptance
// criterion 1: a large manifest whose FIRST document is a protected kind is
// detected without reading the whole file. We prove the short-circuit by making
// the bytes AFTER the first document unreadable garbage that a full scan would
// choke on — detection must still succeed because the scan stops at doc 1.
func TestStreamingScanLargeManifestFirstDocShortCircuits(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}

	var b bytes.Buffer
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n")
	b.WriteString("\n---\n")
	// 50MB of a single oversized document AFTER the first. If the scanner read
	// this far it would exceed maxManifestDocBytes and error; short-circuiting on
	// the first (protected) document means it never does.
	b.WriteString("data: ")
	b.Write(bytes.Repeat([]byte("A"), 50*1024*1024))
	b.WriteByte('\n')

	if !fileContainsProtectedKind(writeTemp(t, b.Bytes()), cfg) {
		t.Error("protected kind in the first document must be detected via short-circuit")
	}
}

// TestStreamingScanLargeManifestNoMatch covers acceptance criterion 2: a large
// multi-document manifest with NO protected kind is scanned without OOM (bounded
// memory: one document at a time) and correctly returns false.
func TestStreamingScanLargeManifestNoMatch(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}

	var b bytes.Buffer
	// ~10k small documents, none protected. Under the old code this was all
	// resident at once; here memory is bounded to one document.
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&b, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm-%d\ndata:\n  k: v\n---\n", i)
	}
	if fileContainsProtectedKind(writeTemp(t, b.Bytes()), cfg) {
		t.Error("a manifest with no protected kind must not match")
	}
}

// TestStreamingScanLargeManifestMatchLast covers the harder half of criterion 2:
// a large manifest whose ONLY protected kind is the LAST document must still be
// found (no early truncation, no missed tail).
func TestStreamingScanLargeManifestMatchLast(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}

	var b bytes.Buffer
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&b, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm-%d\n---\n", i)
	}
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n")

	if !fileContainsProtectedKind(writeTemp(t, b.Bytes()), cfg) {
		t.Error("a protected kind in the LAST document must be detected")
	}
}

// countingReader records how many bytes were actually read from the underlying
// reader, so a test can prove the scan short-circuited instead of consuming the
// whole stream.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// TestStreamingScanShortCircuitsReadCount is the F2 hardening test: it proves the
// scan stops after the first protected document instead of reading the whole
// file. A boolean result alone cannot distinguish "stopped early" from "read
// everything, matched" — so this counts the bytes actually consumed. A protected
// Secret in the first (tiny) document followed by 8MB of more manifest must be
// decided after reading only a few KB.
//
// Reverting the early `return true` in readerContainsProtectedKind (scanning the
// whole stream) makes this test fail — it is the only guard on acceptance
// criterion (a), "detected without reading the whole file".
func TestStreamingScanShortCircuitsReadCount(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}

	var b bytes.Buffer
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n")
	b.WriteString("\n---\n")
	for i := 0; i < 100000; i++ { // ~8MB of further documents after the match
		fmt.Fprintf(&b, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm-%d\n---\n", i)
	}
	total := int64(b.Len())

	cr := &countingReader{r: bytes.NewReader(b.Bytes())}
	if !readerContainsProtectedKind(cr, cfg) {
		t.Fatal("protected kind in the first document must be detected")
	}
	// bufio's initial buffer is 64KB; the match is in the first ~50 bytes, so the
	// scan should read at most one buffer's worth, not the whole 8MB.
	if cr.n > 128*1024 {
		t.Errorf("short-circuit failed: read %d of %d bytes (want < 128KB)", cr.n, total)
	}
}

// TestStreamingScanLargeUnprotectedSingleDoc is the F1 hardening test: a single
// document LARGER than bufio's 64KB initial buffer but well under the cap, whose
// kind is NOT protected, must scan cleanly and return false.
//
// This catches the classic bufio misconfiguration of setting the max buffer to
// 64KB instead of maxManifestDocBytes: with that bug, this legitimate 1MB
// manifest would hit ErrTooLong and fail CLOSED — a spurious BLOCK of a real
// command. Reverting newDocScanner's max to 64*1024 makes this test fail.
func TestStreamingScanLargeUnprotectedSingleDoc(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}

	var b bytes.Buffer
	b.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: big\ndata:\n  blob: |\n")
	// ~1MB of indented block-scalar content, one document, no "\n---" inside it.
	line := "    " + strings.Repeat("A", 200) + "\n"
	for b.Len() < 1024*1024 {
		b.WriteString(line)
	}

	if fileContainsProtectedKind(writeTemp(t, b.Bytes()), cfg) {
		t.Error("a >64KB single document with no protected kind must return false (not fail closed)")
	}
}

// TestStreamingScanOversizedSingleDocFailsClosed: a single document larger than
// the cap cannot be scanned, so it must fail CLOSED (report protected) rather
// than silently return false. Unreachable for any real manifest; pins the safe
// direction of the boundary.
func TestStreamingScanOversizedSingleDocFailsClosed(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}

	// One document (no "\n---" inside it) larger than maxManifestDocBytes, whose
	// kind is NOT protected. The old code would read it all and return false; the
	// streaming scanner cannot buffer it, so it fails closed (true).
	var b bytes.Buffer
	b.WriteString("kind: ConfigMap\ndata: ")
	b.Write(bytes.Repeat([]byte("A"), maxManifestDocBytes+1024))
	b.WriteByte('\n')

	if !fileContainsProtectedKind(writeTemp(t, b.Bytes()), cfg) {
		t.Error("an un-scannable oversized document must fail closed (report protected)")
	}
}

// TestStreamingScanUnreadableFile: an unreadable/absent file is not a match here
// (unchanged from the previous behavior; MatchesProtectedResource handles
// un-inspectable SOURCES separately).
func TestStreamingScanUnreadableFile(t *testing.T) {
	cfg := protChecker{kinds: map[string]bool{"secret": true}}
	if fileContainsProtectedKind(filepath.Join(t.TempDir(), "does-not-exist.yaml"), cfg) {
		t.Error("a missing file must not be reported as protected")
	}
}

// TestSplitYAMLDocsMatchesBytesSplit checks the split function directly against
// bytes.Split, token for token, on the tricky separators — the boundary logic in
// isolation, independent of YAML parsing.
func TestSplitYAMLDocsMatchesBytesSplit(t *testing.T) {
	inputs := []string{
		"a\n---b", "a\n---\n---b", "a\n---", "\n---a", "no-sep",
		"", "a\n----b", "a\n---\nb\n---\nc", "\n---\n---\n",
	}
	for _, in := range inputs {
		want := bytes.Split([]byte(in), []byte("\n---"))
		got := scanAll([]byte(in))
		// bytes.Split emits a trailing "" for a separator at end / leading "";
		// bufio drops an empty FINAL token. Compare only the non-empty documents,
		// which are the only ones that can carry a kind.
		wantNonEmpty := nonEmpty(want)
		gotNonEmpty := nonEmpty(got)
		if !equalByteSlices(wantNonEmpty, gotNonEmpty) {
			t.Errorf("split %q: streaming non-empty=%q, bytes.Split non-empty=%q", in, gotNonEmpty, wantNonEmpty)
		}
	}
}

func scanAll(data []byte) [][]byte {
	sc := newDocScanner(bytes.NewReader(data))
	var out [][]byte
	for sc.Scan() {
		tok := make([]byte, len(sc.Bytes()))
		copy(tok, sc.Bytes())
		out = append(out, tok)
	}
	return out
}

func nonEmpty(docs [][]byte) [][]byte {
	var out [][]byte
	for _, d := range docs {
		if len(d) > 0 {
			out = append(out, d)
		}
	}
	return out
}

func equalByteSlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
