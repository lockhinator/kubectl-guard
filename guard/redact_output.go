package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// RedactedMarker replaces a KNOWN sensitive field's value. The key is kept so the
// document's shape stays legible; only the value is blanked. Exported so tests
// (and callers) reference the exact string.
const RedactedMarker = "***REDACTED (kubectl-guard)***"

// RedactStructuredStream reads kubectl `get -o json|yaml` output from r, blanks
// KNOWN sensitive fields (Secret data/stringData, container env[].value with a
// literal value), and writes the result to w. format is "json" or "yaml".
//
// It is best-effort defense-in-depth against ACCIDENTAL disclosure (a secret
// scrolling in an agent-captured terminal), explicitly NOT a containment boundary.
// So it FAILS OPEN: a document it cannot parse is passed through UNREDACTED rather
// than dropped — never dropping the user's read is more important than guaranteeing
// a blank, because the user is reading their own data. Any unrecognized format is
// copied through verbatim. It decodes document-at-a-time (never accumulating the
// whole output as parsed structures) and never panics on an unexpected shape.
func RedactStructuredStream(r io.Reader, w io.Writer, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return redactJSONStream(r, w)
	case "yaml", "yml":
		return redactYAMLStream(r, w)
	default:
		// Not a format we parse: pass through untouched (fail-open). The gate in
		// main.go only routes json/yaml here, so this is a belt-and-braces guard.
		_, err := io.Copy(w, r)
		return err
	}
}

// redactJSONStream redacts a single top-level JSON value (kubectl `get -o json`
// emits exactly one document — one object, or one List). UseNumber preserves large
// integers (resourceVersion, metadata.generation) so they round-trip without float
// corruption. On a decode error it fails OPEN: it flushes the bytes the decoder had
// already read plus the untouched remainder, reproducing the original verbatim
// (nothing was emitted yet, so no double-write).
func redactJSONStream(r io.Reader, w io.Writer) error {
	var captured bytes.Buffer
	dec := json.NewDecoder(io.TeeReader(r, &captured))
	dec.UseNumber()

	var doc any
	if err := dec.Decode(&doc); err != nil {
		if _, werr := w.Write(captured.Bytes()); werr != nil {
			return werr
		}
		_, cerr := io.Copy(w, r)
		return cerr
	}

	redactValue(doc)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// captureUntilStop is an io.Writer that records what it is given until stop() is
// called, after which it records nothing and drops what it held. Teed onto the
// YAML decoder's input, it bounds the fail-open capture buffer to the FIRST
// document's bytes: once the first document decodes successfully the stream is
// well-formed, so the buffer is released and never grows again (HARD INVARIANT #5,
// memory bounded — the capture is at most one document, not the whole output).
type captureUntilStop struct {
	buf     bytes.Buffer
	stopped bool
}

func (c *captureUntilStop) Write(p []byte) (int, error) {
	if !c.stopped {
		c.buf.Write(p)
	}
	return len(p), nil
}

func (c *captureUntilStop) stop() {
	c.stopped = true
	c.buf.Reset()
}

// redactYAMLStream redacts each YAML document in r. kubectl `get -o yaml` emits a
// SINGLE document (one object or one List); the multi-document loop is for
// robustness (and a `---`-separated stream). It decodes document-at-a-time, redacts
// the generic value, and re-encodes with 2-space indent (the encoder emits `---`
// between documents).
//
// Fail-open: on a decode error it stops redacting and copies the remainder of r
// through UNREDACTED. For the dominant single-document case this is exact — nothing
// was emitted, and captured + the untouched remainder reproduce the input verbatim.
// (If earlier documents of a MALFORMED multi-document stream were already emitted —
// a shape kubectl `get` does not produce — the failing document's already-buffered
// read-ahead bytes may be dropped from the passthrough; the tail is still copied,
// so the read is not lost.)
func redactYAMLStream(r io.Reader, w io.Writer) error {
	capw := &captureUntilStop{}
	dec := yaml.NewDecoder(io.TeeReader(r, capw))
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	encoded := false // whether any document was written to the encoder

	// closeEnc closes the encoder only when something was encoded. Closing a
	// yaml.Encoder that never received a document returns "yaml: expected
	// STREAM-START"; an EMPTY stdout (a NotFound-by-name `get x y -o yaml` is the
	// common case) must not surface that as a spurious redaction warning.
	closeEnc := func() error {
		if !encoded {
			return nil
		}
		return enc.Close()
	}

	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return closeEnc()
		}
		if err != nil {
			// Flush any emitted docs, then fail open on the rest.
			_ = closeEnc()
			if _, werr := w.Write(capw.buf.Bytes()); werr != nil {
				return werr
			}
			_, cerr := io.Copy(w, r)
			return cerr
		}
		redactValue(doc)
		if eerr := enc.Encode(doc); eerr != nil {
			encoded = true
			_ = enc.Close()
			return eerr
		}
		encoded = true
		// First document decoded cleanly: release the fail-open capture so it does
		// not grow with the rest of the stream.
		capw.stop()
	}
}

// redactValue walks a decoded document (from JSON or YAML — both yield
// map[string]any for objects) and blanks KNOWN sensitive fields IN PLACE. It is
// deliberately narrow: only kinds whose schema the guard knows are touched
// (Secret, Pod, and *List containers of them). Every other kind — ConfigMaps,
// Services, and every CRD (ExternalSecrets, SealedSecrets, ...) — is left
// UNTOUCHED. It never scrubs free text and never heuristically guesses.
//
// Every field access is a checked type assertion, so an unexpected shape (a
// wrong-typed `data`, a string where a list is expected) is skipped rather than
// panicking — a shape the guard does not recognize is passed through, consistent
// with fail-open.
func redactValue(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	kind, _ := m["kind"].(string)

	// A List (kind: List, SecretList, PodList, or any "*List") carries the objects
	// under items[]; recurse into each so a `get secrets`/`get pods` (which returns
	// a List) is redacted item by item.
	if isListKind(kind) {
		if items, ok := m["items"].([]any); ok {
			for _, it := range items {
				redactValue(it)
			}
		}
		return
	}

	switch kind {
	case "Secret":
		redactSecret(m)
		redactLastApplied(m)
	default:
		// A PodSpec is embedded in more than a bare Pod: every workload controller
		// carries one in its pod template, and env[].value there holds the same
		// literal secrets, so `get deployment -o yaml` would otherwise leak what
		// `get pod` redacts. Redact the env at each known kind's template path.
		if path, ok := podSpecPaths[kind]; ok {
			if spec, ok := navigateMap(m, path); ok {
				redactPodSpecContainers(spec)
			}
			redactLastApplied(m)
		}
	}
	// Any other kind (incl. every CRD): untouched.
}

// lastAppliedAnnotation is the annotation `kubectl apply` writes with a JSON
// snapshot of the WHOLE object at apply time.
const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// redactLastApplied blanks the kubectl.kubernetes.io/last-applied-configuration
// annotation on an object we redact. `kubectl apply` stores a plaintext JSON copy
// of the entire object in it — including the very Secret `data` / container
// env[].value we blank elsewhere — so leaving it intact would mirror the redacted
// secret verbatim one screen up (a false sense of safety). Blanking the whole
// annotation value is safe: it is kubectl-internal metadata, not something a user
// re-applies from redacted output. Only applied to the kinds we already redact, so
// a ConfigMap/Service/CRD annotation is untouched.
func redactLastApplied(m map[string]any) {
	meta, ok := m["metadata"].(map[string]any)
	if !ok {
		return
	}
	ann, ok := meta["annotations"].(map[string]any)
	if !ok {
		return
	}
	if _, has := ann[lastAppliedAnnotation]; has {
		ann[lastAppliedAnnotation] = RedactedMarker
	}
}

// podSpecPaths maps a workload kind to the path (a sequence of map keys) from the
// object root to the PodSpec whose containers' env[].value literals are redacted.
// These are stable, KNOWN Kubernetes schemas (not heuristics) — the finite set of
// built-in kinds that embed a PodSpec in a pod template.
var podSpecPaths = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
	"PodTemplate":           {"template", "spec"},
}

// navigateMap walks nested maps following path, returning the map at the end and
// whether every step existed and was a map (a missing/wrong-typed step yields
// false, and the caller skips redaction — fail-open, never a panic).
func navigateMap(m map[string]any, path []string) (map[string]any, bool) {
	cur := m
	for _, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// isListKind reports whether kind names a Kubernetes list wrapper: the generic
// "List", or a typed "<Kind>List" (SecretList, PodList, ...) — both end in "List".
// Matched so the items of any collection response are walked.
func isListKind(kind string) bool {
	return strings.HasSuffix(kind, "List")
}

// redactSecret blanks every value under a Secret's `data` and `stringData` maps,
// keeping the keys so the record still shows WHICH keys existed. Both maps are
// optional and either may be absent or wrong-typed (skipped).
func redactSecret(m map[string]any) {
	for _, field := range []string{"data", "stringData"} {
		sub, ok := m[field].(map[string]any)
		if !ok {
			continue
		}
		for k := range sub {
			sub[k] = RedactedMarker
		}
	}
}

// redactPodSpecContainers blanks the literal `value` of each container env entry
// across a PodSpec's containers, initContainers, and ephemeralContainers. Only an
// env entry that HAS a `value` key (a literal) is blanked; a `valueFrom` reference
// (secretKeyRef, configMapKeyRef, fieldRef) is left alone — it carries no secret
// material inline, and blanking it would corrupt the reference. spec is the
// PodSpec map itself (already navigated to, e.g. Pod.spec or Deployment
// .spec.template.spec).
func redactPodSpecContainers(spec map[string]any) {
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		containers, ok := spec[field].([]any)
		if !ok {
			continue
		}
		for _, c := range containers {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			env, ok := cm["env"].([]any)
			if !ok {
				continue
			}
			for _, e := range env {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if _, has := em["value"]; has {
					em["value"] = RedactedMarker
				}
			}
		}
	}
}
