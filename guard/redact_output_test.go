package guard

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// redact runs RedactStructuredStream over in and returns the output string.
func redact(t *testing.T, in, format string) string {
	t.Helper()
	var out bytes.Buffer
	if err := RedactStructuredStream(strings.NewReader(in), &out, format); err != nil {
		t.Fatalf("RedactStructuredStream(%s) error: %v", format, err)
	}
	return out.String()
}

// decodeYAML/decodeJSON parse output back into a generic value for assertions.
func decodeYAML(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("output is not valid YAML: %v\n%s", err, s)
	}
	return m
}

func decodeJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, s)
	}
	return m
}

func TestRedactSecretYAML(t *testing.T) {
	in := `apiVersion: v1
kind: Secret
metadata:
  name: db-creds
  namespace: prod
type: Opaque
data:
  password: aHVudGVyMg==
  username: YWRtaW4=
stringData:
  token: plaintext-token
`
	out := redact(t, in, "yaml")
	// The raw secret values must be gone.
	for _, secret := range []string{"aHVudGVyMg==", "YWRtaW4=", "plaintext-token"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret value %q survived redaction:\n%s", secret, out)
		}
	}
	m := decodeYAML(t, out)
	data, _ := m["data"].(map[string]any)
	if len(data) != 2 || data["password"] != RedactedMarker || data["username"] != RedactedMarker {
		t.Errorf("data not blanked (keys must remain): %v", data)
	}
	sd, _ := m["stringData"].(map[string]any)
	if sd["token"] != RedactedMarker {
		t.Errorf("stringData not blanked: %v", sd)
	}
	// Non-secret fields intact.
	if m["type"] != "Opaque" {
		t.Errorf("type changed: %v", m["type"])
	}
	meta, _ := m["metadata"].(map[string]any)
	if meta["name"] != "db-creds" || meta["namespace"] != "prod" {
		t.Errorf("metadata changed: %v", meta)
	}
}

func TestRedactPodYAML(t *testing.T) {
	in := `apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  initContainers:
  - name: init
    env:
    - name: INIT_SECRET
      value: init-literal-secret
  containers:
  - name: main
    env:
    - name: DB_PASSWORD
      value: super-secret
    - name: FROM_REF
      valueFrom:
        secretKeyRef:
          name: db
          key: password
  ephemeralContainers:
  - name: debug
    env:
    - name: EPH_SECRET
      value: ephemeral-secret
`
	out := redact(t, in, "yaml")
	for _, secret := range []string{"init-literal-secret", "super-secret", "ephemeral-secret"} {
		if strings.Contains(out, secret) {
			t.Errorf("literal env value %q survived redaction:\n%s", secret, out)
		}
	}
	// valueFrom must be untouched.
	if !strings.Contains(out, "secretKeyRef") || !strings.Contains(out, "key: password") {
		t.Errorf("valueFrom reference was corrupted:\n%s", out)
	}
	if strings.Count(out, RedactedMarker) != 3 {
		t.Errorf("want 3 redacted literal env values, got %d:\n%s", strings.Count(out, RedactedMarker), out)
	}
}

// TestRedactEmptyStreamNoError: an empty stdout (a NotFound-by-name
// `get x y -o yaml`) must not error — closing a yaml.Encoder that never received a
// document used to surface a spurious "yaml: expected STREAM-START" warning.
func TestRedactEmptyStreamNoError(t *testing.T) {
	for _, format := range []string{"yaml", "json"} {
		var out strings.Builder
		if err := RedactStructuredStream(strings.NewReader(""), &out, format); err != nil {
			t.Errorf("%s: empty stream returned error %v, want nil", format, err)
		}
		if out.String() != "" {
			t.Errorf("%s: empty stream produced output %q, want empty", format, out.String())
		}
	}
}

// TestRedactLastAppliedAnnotation: the kubectl.kubernetes.io/last-applied-
// configuration annotation (a plaintext JSON mirror of the whole object that
// `kubectl apply` writes) must be blanked on a redacted kind — otherwise the
// secret it mirrors survives redaction verbatim.
func TestRedactLastAppliedAnnotation(t *testing.T) {
	cases := map[string]string{
		"Secret":     "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n  annotations:\n    kubectl.kubernetes.io/last-applied-configuration: '{\"data\":{\"password\":\"U0VOVElORUw=\"}}'\ndata:\n  password: U0VOVElORUw=\n",
		"Deployment": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  annotations:\n    kubectl.kubernetes.io/last-applied-configuration: '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"env\":[{\"value\":\"U0VOVElORUw=\"}]}]}}}}'\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        env:\n        - name: K\n          value: U0VOVElORUw=\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			out := redact(t, doc, "yaml")
			if strings.Contains(out, "U0VOVElORUw=") {
				t.Errorf("%s: secret survived in the last-applied annotation:\n%s", name, out)
			}
			if !strings.Contains(out, "last-applied-configuration: '"+RedactedMarker+"'") {
				t.Errorf("%s: last-applied annotation not blanked:\n%s", name, out)
			}
		})
	}
	// A ConfigMap's last-applied annotation is NOT touched (we only redact known
	// secret-bearing kinds).
	cm := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  annotations:\n    kubectl.kubernetes.io/last-applied-configuration: '{\"data\":{\"k\":\"v\"}}'\ndata:\n  k: v\n"
	if out := redact(t, cm, "yaml"); !strings.Contains(out, "\\\"k\\\":\\\"v\\\"") && !strings.Contains(out, `"k":"v"`) {
		t.Errorf("ConfigMap last-applied annotation should be untouched:\n%s", out)
	}
}

// TestRedactWorkloadPodTemplates: env[].value literals inside a workload
// controller's pod template (Deployment/StatefulSet/DaemonSet/ReplicaSet/Job at
// spec.template.spec, CronJob at spec.jobTemplate.spec.template.spec) are redacted
// too — otherwise `get deployment -o yaml` would leak what `get pod` redacts.
func TestRedactWorkloadPodTemplates(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"Deployment", "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        env:\n        - name: K\n          value: LEAK\n"},
		{"StatefulSet", "apiVersion: apps/v1\nkind: StatefulSet\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        env:\n        - name: K\n          value: LEAK\n"},
		{"DaemonSet", "apiVersion: apps/v1\nkind: DaemonSet\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        env:\n        - name: K\n          value: LEAK\n"},
		{"Job", "apiVersion: batch/v1\nkind: Job\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        env:\n        - name: K\n          value: LEAK\n"},
		{"CronJob", "apiVersion: batch/v1\nkind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - name: c\n            env:\n            - name: K\n              value: LEAK\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := redact(t, tc.doc, "yaml")
			if strings.Contains(out, "LEAK") {
				t.Errorf("%s pod-template env value leaked:\n%s", tc.name, out)
			}
			if strings.Count(out, RedactedMarker) != 1 {
				t.Errorf("%s: want 1 redacted env value, got %d:\n%s", tc.name, strings.Count(out, RedactedMarker), out)
			}
		})
	}
}

func TestRedactPodJSON(t *testing.T) {
	in := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app"},"spec":{"containers":[{"name":"main","env":[{"name":"DB_PASSWORD","value":"super-secret"},{"name":"REF","valueFrom":{"secretKeyRef":{"name":"db","key":"pw"}}}]}]}}`
	out := redact(t, in, "json")
	if strings.Contains(out, "super-secret") {
		t.Errorf("literal env value survived:\n%s", out)
	}
	if !strings.Contains(out, "secretKeyRef") {
		t.Errorf("valueFrom corrupted:\n%s", out)
	}
	m := decodeJSON(t, out)
	spec := m["spec"].(map[string]any)
	c := spec["containers"].([]any)[0].(map[string]any)
	env := c["env"].([]any)
	if env[0].(map[string]any)["value"] != RedactedMarker {
		t.Errorf("literal env value not blanked: %v", env[0])
	}
	if _, hasVal := env[1].(map[string]any)["value"]; hasVal {
		t.Errorf("valueFrom entry gained a value field: %v", env[1])
	}
}

func TestRedactListEachItem(t *testing.T) {
	for _, kind := range []string{"List", "SecretList"} {
		in := `apiVersion: v1
kind: ` + kind + `
items:
- apiVersion: v1
  kind: Secret
  metadata:
    name: a
  data:
    k: c2VjcmV0QQ==
- apiVersion: v1
  kind: Secret
  metadata:
    name: b
  data:
    k: c2VjcmV0Qg==
`
		out := redact(t, in, "yaml")
		for _, s := range []string{"c2VjcmV0QQ==", "c2VjcmV0Qg=="} {
			if strings.Contains(out, s) {
				t.Errorf("kind %s: item secret %q survived:\n%s", kind, s, out)
			}
		}
		if strings.Count(out, RedactedMarker) != 2 {
			t.Errorf("kind %s: want 2 redactions, got %d", kind, strings.Count(out, RedactedMarker))
		}
	}
}

func TestRedactUnknownKindsUnchanged(t *testing.T) {
	cases := map[string]string{
		"ConfigMap": `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
data:
  password: not-actually-secret-just-a-key-named-password
`,
		"Service": `apiVersion: v1
kind: Service
metadata:
  name: svc
spec:
  clusterIP: 10.0.0.1
`,
		"CRD": `apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: es
spec:
  data:
  - secretKey: token
    remoteRef:
      key: prod/token
`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out := redact(t, in, "yaml")
			if strings.Contains(out, RedactedMarker) {
				t.Errorf("%s was redacted but should be untouched:\n%s", name, out)
			}
			// Content must be preserved (ConfigMap's data value, CRD's remoteRef).
			if name == "ConfigMap" && !strings.Contains(out, "not-actually-secret-just-a-key-named-password") {
				t.Errorf("ConfigMap data value lost:\n%s", out)
			}
			if name == "CRD" && !strings.Contains(out, "prod/token") {
				t.Errorf("CRD content lost:\n%s", out)
			}
		})
	}
}

// TestRedactMalformedFailsOpen: unparseable input passes through UNREDACTED (and,
// for the single-document case, byte-for-byte) rather than being dropped, and does
// not panic.
func TestRedactMalformedFailsOpen(t *testing.T) {
	cases := map[string]struct {
		in     string
		format string
	}{
		"bad yaml":        {"kind: Secret\n\tbad: [unclosed\n", "yaml"},
		"bad json":        {`{"kind":"Secret","data":{`, "json"},
		"not yaml at all": {"this is definitely not: : : valid: [yaml", "yaml"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			// Must not panic; error may be nil (fail-open copies through).
			if err := RedactStructuredStream(strings.NewReader(tc.in), &out, tc.format); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out.String() != tc.in {
				t.Errorf("malformed input not passed through verbatim:\ngot:  %q\nwant: %q", out.String(), tc.in)
			}
		})
	}
}

// TestRedactJSONNumberFidelity: large ints (resourceVersion, metadata.generation)
// round-trip without float corruption thanks to UseNumber.
func TestRedactJSONNumberFidelity(t *testing.T) {
	in := `{"kind":"Secret","metadata":{"name":"s","generation":123456789012345678,"resourceVersion":"987654321098765432"},"data":{"k":"dg=="}}`
	out := redact(t, in, "json")
	if !strings.Contains(out, "123456789012345678") {
		t.Errorf("large integer generation corrupted:\n%s", out)
	}
	if !strings.Contains(out, "987654321098765432") {
		t.Errorf("resourceVersion string corrupted:\n%s", out)
	}
	if strings.Contains(out, "dg==") {
		t.Errorf("secret value survived:\n%s", out)
	}
}

// TestRedactMultiDocYAML: each document of a ---separated stream is handled.
func TestRedactMultiDocYAML(t *testing.T) {
	in := `apiVersion: v1
kind: Secret
metadata:
  name: a
data:
  k: c2VjcmV0MQ==
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
data:
  keep: keepme
---
apiVersion: v1
kind: Secret
metadata:
  name: b
data:
  k: c2VjcmV0Mg==
`
	out := redact(t, in, "yaml")
	for _, s := range []string{"c2VjcmV0MQ==", "c2VjcmV0Mg=="} {
		if strings.Contains(out, s) {
			t.Errorf("secret %q survived multi-doc redaction:\n%s", s, out)
		}
	}
	if !strings.Contains(out, "keepme") {
		t.Errorf("ConfigMap value in multi-doc was lost:\n%s", out)
	}
	if strings.Count(out, RedactedMarker) != 2 {
		t.Errorf("want 2 redactions across docs, got %d:\n%s", strings.Count(out, RedactedMarker), out)
	}
	// Output must remain valid multi-document YAML.
	dec := yaml.NewDecoder(strings.NewReader(out))
	n := 0
	for {
		var v any
		err := dec.Decode(&v)
		if err != nil {
			break
		}
		n++
	}
	if n != 3 {
		t.Errorf("want 3 documents in output, decoded %d:\n%s", n, out)
	}
}

// TestRedactWrongTypedFieldsNoPanic: a Secret whose data is a string (not a map),
// or a Pod whose spec is malformed, is skipped defensively rather than panicking.
func TestRedactWrongTypedFieldsNoPanic(t *testing.T) {
	cases := []string{
		"kind: Secret\ndata: not-a-map\n",
		"kind: Pod\nspec: not-a-map\n",
		"kind: Pod\nspec:\n  containers: not-a-list\n",
		"kind: Pod\nspec:\n  containers:\n  - env: not-a-list\n",
		"kind: Secret\n", // no data at all
	}
	for _, in := range cases {
		var out bytes.Buffer
		if err := RedactStructuredStream(strings.NewReader(in), &out, "yaml"); err != nil {
			t.Errorf("input %q errored: %v", in, err)
		}
	}
}

// TestRedactUnknownFormatPassthrough: a format the redactor does not parse is
// copied through untouched.
func TestRedactUnknownFormatPassthrough(t *testing.T) {
	in := "NAME   READY\nweb    1/1\n"
	out := redact(t, in, "wide")
	if out != in {
		t.Errorf("unknown format not passed through:\ngot  %q\nwant %q", out, in)
	}
}
