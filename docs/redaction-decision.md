# Decision: output redaction is out of scope (blocking-only)

**Status:** decided · **Issue:** #76 · **Milestone:** v0.6.0 · **Scope of the
decision:** through v1.0

> **Update (v1.0, #108):** the narrow, opt-in door this note deliberately left
> open (see "What would change our mind") has been implemented as
> `redact_output: structured` (default `off`). It applies ONLY to the one
> argv-decidable shape this note endorsed — a non-interactive `kubectl get -o
> json|yaml` — blanking known secret fields (`Secret.data`/`stringData`, container
> `env[].value` in Pods and workload pod templates). Everything else, including
> every mutation and interactive verb, still hands off via `syscall.Exec`
> untouched. It is defense-in-depth against *accidental* disclosure, **not** a
> containment boundary. The blocking-only stance below remains the default and the
> product's core model; redaction is an explicit opt-in on top of it.

kubectl-guard is a **blocking-only** tool. It decides, from the command line it
is given, whether a command may run — and then gets out of the way. It does not
read, filter, or redact kubectl's output.

This note records why, what the alternative would cost, and what would have to
be true for us to revisit it.

---

## The question

The product's headline is "keep secrets out of the agent's context window." The
only lever the guard has today is refusing whole protected resources:

```bash
kubectl get secret db-creds -o yaml    # blocked: protected resource
```

But secrets leak through commands that are not *about* secrets, and the guard
has nothing to say about them:

```bash
kubectl get pod my-app -o yaml   # env values, mounted secret refs
kubectl logs my-app              # an app logged a token
kubectl describe pod my-app      # sensitive annotations
```

So: is kubectl-guard a blocker, or does 1.0 also need to scrub secret-looking
values out of otherwise-legitimate output?

## The architectural blocker

`guard.ExecKubectl` (`guard/guard.go`) hands off with `syscall.Exec`. That
system call **replaces the guard's process image with kubectl's**. There is no
parent left, no pipe, no buffer. stdin, stdout, stderr, the controlling
terminal, the process group, and the exit code are all inherited by kubectl
exactly as if the guard had never run.

That is the reason the guard is invisible today, and it is also the reason it
cannot see a single byte of output. Redaction requires abandoning
`syscall.Exec` for `exec.Cmd` with piped stdio, so the guard survives as a
parent process and relays output through itself.

Everything below follows from that one change.

---

## Architecture cost of dropping `syscall.Exec`

### Throughput: not the problem

Measured on this repo's dev machine (darwin/arm64, Go 1.25), draining 48 MB of
subprocess stdout through an `exec.Cmd` pipe costs **~12 ms** versus a
`syscall.Exec` passthrough. Line-scanning that same stream with a
`bufio.Scanner` — i.e. actually looking at every byte, not just discarding it —
costs **~17 ms**. Copying and scanning bytes is cheap. Anyone arguing against
redaction on raw-throughput grounds is arguing against the wrong thing.

### Structured parsing: expensive, and it is the only *sound* approach

The cheap part is copying. The expensive part is understanding. Structured
redaction means unmarshalling the output before you can decide which fields to
blank. Parsing a **6.3 MB** `kubectl get pods -o yaml`-shaped document with
`gopkg.in/yaml.v3` takes **376 ms and allocates 219 MB of heap** — a ~35×
memory amplification over the input.

`kubectl get pods -A -o yaml` on a large cluster is routinely tens of MB. A
guard that redacts it would add hundreds of milliseconds and a multi-hundred-MB
allocation spike to a command that is, today, free. This is the same buffering
concern that motivated #25 (streaming manifests), except that here it is on the
hot path of every read.

### Interactive commands: cannot be redacted, must stay pass-through

Several gated verbs are interactive and require a real terminal. Verified
against `kubectl` v1.33:

| Command | Why it resists redaction |
|---|---|
| `kubectl exec -it` (`-i, --stdin`, `-t, --tty`) | Raw terminal stream; needs a PTY. Not parseable. |
| `kubectl attach -it` | Same. |
| `kubectl edit` | Spawns `$KUBE_EDITOR`/`$EDITOR` (falls back to `vi`) as a child on the same terminal. |
| `kubectl logs -f` (`-f, --follow`) | Unbounded live stream; no document boundary to parse. |
| `kubectl port-forward`, `kubectl proxy` | Long-lived; the payload never passes through kubectl's stdout at all. |

To keep these working, the guard would have to allocate a PTY (a new
dependency), forward `SIGINT`/`SIGWINCH`, and proxy terminal resize events —
and having done all that, it *still* cannot redact them, because a raw terminal
stream carries no structure to redact. They would remain pass-through. The work
buys nothing for exactly the verbs that are the most direct exfiltration path.

### Exit-code and signal fidelity: recoverable, but hand-written

Exit codes survive via `cmd.ProcessState.ExitCode()`. Signal semantics do not
come for free: the guard becomes a process in the middle and must forward
signals and reproduce the exit-on-signal convention (`128+N`) itself. Every one
of these is a place to introduce a bug in a tool whose value proposition is
that it is invisible.

---

## Detection approach

### Structured redaction (parse `-o json|yaml`, blank known fields)

Low false-positive rate. Works only where the guard knows the schema:
`Secret.data` / `.stringData`, `PodSpec.containers[].env[].value`. It cannot
know a CRD's sensitive fields — and CRDs are exactly where secrets increasingly
live (ExternalSecrets, SealedSecrets, ArgoCD repo credentials). It also only
applies when the user asked for a machine format. `kubectl describe` and the
default table output would need per-kind renderers.

### Heuristic scrubbing (entropy / regex over arbitrary text)

The only option for `logs` and `describe`, and it is bad at both ends.
High-entropy strings in real kubectl output include image digests
(`sha256:…`), UIDs, `resourceVersion`, bearer-token *prefixes* in error
messages, and base64 CA bundles. Blanking those destroys the output's utility.
Meanwhile a password like `hunter2` has no entropy signature at all and sails
through. We would be trading a large, visible false-positive cost for a small,
invisible false-negative reduction.

---

## The decisive argument: redaction is a speed bump, not a boundary

The guard's authority comes from the fact that it sees the *argv* and can make
a decision with certainty before anything runs. Redaction gives up that
certainty: it becomes a guess about the contents of a stream.

And within the set of commands the guard *does* see, it is a guess that is
trivially routed around. Each of these reaches the same bytes through kubectl,
under the guard, without ever producing output that a redactor could recognize:

- `kubectl get --raw /api/v1/namespaces/default/secrets/db-creds`
- `kubectl proxy`, then `curl` the API directly
- `kubectl exec pod -- cat /var/run/secrets/…/token`

Note the scope of that claim. It is deliberately **not** "a determined attacker
can bypass the guard entirely" — of course they can: they can `import client-go`,
or invoke the real kubectl by absolute path. But that argument proves too much,
because it defeats the guard's *blocking* exactly as thoroughly as it defeats
redaction. The guard has never claimed to be an access-control boundary against
a determined adversary; its stated threat model is accidental and unsupervised
commands (see `guard/commands.go`, and the README's "Not an access-control
boundary"). Both features live inside that threat model, and neither is
weakened by leaving it.

The distinction that actually separates them is **decidability**, and its
consequence, **false confidence**:

A blocked command is a **decision**. The guard read the argv, matched a rule,
and refused; the request never reached the API server. It is right or wrong for
a reason the user can inspect and configure. A redacted output is a **guess**
about the contents of a stream — and one whose three sibling paths above the
guard *already gates by name*, precisely because those are decidable from argv:

- `--raw` is blocked while resource protection is active.
- `proxy` / `port-forward` are gated as access vectors.
- `exec` / `cp` / `attach` gating is being extended to every context (#73).

So redaction would add a probabilistic filter over one output path, next to a
set of deterministic gates over the others. It would catch some accidental
disclosure — and it would invite users to believe the tool guarantees secrets
never reach their terminal, which it would not. A guarantee a security tool
cannot keep is worse than an absence it documents.

---

## Decision

**kubectl-guard is blocking-only through 1.0. `syscall.Exec` stays.**

Output redaction is a deliberate non-goal, recorded in the README's
"Limitations" section so no user infers a guarantee the tool does not make.

The guard's contract is precise, and worth stating exactly:

> If a command *names* a protected resource, or *targets* a protected
> context/namespace, or *reaches into* a workload, the guard sees that in the
> arguments and acts before anything runs. Once a command is allowed, its
> output is between the user and the API server.

## Revisit criteria

A future scoped mode — `redact_output: off | structured` — is worth building
only if it stays on the *decidable* side of the line. The shape would be:

- Engage **only** when the command is a non-interactive read with a structured
  output format the guard can parse (`get … -o json|yaml`). This is decidable
  from argv, but not yet *decided*: `ParseArgs` currently consumes the value of
  `-o`/`--output` without storing it (it does so only to keep the value from
  landing in verb position). Capturing the format onto `ParsedArgs` is part of
  the #108 work, not a facility that already exists.
- Use `exec.Cmd` **only on that path**. Every other command — every mutation,
  every interactive verb, every table read — keeps `syscall.Exec`, so the
  fidelity and performance costs above are never paid by anyone who did not opt
  in to exactly this.
- Redact only known schemas. Never heuristically scrub free text.
- Document it as defense-in-depth against *accidental* disclosure, never as a
  containment boundary.

That work is tracked as a post-1.0 follow-up in **#108**. It is not a 1.0
requirement, and 1.0 should not wait for it.

---

## References

- Issue #76 (this decision) · #108 (post-1.0 scoped redaction follow-up)
- #25 (streaming manifests — same buffering concern) · #73 (exec/cp as
  sensitive access)
- `guard/guard.go` — `ExecKubectl`, the `syscall.Exec` handoff
- Measurements reproduced with Go 1.25 / `gopkg.in/yaml.v3` v3.0.1
