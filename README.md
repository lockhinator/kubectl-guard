# kubectl-guard

**Keep your secrets out of the context window.**

A CLI wrapper for kubectl that sits between AI agents (and humans) and your cluster, blocking secret reads, gating production mutations, and auditing everything.

> LLMs can run kubectl on your behalf — but they have no "are you sure?" reflex. Whatever they read becomes context, and context leaks: into logs, into transcripts, into a model provider's servers. kubectl-guard is the human-in-the-loop seatbelt for that.

## The problem

When an autonomous agent has cluster access, these are all one command away from a data leak or an outage — and the agent will just *do* them, with no pause for confirmation:

| What the agent does | What actually happens | The risk |
|---|---|---|
| `kubectl get secret db-creds -o yaml` | Secret value printed to stdout | Enters the LLM context → logged, displayed, or sent to the model provider |
| `kubectl exec` → `cat /var/run/secrets` | Same exfiltration via exec | Same leak, harder to spot |
| `kubectl get all` | Secrets included in bulk output | Bulk dump into context |
| `kubectl apply` (a manifest the agent wrote) | Rogue ServiceAccount / backdoor on prod | Agent can grant itself permanent access |
| `kubectl delete deployment api` | Agent misidentifies the cluster | Production outage |

kubectl-guard is the guardrail that catches every one of these — and works just as well for tired, distracted humans.

## Installation

**mise** (recommended) — installs the prebuilt binary from GitHub Releases:

```bash
mise use -g github:lockhinator/kubectl-guard
```

**From source:**

```bash
git clone https://github.com/lockhinator/kubectl-guard
cd kubectl-guard
make install
```

Then add the alias to your shell config (`~/.zshrc` or `~/.bashrc`):

```bash
alias kubectl='kubectl-guard'
```

On first run, kubectl-guard presents an interactive setup wizard to select which contexts to protect:

```
$ kubectl get pods

kubectl-guard: First-time Setup

Select contexts to protect (space to toggle, enter to confirm):

  [ ] docker-desktop
  [ ] minikube
  [x] prod-cluster
  [x] prod-us-east-1

✓ Saved to ~/.kubectl-guard.yaml
```

## Using kubectl-guard with AI agents

The agent-safe setup is two commands:

```bash
# 1. Block all secret access everywhere — the value never leaves the cluster,
#    so it can never enter the context window.
kubectl-guard config add-resource secret

# 2. Require typing the context name to confirm any state change on prod —
#    an autonomous agent cannot satisfy this, so a human must approve.
kubectl-guard config add-context 'prod-*'
kubectl-guard config confirm-mode type-name
```

Now an agent session looks like this:

```
> kubectl get secret stripe-keys -o yaml
⚠️  Blocked: get secret targets a protected resource (context: prod-cluster)
# The agent never sees the secret. It's not in the context window.

> kubectl delete deployment api --context=prod-cluster
⚠️  delete deployment on protected context: prod-cluster
Type "prod-cluster" to confirm (anything else aborts):
# An autonomous agent can't type this — a human must.
```

Every attempt — blocked, aborted, or confirmed — is appended to the audit log (`~/.kubectl-guard-audit.log`), so you have a full record of what your agent tried to do.

By default the audit log captures **every** command the agent runs — including the ones it was allowed to run — not just the ones that were gated. So when Claude shells into your cluster, you get a complete, timestamped record of everything it executed, which is invaluable for post-incident review. Tune this with `config audit-mode` (`all` | `gated` | `off`).

## Protection model

- **Protected contexts** — state-altering commands (`apply`, `delete`, `scale`,
  `exec`, `config use-context`, …) require confirmation. Read-only commands
  (`get`, `describe`, `logs`, `config view`, …) pass through.
- **Protected resources** — any command touching the resource is **blocked
  everywhere** (reads included), regardless of context. Use this to block all
  access to secrets, for example.
- **No bypass** — the `--context` and `--kubeconfig` flags are honored, so
  `kubectl --context=prod delete pod x` is still gated.
- Every command is written to the **audit log** (by default; see
  `audit_mode`), recording who ran it, when, against which context, and the
  guard's decision.

## Protected resources (reference)

[See the agent quickstart](#using-kubectl-guard-with-ai-agents) for the
motivated setup. This section is the complete reference for what gets matched.

Add or remove a protected resource:

```bash
kubectl-guard config add-resource secret      # block all secret access
kubectl-guard config remove-resource secret
```

Once enabled, every command targeting that resource is refused with exit 1 —
reads, writes, and applies alike:

```bash
$ kubectl get secret                          # blocked
$ kubectl get secrets -A                      # plural form also blocked
$ kubectl create secret generic x             # writes blocked
$ kubectl apply -f secret.yaml                # manifests scanned for kind: Secret
$ kubectl get secret,configmap                # comma-separated lists matched per-part
$ kubectl get all                             # "all"/"*" blocked (they span secrets)
```

**What gets matched:**
- Singular/plural forms (`secret` / `secrets`)
- Short names (`cm` → `configmap`, `svc` → `service`, …)
- `type/name` tokens (`secret/db`)
- Comma-separated resource lists (`secret,configmap`)
- `all` and `*` wildcards (blocked whenever any resource is protected)

**Manifest sources:**
- `-f file.yaml` — scanned for `kind:` (multi-document aware)
- `-f dir` / `-Rf dir` — directories walked recursively
- `-f -` (stdin), URLs, and `-k` (kustomize) — cannot be inspected, so they
  are **conservatively blocked** when resource protection is active

Use `kubectl-guard config list` to see which resources are currently protected.

## Configuration

Config file: `~/.kubectl-guard.yaml` (print the exact path with
`kubectl-guard config path`). It is written with `0600` permissions
(owner read/write only) and re-read on every invocation, so it can also be
hand-edited.

```yaml
# kubectl-guard configuration
# Protect production contexts and sensitive resources from accidental commands

protected_contexts:
  - prod-cluster
  - prod-*           # Glob patterns supported
protected_resources:
  - secret           # Blocked on every context
confirm_mode: type-name   # simple (y/N) or type-name (type the context name)
audit_mode: all           # all (default) | gated | off
audit_log: ~/.kubectl-guard-audit.log   # optional; defaults to this path
```

Fields:
- **`protected_contexts`** — glob patterns of contexts that gate
  state-altering commands (require confirmation)
- **`protected_resources`** — resources blocked everywhere, reads included
- **`confirm_mode`** — `simple` (y/N prompt) or `type-name` (type the
  context name to confirm)
- **`audit_mode`** — `all` (default, logs every command including allowed
  passthrough), `gated` (only interventions: blocked/confirmed/aborted/denied),
  or `off` (logs nothing)
- **`audit_log`** — optional override for the audit log path

Manage via CLI:

```bash
kubectl-guard config list                 # Show contexts, resources, modes
kubectl-guard config add-context prod-*   # Protect matching contexts
kubectl-guard config remove-context staging
kubectl-guard config add-resource secret  # Block a resource everywhere
kubectl-guard config remove-resource secret
kubectl-guard config confirm-mode type-name  # Stronger confirmation prompt
kubectl-guard config audit-mode all          # Log every command (default)
kubectl-guard config audit                # Show audit log path + recent entries
kubectl-guard config setup                # Re-run setup wizard
kubectl-guard config path                 # Print config file path
```

## How it works

kubectl-guard is installed as a drop-in alias for `kubectl`. Each invocation
parses the arguments, resolves the target context (honoring `--context`,
`--kubeconfig`, and `KUBECONFIG`), and decides whether to block, prompt, or
pass through — then replaces its own process with the real `kubectl` via
`exec`, so stdout, stdin, and exit codes are preserved exactly.

- **Safe commands** (`get`, `describe`, `logs`, `config view`, `auth can-i`, …)
  pass through without prompts.
- **State-altering commands** (`apply`, `delete`, `scale`, `exec`,
  `config use-context`, `auth reconcile`, …) require confirmation on
  protected contexts.
- **Protected resources** are blocked on every context, including reads.
- Context matching uses glob patterns; resource matching treats
  singular/plural/short-name forms as equivalent.

## Limitations

kubectl-guard is a **client-side guardrail for accidental and unsupervised
commands**, not a substitute for Kubernetes RBAC or network policy. Worth
knowing:

- **Not an access-control boundary.** A determined user can bypass it by
  running the real `kubectl` binary directly or un-aliasing. Use RBAC for
  real enforcement; use kubectl-guard for the "are you sure?" and the audit
  trail.
- **TOCTOU on `-f` files.** There is a small window between the guard
  scanning a manifest and `kubectl` re-reading it. The threat model is
  accidents and unsupervised agents, not an adversary swapping a symlink
  mid-flight.
- **Unknown verbs pass through.** Unrecognized commands (e.g. some plugins)
  are forwarded without a prompt.
- **`-k` kustomize** directories are conservatively blocked when resource
  protection is active, but their contents are not deeply parsed.
