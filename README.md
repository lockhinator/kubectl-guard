# kubectl-guard

**Keep your secrets out of the context window.**

A CLI wrapper for kubectl that sits between AI agents (and humans) and your cluster, blocking secret reads, gating production mutations, and auditing everything.

> LLMs can run kubectl on your behalf — but they have no "are you sure?" reflex. Whatever they read becomes context, and context leaks: into logs, into transcripts, into a model provider's servers. kubectl-guard is the human-in-the-loop seatbelt for that.

## Features

- **🔒 Secret protection** — Block all secret access across your entire cluster. Secrets never leave the cluster, so they can never enter LLM context windows or logs.
- **🚦 Production gating** — Require explicit confirmation for state-altering commands on production contexts. Type the context name to confirm — something autonomous agents can't do.
- **📋 Comprehensive audit logging** — Every command is logged with timestamps, context, and outcome. Full visibility into what your agents (or you) tried to do.
- **🛡️ No bypass** — Respects `--context` and `--kubeconfig` flags, so even explicit context switches are gated.
- **⚡ Drop-in replacement** — Works as a kubectl alias. No changes to your workflows or agent prompts.
- **🔧 Reliable configuration** — Atomic config writes and concurrent-safe audit logging prevent corruption.
- **🎯 Smart command classification** — Automatically distinguishes safe reads from dangerous mutations, even with uppercase verbs or plugins.

## What's New

### v0.2.1 — Reliability & Security Fixes

- **Atomic config writes** — Configuration files are now written atomically (temp file + rename) to prevent corruption if writes fail mid-flight.
- **Concurrent-safe audit logging** — Audit log writes use file locking to prevent interleaved or corrupted entries under concurrent use.
- **Clean output separation** — Guard messages now route to stderr, keeping stdout clean for kubectl output and piping.
- **Version flag fix** — `-v` now properly forwards to kubectl for verbosity. Use `--version` or `-V` to show kubectl-guard version.
- **Uppercase verb protection** — Commands with uppercase verbs (e.g., `DELETE`, `APPLY`) can no longer bypass context protection.

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

Verify the installation:

```bash
kubectl-guard --version  # or -V
```

#### PATH-shadowing install (agents & non-interactive shells)

The alias above only applies in **interactive** shells. An AI agent or script
that execs `kubectl` by name (or by absolute path) in a non-interactive shell
**bypasses the alias entirely**. For the agent use case, install a
`kubectl` shim that sits **earlier in `PATH`** than the real kubectl:

```bash
make install-shim
```

This installs the guard and a `kubectl` symlink pointing at it under
`~/.local/share/kubectl-guard/shims/`, then prints the `PATH` line to add to
your shell config (`~/.zshrc` or `~/.bashrc`):

```bash
export PATH="$HOME/.local/share/kubectl-guard/shims:$PATH"
```

Reload your shell, then confirm interception is active:

```bash
kubectl-guard doctor
```

When invoked as `kubectl`, the guard runs its protection logic and `exec`s the
**real** kubectl (found by skipping itself on `PATH`), so stdout, stdin, and
exit codes are preserved and there is no infinite loop. This intercepts
`kubectl get secret` even from `bash -c 'kubectl get secret'` or an agent
subprocess.

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

##### Headless / non-interactive setup (CI, agents, no TTY)

The wizard requires a TTY, so in a headless context (CI, a container, an agent
subprocess) it cancels and the command doesn't run. Bootstrap the guard
without a prompt using either **environment variables** or `config init`:

```bash
# Option 1: env vars (take effect on first run when no config exists)
export KUBECTL_GUARD_PROTECTED_CONTEXTS=prod-*,prod-cluster
export KUBECTL_GUARD_PROTECTED_RESOURCES=secret
export KUBECTL_GUARD_CONFIRM_MODE=type-name   # optional: simple|type-name

# Option 2: write the config in one shot
kubectl-guard config init \
  --protected-contexts 'prod-*,prod-cluster' \
  --protected-resources secret \
  --confirm-mode type-name
```

If no config exists and you just want the guard to get out of the way
deterministically (e.g. a CI step that hasn't been configured yet), pass
`--no-prompt` or set `KUBECTL_GUARD_NO_PROMPT=yes`: the guard writes an empty
config (no protection) and proceeds with a stderr warning. A headless
`bash -c 'kubectl-guard get pods'` will not hang or fail.

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

### Identifying who drove a command

Every audit entry records an **`actor`** — *who* drove the command — alongside the OS `user` whose account ran it. Without this, `kubectl get secret` run by Claude and typed by a human look identical in the log. Set `KUBECTL_GUARD_ACTOR` to a short label so agent activity is distinguishable:

```bash
# In your shell, CI step, or agent framework's env config:
export KUBECTL_GUARD_ACTOR=claude-code
# For Claude Code, add it to settings.json under "env"; for Cursor/other
# tools, export it in the session that launches the agent.
```

```jsonl
{"time":"2026-07-09T10:00:00Z","user":"cameron","actor":"claude-code","command":"get secret stripe-keys","outcome":"blocked","reason":"protected-resource"}
```

The actor is resolved in priority order:

1. `KUBECTL_GUARD_ACTOR` env var (explicit opt-in — the clean, portable path).
2. The `actor` field in `~/.kubectl-guard.yaml` (a static default, e.g. for a shared CI host).
3. The OS username (fallback — current behavior).

The OS `user` is always recorded regardless, so you keep full attribution. `config audit` shows the `actor` in recent entries automatically.

## Protection model

- **Protected contexts** — state-altering commands (`apply`, `delete`, `scale`,
  `exec`, `config use-context`, …) require confirmation. Read-only commands
  (`get`, `describe`, `logs`, `config view`, …) pass through.
- **Protected resources** — any command touching the resource is **blocked
  everywhere** (reads included), regardless of context. Use this to block all
  access to secrets, for example.
- **No bypass** — the `--context` and `--kubeconfig` flags are honored, so
  `kubectl --context=prod delete pod x` is still gated.
- **Case-insensitive verbs** — Commands with uppercase verbs (`DELETE`, `APPLY`)
  are normalized and treated the same as lowercase, preventing bypass attempts.
- **Clean output** — Guard messages route to stderr, keeping stdout clean for
  kubectl output and piping to other tools.
- Every command is written to the **audit log** (by default; see
  `audit_mode`), recording who ran it, when, against which context, and the
  guard's decision. Audit log writes are concurrent-safe with file locking.

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
(owner read/write only) using atomic writes (temp file + rename) to prevent
corruption. Config is re-read on every invocation, so it can also be hand-edited.

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
kubectl-guard --version                  # Show version (or -V)
kubectl-guard config list                 # Show contexts, resources, modes
kubectl-guard config add-context prod-*   # Protect matching contexts
kubectl-guard config remove-context staging
kubectl-guard config add-resource secret  # Block a resource everywhere
kubectl-guard config remove-resource secret
kubectl-guard config confirm-mode type-name  # Stronger confirmation prompt
kubectl-guard config audit-mode all          # Log every command (default)
kubectl-guard config audit                # Show audit log path + recent entries
kubectl-guard config setup                # Re-run setup wizard
kubectl-guard config init                 # Write config non-interactively (headless)
kubectl-guard config path                 # Print config file path
```

### Diagnostics

```bash
kubectl-guard doctor                      # Check PATH-shadowing interception
```

`doctor` reports whether `kubectl` on `PATH` resolves to the guard (i.e.
interception is **ACTIVE**), lists every `kubectl` found on `PATH` in order
(like `which -a kubectl`), and prints the resolved path of the **real**
kubectl the guard forwards to. Use it after `make install-shim` to confirm
agents and non-interactive shells are covered.

### Automation escape hatch (audited)

For legitimate automation — a CI/CD pipeline or deploy script that needs to
run a gated command on a protected context — the guard offers a deliberate,
**audited** bypass:

```bash
# Auto-confirm a gated command (state-altering on a protected context).
# Runs without prompting and is logged as "auto-confirmed" with the actor.
kubectl delete pod nginx --yes
# or via env var (handy for CI):
KUBECTL_GUARD_CONFIRM=yes kubectl delete pod nginx
```

**`--yes` / `KUBECTL_GUARD_CONFIRM=yes` only auto-confirms `RequireConfirmation`
(state-altering on a protected context). It does NOT bypass a protected-resource
`Blocked` — that stays a hard block.** If you need to apply a secret in CI,
remove it from `protected_resources` or scope it. The bypass is recorded with a
distinct `auto-confirmed` outcome (not `confirmed`) so the audit trail shows
exactly which runs were auto-approved.

```bash
# Hard bypass (discouraged): disable the guard entirely for one invocation.
# Even protected-resource blocks are skipped. Logged as "bypassed".
KUBECTL_GUARD_BYPASS=1 kubectl apply -f emergency.yaml
```

`KUBECTL_GUARD_BYPASS` is the nuclear option — use it only when you must drop
protection wholesale, and expect it to stand out in the audit log.

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
  protected contexts. Verbs are case-insensitive (uppercase `DELETE` is
  treated the same as lowercase `delete`).
- **Protected resources** are blocked on every context, including reads.
- **Guard messages** route to stderr, keeping stdout clean for kubectl output
  and piping to other tools.
- Context matching uses glob patterns; resource matching treats
  singular/plural/short-name forms as equivalent.

## Limitations

kubectl-guard is a **client-side guardrail for accidental and unsupervised
commands**, not a substitute for Kubernetes RBAC or network policy. Worth
knowing:

- **Not an access-control boundary.** A determined user can bypass it by
  running the real `kubectl` binary directly or un-aliasing. The
  [PATH-shadowing install](#path-shadowing-install-agents--non-interactive-shells)
  closes the common gap (non-interactive shells and agents that call `kubectl`
  by name), but a user can still invoke the real binary by absolute path. Use
  RBAC for real enforcement; use kubectl-guard for the "are you sure?" and the
  audit trail.
- **TOCTOU on `-f` files.** There is a small window between the guard
  scanning a manifest and `kubectl` re-reading it. The threat model is
  accidents and unsupervised agents, not an adversary swapping a symlink
  mid-flight.
- **Unknown verbs pass through.** Unrecognized commands (e.g. some plugins)
  are forwarded without a prompt, but verb normalization prevents uppercase
  bypass attempts.
- **`-k` kustomize** directories are conservatively blocked when resource
  protection is active, but their contents are not deeply parsed.

## Reliability

- **Atomic config writes** — Configuration is written to a temp file then
  renamed, preventing corruption if writes fail mid-flight.
- **Concurrent-safe audit logging** — File locking prevents interleaved or
  corrupted audit entries under concurrent use.
- **Clean output separation** — Guard messages route to stderr, keeping
  stdout clean for kubectl output and piping to other tools.
