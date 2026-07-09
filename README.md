# kubectl-guard

**Keep your secrets out of the context window.**

A CLI wrapper for kubectl that sits between AI agents (and humans) and your cluster, blocking secret reads, gating production mutations, and auditing everything.

> LLMs can run kubectl on your behalf — but they have no "are you sure?" reflex. Whatever they read becomes context, and context leaks: into logs, into transcripts, into a model provider's servers. kubectl-guard is the human-in-the-loop seatbelt for that.

## Features

- **🔒 Secret protection** — Block all secret access across your entire cluster. Secrets never leave the cluster, so they can never enter LLM context windows or logs.
- **🚦 Production gating** — Require explicit confirmation for state-altering commands on production contexts **and namespaces**. Type the context/namespace name to confirm — something autonomous agents can't do. Optional hard **block mode** refuses with no prompt.
- **📋 Comprehensive audit logging** — Every command is logged with timestamps, context, outcome, and *who drove it* (the actor). Full visibility into what your agents (or you) tried to do.
- **🤖 Agent-native output** — Distinct exit codes (0/1/2/3/4) and a `--json` mode let agent frameworks parse guard decisions programmatically instead of scraping warning text.
- **🛡️ Hard to bypass** — Honors `--context`/`--kubeconfig`/`--namespace`, denies `--server` (unknown cluster) and optionally `--as` impersonation, and a PATH-shadowing install (`make install-shim`) intercepts `kubectl` even in non-interactive shells and agent subprocesses where an alias can't reach.
- **🤫 Headless-friendly** — Configure without a TTY via env vars, `config init`, or `--no-prompt`, so CI and agents bootstrap deterministically. `--dry-run` commands skip the prompt (no cry-wolf).
- **🔓 Audited escape hatch** — `--yes`/`KUBECTL_GUARD_CONFIRM` auto-confirms gated commands for automation while still logging them (protected-resource blocks and block mode are never bypassed).
- **👀 Diff before confirm** — Optionally preview `kubectl diff` before the prompt for apply/create/replace, so a confirmation is informed.
- **⚡ Drop-in replacement** — Works as a kubectl alias. No changes to your workflows or agent prompts.
- **🔧 Reliable configuration** — Atomic config writes and concurrent-safe audit logging prevent corruption.
- **🎯 Smart command classification** — Automatically distinguishes safe reads from dangerous mutations, even with uppercase verbs or plugins.

## What's New

### v0.4.0 — Security completeness

- **Targeting & identity flags** — `--server` (which points at a different cluster the guard can't verify) is now **denied** when context protection is configured. `--as`/`--as-group`/`--as-uid` impersonation and `--token` are **recorded in the audit log**, and optionally **blocked** on protected contexts via `block_impersonation`.
- **Namespace-level protection** — new `protected_namespaces` (glob patterns) gate state-altering commands by namespace, composing with context protection. The target namespace is resolved from `--namespace`/`-n`, then the namespace baked into the active context, then `default`; `--all-namespaces`/`-A` is gated when any namespace is protected.
- **Hard block mode** — `context_mode: block` / `namespace_mode: block` hard-refuse state-altering commands with no confirmation option. Block mode is absolute: `--yes` cannot override it.
- **Diff before confirm** — `diff_before_confirm: true` runs `kubectl diff` and shows it on stderr before the prompt for diffable commands (apply/create/replace).
- **Dry-run aware** — `apply --dry-run=client`/`server` change nothing, so they skip the prompt (audited as `dry-run`); `--dry-run=none` still gates. Reduces cry-wolf confirmations.

### v0.3.0 — Agent-native safety

- **Structured exit codes + JSON output** — Guard decisions now exit with distinct codes (`0` allow, `1` kubectl error, `2` blocked, `3` denied, `4` needs-confirmation) so an agent framework can tell a guard intervention from a kubectl failure. A guard-only `--json` flag emits a structured decision object on stderr for non-allow decisions (and nothing for allow, so kubectl's stdout stays clean).
- **Actor identity** — Each audit entry now records *who drove* the command (`actor`), sourced from `KUBECTL_GUARD_ACTOR` (e.g. `claude-code`), alongside the OS `user`. Agent activity is finally distinguishable from human activity in the log.
- **PATH-shadowing install + `doctor`** — `make install-shim` places a `kubectl` shim earlier in `PATH` than the real kubectl, intercepting calls even in non-interactive shells and agent subprocesses (an alias only covers interactive shells). `kubectl-guard doctor` verifies interception is active.
- **Headless / non-TTY setup** — Configure without a TTY via `KUBECTL_GUARD_PROTECTED_*` env vars, `kubectl-guard config init`, or `--no-prompt`/`KUBECTL_GUARD_NO_PROMPT`. CI and agents bootstrap deterministically instead of hitting a wizard they can't answer.
- **Audited automation escape hatch** — `--yes` / `KUBECTL_GUARD_CONFIRM=yes` auto-confirms gated commands for pipelines while logging them as `auto-confirmed` (protected-resource blocks are never bypassed). `KUBECTL_GUARD_BYPASS` is a discouraged full bypass, logged as `bypassed`.

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

The first-run env vars and `config init` cover protected **contexts**,
**resources**, and the **confirm mode**. Protected **namespaces** and the
**block modes** (`context_mode`/`namespace_mode`) are not part of first-run
bootstrap — set them afterward with `config add-namespace` /
`config namespace-mode` / `config context-mode`, or by writing the YAML
directly (config is re-read every invocation).

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
  `exec`, `config use-context`, …) require confirmation (or are hard-blocked in
  `context_mode: block`). Read-only commands (`get`, `describe`, `logs`,
  `config view`, …) pass through.
- **Gated access vectors** — `port-forward` and `proxy` mutate nothing, but they
  open a live channel into the cluster with your credentials (a tunnel to a prod
  database; the whole API server bound locally). They are gated exactly like
  state-altering commands, alongside `exec`, `attach`, and `cp`.
- **Protected namespaces** — glob patterns of namespaces that gate
  state-altering commands when the target namespace matches. The target
  namespace is resolved from `--namespace`/`-n`, then the namespace baked into
  the resolved context (best-effort via kubeconfig), then `default`.
  `--all-namespaces`/`-A` is gated whenever any namespace is protected.
  Composes with context protection: a command is gated if *either* the context
  or the namespace is protected.
- **Block mode** — set `context_mode: block` and/or `namespace_mode: block` to
  hard-refuse state-altering commands with **no confirmation option** (for CI
  service accounts or a strict "agents must never touch prod" policy). Block
  mode is absolute: `--yes`/`KUBECTL_GUARD_CONFIRM` cannot override it.
- **Dry-run aware** — `apply --dry-run=client`/`--dry-run=server` change no
  cluster state, so they skip the confirmation prompt (audited as `dry-run`).
  The guard mirrors kubectl's own dry-run parsing, so every form kubectl treats
  as a real mutation still gates: `--dry-run=none`, `--dry-run=false`/`0`, and a
  plain `apply`. Protected-resource blocks still apply (a dry-run of a secret is
  still blocked).
- **Protected resources** — any command touching the resource is **blocked
  everywhere** (reads included), regardless of context. Use this to block all
  access to secrets, for example.
- **`--raw` is un-inspectable** — `kubectl get --raw <path>` requests a literal
  API-server path, so no resource token appears in the command and resource
  protection has nothing to match. While **any** resource protection is
  configured, `--raw` is therefore **blocked** — the same conservative stance
  taken for stdin/URL/kustomize sources. Without resource protection it is
  untouched, so `kubectl get --raw /healthz` and `/version` keep working.
  (`--raw` is also available on `create`/`replace`/`delete`, making it a write
  vector as well as a read one; all are covered.)
- **No bypass** — the `--context` and `--kubeconfig` flags are honored, so
  `kubectl --context=prod delete pod x` is still gated.
- **Targeting & identity flags** — `--server` (which points at a different
  cluster the guard can't map to a context) is **denied** when context
  protection is configured (fail-closed). `--as`/`--as-group`/`--as-uid`
  impersonation and `--token` credential overrides are **recorded in the
  audit log** for attribution, and optionally **blocked** on protected
  contexts via `block_impersonation`.
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

Once enabled, every command targeting that resource is refused with exit code 2
(`blocked`) — reads, writes, and applies alike:

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
protected_namespaces:
  - kube-system      # State changes gated in these namespaces
  - prod-*           # Glob patterns supported
context_mode: confirm     # confirm (default) | block
namespace_mode: confirm   # confirm (default) | block
confirm_mode: type-name   # simple (y/N) or type-name (type the context name)
audit_mode: all           # all (default) | gated | off
audit_log: ~/.kubectl-guard-audit.log   # optional; defaults to this path
actor: ci-deploy          # optional static default actor (overridden by KUBECTL_GUARD_ACTOR)
block_impersonation: true # optional: deny --as* on protected contexts
diff_before_confirm: true # optional: show `kubectl diff` before the confirm prompt
```

Fields:
- **`protected_contexts`** — glob patterns of contexts that gate
  state-altering commands (require confirmation)
- **`protected_namespaces`** — glob patterns of namespaces that gate
  state-altering commands (resolved from `--namespace`/`-n`, the context's
  baked-in namespace, or `default`)
- **`protected_resources`** — resources blocked everywhere, reads included
- **`context_mode`** — `confirm` (default, prompts) or `block` (hard-refuse)
- **`namespace_mode`** — `confirm` (default) or `block`, for protected namespaces
- **`confirm_mode`** — `simple` (y/N prompt) or `type-name` (type the
  context name to confirm)
- **`audit_mode`** — `all` (default, logs every command including allowed
  passthrough), `gated` (only interventions: blocked/confirmed/aborted/denied),
  or `off` (logs nothing)
- **`audit_log`** — optional override for the audit log path
- **`actor`** — optional static default for the audit `actor` field (overridden
  by `KUBECTL_GUARD_ACTOR` when set); useful for a shared CI host
- **`diff_before_confirm`** — when true, run `kubectl diff` (server-side) and
  show the result on stderr before the confirmation prompt for diffable commands
  (`apply`/`create`/`replace -f`). Off by default (adds latency and needs
  server-side dry-run RBAC; a failed diff warns and prompts anyway)

Manage via CLI:

```bash
kubectl-guard --version                  # Show version (or -V)
kubectl-guard config list                 # Show contexts, resources, namespaces, confirm mode, audit path
kubectl-guard config add-context prod-*   # Protect matching contexts
kubectl-guard config remove-context staging
kubectl-guard config add-resource secret  # Block a resource everywhere
kubectl-guard config remove-resource secret
kubectl-guard config add-namespace kube-system  # Gate state changes in a namespace
kubectl-guard config add-namespace 'prod-*'      # Glob patterns supported
kubectl-guard config remove-namespace kube-system
kubectl-guard config confirm-mode type-name  # Stronger confirmation prompt
kubectl-guard config context-mode block      # Hard-block state changes on protected contexts
kubectl-guard config namespace-mode block    # Hard-block state changes on protected namespaces
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
`--kubeconfig`, and `KUBECONFIG`) and namespace (`--namespace`/`-n`), and
decides whether to block, prompt, or pass through — then replaces its own
process with the real `kubectl` via `exec`, so stdout, stdin, and exit codes
are preserved exactly.

- **Safe commands** (`get`, `describe`, `logs`, `config view`, `auth can-i`, …)
  pass through without prompts.
- **State-altering commands** (`apply`, `delete`, `scale`, `exec`,
  `config use-context`, `auth reconcile`, …) require confirmation on protected
  contexts **or namespaces** (or are hard-blocked in `context_mode`/
  `namespace_mode: block`). Verbs are case-insensitive (uppercase `DELETE` is
  treated the same as lowercase `delete`).
- **Access vectors** (`port-forward`, `proxy`, `exec`, `attach`, `cp`) are gated
  the same way. They change no cluster state, so nothing about them is
  "read-only" in the sense that matters: they reach production data directly.
- **Dry-run commands** (`apply --dry-run=client|server`) change no state and
  skip the prompt (audited as `dry-run`). Verbs that have no `--dry-run` flag
  (`exec`, `port-forward`, `proxy`, …) are always gated: a `--dry-run` token on
  such a command never buys an ungated pass.
- **Protected resources** are blocked on every context, including reads. While
  resource protection is active, `--raw` API paths are blocked too, since the
  guard cannot map them to a resource type.
- **Targeting/identity** — `--server` is denied when contexts are protected;
  `--as`/`--token` are recorded in the audit log.
- **Verb resolution** — the guard consumes the values of kubectl's global flags
  before deciding which token is the verb, so `kubectl -v 3 delete pod x` and
  `kubectl --request-timeout 30 port-forward …` gate exactly like their plain
  forms. If a verb still cannot be recognized, the guard falls back to the first
  recognized verb in the command rather than treating it as unknown (fail-closed).
- **Guard messages** route to stderr, keeping stdout clean for kubectl output
  and piping to other tools.
- Context and namespace matching use glob patterns; resource matching treats
  singular/plural/short-name forms as equivalent.

### Exit codes

Guard decisions use distinct exit codes so an agent framework (or a script)
can tell a guard intervention apart from an ordinary kubectl failure. kubectl
itself uses `0`/`1`, so the guard uses higher codes:

| Code | Meaning |
|------|---------|
| `0`  | allowed / ran successfully (kubectl's own code is preserved via `exec`) |
| `1`  | kubectl error (passthrough) |
| `2`  | blocked — a protected resource, or a block-mode refusal on a protected context/namespace (`context_mode`/`namespace_mode: block`) |
| `3`  | denied (fail-closed: config/context could not be verified, `--server` on a protected setup, or blocked impersonation) |
| `4`  | needs confirmation but aborted (no TTY / agent / declined) |

### JSON output mode (`--json`)

Add the guard-only `--json` flag (recognized by the guard, **stripped before
forwarding to kubectl**) to get a structured decision object on **stderr** for
any non-allow decision. For an allowed command nothing is emitted, so kubectl's
stdout stays clean for the agent to consume:

```bash
$ kubectl get secret --json   # blocked
{"decision":"blocked","reason":"protected-resource","context":"prod-cluster","command":"get secret","resource":"secret"}
# exit code 2

$ kubectl get pods --json     # allowed
# (no stderr output; kubectl's normal stdout flows through)
# exit code 0
```

The object fields: `decision` (`blocked` | `denied` | `needs-confirmation`),
`reason` (e.g. `protected-resource`, `protected-context-block-mode`,
`protected-namespace-block-mode`), `context`, `command`, and `resource` (the
protected-resource token, for a resource `blocked`). In `--json` mode a
`needs-confirmation` decision aborts
immediately with exit `4` (an agent cannot answer an interactive prompt) rather
than blocking on stdin.

### Environment variables

| Variable | Purpose |
|---|---|
| `KUBECTL_GUARD_ACTOR` | Labels *who* drove the command in the audit log (e.g. `claude-code`). |
| `KUBECTL_GUARD_PROTECTED_CONTEXTS` | Comma-separated context patterns for headless first-run config. |
| `KUBECTL_GUARD_PROTECTED_RESOURCES` | Comma-separated resources to block everywhere for headless first-run config. |
| `KUBECTL_GUARD_CONFIRM_MODE` | `simple` \| `type-name`, applied on headless first-run config. |
| `KUBECTL_GUARD_NO_PROMPT` | Truthy: skip the setup wizard, write an empty config, and proceed (headless). |
| `KUBECTL_GUARD_CONFIRM` | Truthy (`yes`): auto-confirm gated commands (audited as `auto-confirmed`). |
| `KUBECTL_GUARD_BYPASS` | Truthy: disable the guard entirely for one invocation (audited as `bypassed`; discouraged). |

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
