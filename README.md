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
- **🤫 Headless-friendly, fail-closed** — Configure without a TTY via env vars, `config init`, or `--no-prompt`, so CI and agents bootstrap deterministically. An unconfigured headless run **refuses to mutate** rather than silently writing an unprotected config (`KUBECTL_GUARD_BOOTSTRAP`). `--dry-run` commands skip the prompt (no cry-wolf).
- **🔓 Audited escape hatch** — `--yes`/`KUBECTL_GUARD_CONFIRM` auto-confirms gated commands for automation while still logging them (protected-resource blocks and block mode are never bypassed).
- **👀 Diff before confirm** — Optionally preview `kubectl diff` before the prompt for apply/create/replace, so a confirmation is informed.
- **⚡ Drop-in replacement** — Works as a kubectl alias. No changes to your workflows or agent prompts.
- **🔧 Reliable configuration** — Atomic config writes and concurrent-safe audit logging prevent corruption.
- **🎯 Smart command classification** — Automatically distinguishes safe reads from dangerous mutations, even with uppercase verbs or plugins.

## What's New

### v0.5.0 — Bypass closure & agent-relay

- **Gated access vectors** — `port-forward` and `proxy` are now gated like `exec`/`attach`/`cp`. They mutate nothing, but they open a live channel into the cluster with your credentials (a tunnel to a prod database; the whole API server bound locally), so they require confirmation on protected contexts/namespaces (or are blocked in block mode).
- **Verb-shift bypass closed** — a kubectl global flag taking a space-separated value (`kubectl -v 3 delete …`, `--request-timeout 30 …`) used to push the real verb out of position, so it ran **ungated**. The guard now consumes those flags' values (its table mirrors kubectl's persistent value-taking flags) and falls back to the first recognized verb, so every gated verb gates regardless of leading global flags.
- **`--raw` gating** — `kubectl get --raw /api/v1/namespaces/default/secrets/db-creds` read secrets straight past resource protection. `--raw` is now blocked whenever any resource protection is configured (the guard cannot map a literal API path to a resource type); untouched when none is, so `--raw /healthz` still works. `create`/`replace`/`delete --raw` are covered too.
- **Audit-log secret redaction** — the guard no longer writes secret values into its own audit log, `--json` output, or prompts. Credential flags, `key=value` flags (`--from-literal`/`--env`/…), JSON blobs (`--patch`/`--overrides`), `set env` positionals, and `config set` credential properties are redacted to `***` on every surface, while kubectl still receives the real command.
- **Secure-default headless bootstrap** — an unconfigured headless first run no longer silently writes an empty (unprotected) config and proceeds. `KUBECTL_GUARD_BOOTSTRAP` selects the posture; the default `deny` refuses state-altering commands and writes nothing, `empty` is the opt-in for intentionally-unprotected CI.
- **Agent-relay approval flow** — `confirm_mode: agent-relay` (or `KUBECTL_GUARD_AGENT_RELAY=1`) emits a structured `needs-confirmation` object on stderr and exits `4` instead of prompting stdin, so an agent framework can relay the request to its human and re-run with `--yes` once approved. Hard blocks stay hard blocks.

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
export KUBECTL_GUARD_CONFIRM_MODE=type-name   # optional: simple|type-name|agent-relay

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

###### The headless first run is fail-closed

If the guard runs with **no config and no `KUBECTL_GUARD_*` config** and cannot
prompt (`--no-prompt` / `KUBECTL_GUARD_NO_PROMPT=yes`), its posture is decided by
`KUBECTL_GUARD_BOOTSTRAP`:

| Mode | Behavior |
|------|----------|
| `deny` *(default)* | State-altering commands are **refused** (exit `3`) with an actionable message. Read-only commands pass through. **No config is written.** |
| `empty` | Writes an empty config (no protection) and proceeds, with a loud stderr warning. The pre-v0.5.0 behavior, for the deliberately-unprotected CI case. |
| `prompt` | Runs the interactive setup wizard even under `--no-prompt`. Needs a TTY. |

Under `deny`, "state-altering" is judged conservatively: anything that is not a
**recognized safe read** is refused, so an unknown or future mutating verb
(e.g. `certificate approve`) fails closed rather than slipping through. An
unrecognized `KUBECTL_GUARD_BOOTSTRAP` value also falls back to `deny` and warns,
so a typo cannot silently produce an unprotected guard.

`deny` guards against **mutating** an unverified cluster; it does not block
**reads**, so `kubectl get secret` / `get --raw <path>` still run on an
unconfigured cluster (there is nothing yet telling the guard which resources are
sensitive). To block secret *reads*, configure `protected_resources` — that
protection is deliberately explicit, not a bootstrap default. The `deny` posture
also only applies on the headless (`--no-prompt` / `KUBECTL_GUARD_NO_PROMPT`)
path; an interactive run with no config still launches the setup wizard.

Why the default changed: writing an empty config on first run persisted a
*valid but unprotected* config to disk. Every later invocation then found that
config, never prompted, and the guard was a permanent no-op — with nobody
watching. `deny` keeps a headless `bash -c 'kubectl-guard get pods'` working
without hanging, while refusing to mutate a cluster it cannot vouch for.

```bash
# Deliberately unprotected CI step (opt in explicitly):
export KUBECTL_GUARD_BOOTSTRAP=empty
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

### Agent-relay: human-in-the-loop *through* the agent

Type-to-confirm correctly blocks an autonomous agent — but it also blocks the
legitimate case where a human *is* in the loop, reachable through the agent's own
UI. **Agent-relay mode** turns a gated command into a structured request the
agent can relay to its human and resume:

```bash
kubectl-guard config confirm-mode agent-relay
# or, per-invocation / per-session:  export KUBECTL_GUARD_AGENT_RELAY=1
```

On a command that would normally prompt, the guard does **not** touch stdin.
Instead it prints a needs-confirmation object on **stderr** and exits `4`:

```json
{"decision":"needs-confirmation","reason":"agent-relay","context":"prod-cluster","command":"delete pod nginx","prompt":"Approve \"delete pod\" on protected context \"prod-cluster\"? Re-run with --yes to proceed."}
```

The agent framework catches exit code `4` + the JSON, relays `prompt` to its
human, and — once approved — re-runs the **same command with `--yes`**, which
runs it (audited as `auto-confirmed`). If the human declines, the agent aborts.
This makes the guard composable with agent UIs instead of competing with them.

A hard **`Blocked`** (protected resource, or `context_mode: block`) is *not*
relayable — it stays a hard refusal (exit `2`) regardless of confirm mode, so
agent-relay can never downgrade a block into an approvable request.

By default the audit log captures **every** command the agent runs — including the ones it was allowed to run — not just the ones that were gated. So when Claude shells into your cluster, you get a complete, timestamped record of everything it executed, which is invaluable for post-incident review. Tune this with `config audit-mode` (`all` | `gated` | `off`).

### Secret redaction

Secret-bearing flag **values** are redacted from every surface the guard
produces — the audit log, `--json` output, and user-facing messages — while the
flag name (and, for `--from-literal`, the key) is kept so the record stays
useful:

```bash
kubectl create secret generic db --from-literal=password=hunter2
# audit log records: create secret generic db --from-literal=password=***
```

Redacted:

| Form | Example | Logged as |
|------|---------|-----------|
| Credential flags | `--token`, `--password`, `--docker-password`, `--docker-email`, `--client-key`, `--client-certificate`, `--certificate-authority`, `--tls-private-key` | `--token=***` |
| `key=value` flags | `--from-literal`, `--env` (`-e`), `--exec-env`, `--auth-provider-arg` | `--env=DB_PASSWORD=***` |
| `set env` positionals | `kubectl set env deploy/api DB_PASSWORD=hunter2` | `set env deploy/api DB_PASSWORD=***` |
| JSON/YAML blobs | `--patch` (`-p`), `--overrides`, `--exec-arg` | `patch secret db -p ***` |
| `config set` credential properties | `kubectl config set users.admin.token hunter2` | `config set users.admin.token ***` |

Both `--flag=value` and `--flag value` forms are covered — as are pflag's
attached shorthand forms (`-ePASSWORD=x`), kubectl's own credential flags when
they appear in an `exec`/`run` payload after `--` (`exec pod -- app --token x`),
and `kubectl patch secret db -p '{"stringData":{"password":"…"}}'`, the usual way
to set a secret from the CLI. The **key is preserved** so the log still records
*which* variable was set, just not to what. kubectl still receives the real,
unredacted command.

A patch/overrides body is redacted **whole**: the guard cannot prove an
arbitrary JSON blob is free of secret material, so it applies the same "cannot
prove it is safe" stance it uses for `--raw`. The verb and target still appear,
so `patch deploy/web -p ***` tells you what was patched, just not with what.

Redaction of positional `key=value` and of short flags is deliberately
verb-scoped, because kubectl reuses letters: `-p` is `--patch` on `patch` but
the boolean `--previous` on `logs`, so `kubectl logs -p nginx` is logged
verbatim. Likewise `set image deploy/x nginx=nginx:latest` and
`label pod nginx env=prod` carry no secrets and stay legible.

**Caveats.** Redaction only covers secrets that appear in `argv`:

- `--from-file=./creds.txt` and `--cert`/`--key` put only a *path* in argv. The
  file's contents are never seen by the guard, so they are never logged — but
  the guard also cannot redact them.
- A value piped on **stdin** (`--env -`, `--from-file -`) is out of view entirely.
- An `exec`/`run` **payload after `--`** is an arbitrary foreign command line.
  The guard redacts kubectl's *own* credential flags there (`--token`,
  `--password`, …), but it cannot know an application's flag names or inline
  env assignments, so `exec pod -- env PASSWORD=hunter2 app`,
  `-- app --db-password=hunter2`, and `-- sh -c 'export TOKEN=…'` are logged
  verbatim. Blanking every `key=value` or unknown `--flag` in a payload would
  destroy the audit record of what actually ran; keep secrets out of exec
  payloads (reference a mounted Secret or stdin instead).
- Your **shell history** is outside the guard's control. `HISTCONTROL=ignorespace`
  plus a leading space, or `--from-file`, avoids it.
- A secret embedded in a **manifest** applied with `-f` is not in argv. With
  `diff_before_confirm: true`, `kubectl diff` output is printed to your terminal
  before the prompt and can show Secret contents; it is never written to the
  audit log.
- **Arbitrary data fields** are not redacted, because the guard cannot tell a
  secret from ordinary metadata and blanking them would make the log useless:
  `kubectl annotate pod x secret=hunter2` and `kubectl label pod x key=hunter2`
  are logged verbatim. Annotations and labels are not a place to put credentials.

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

  Protecting a namespace also guards **the namespace object itself**. A command
  whose target *is* a protected namespace is gated even on an unprotected
  context and with no `-n` flag, because otherwise the target namespace would
  resolve to `default` and the most destructive command of all would sail
  through:

  ```bash
  kubectl delete namespace kube-system   # gated
  kubectl delete ns/prod-app             # gated (type/name form)
  kubectl edit namespace kube-system     # gated
  kubectl delete ns,pod kube-system      # gated (comma type list)
  ```

  Because kubectl's own usage is `delete TYPE (NAME | -l label | --all)`, a
  namespace command that supplies **no names** cannot be checked against the
  protected patterns. `kubectl delete namespace --all` and
  `kubectl delete ns -l env=prod` are therefore gated whenever *any* namespace
  is protected — the guard cannot prove a protected namespace is not among the
  targets. Reads (`kubectl get namespace kube-system`) are unaffected; use
  `protected_resources` to block reads.
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
  state-altering commands (require confirmation). See
  [Glob pattern semantics](#glob-pattern-semantics).
- **`protected_namespaces`** — glob patterns of namespaces that gate
  state-altering commands (resolved from `--namespace`/`-n`, the context's
  baked-in namespace, or `default`). Same glob semantics as
  `protected_contexts`.
- **`protected_resources`** — resources blocked everywhere, reads included
- **`context_mode`** — `confirm` (default, prompts) or `block` (hard-refuse)
- **`namespace_mode`** — `confirm` (default) or `block`, for protected namespaces
- **`confirm_mode`** — `simple` (y/N prompt), `type-name` (type the context
  name to confirm), or `agent-relay` (emit a needs-confirmation JSON on stderr
  and exit `4` instead of prompting, for agent frameworks — see
  [Agent-relay](#agent-relay-human-in-the-loop-through-the-agent))
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

### Glob pattern semantics

`protected_contexts` and `protected_namespaces` are matched with the **same**
glob matcher, so a pattern means exactly one thing wherever you write it.
Context and namespace names are *names*, not filesystem paths, so the matcher
uses shell-like semantics rather than path semantics:

| Syntax | Matches |
|--------|---------|
| `*` | any sequence of characters, **including `/` and `:`** (and the empty string) |
| `?` | exactly one character (one UTF-8 rune, not one byte) |
| `[abc]` | one character from the set |
| `[a-z]` | one character from the range |
| `[^abc]` | one character **not** in the set |
| `\*`, `\?`, `\[`, `\\` | the literal character, escaped |

Everything else matches itself. Behavior is **identical on Linux, macOS, and
Windows** — `/` and `\` carry no special path meaning.

Note that only `^` negates a character class. Unlike most shells, `[!abc]` is
**not** a negation here — `!` is an ordinary member of the set. This matches the
behavior of the matcher used in earlier releases, so upgrading can never turn a
protected context into an unprotected one.

```yaml
protected_contexts:
  - 'prod-*'                          # prod-us-east-1, prod-us/east/1
  - '*prod*'                          # team-a/prod/cluster, myprodcluster
  - 'arn:aws:eks:*:*:cluster/prod-*'  # EKS ARNs
  - 'gke_*_prod-*'                    # GKE context names
```

Because `*` spans `/`, a path-shaped context name (`team-a/prod`) is matched by
`*prod*` the way you would expect from a shell. Note the literal parts of a
pattern still have to match literally: `prod-*` matches `prod-us/east/1` but not
`prod/us/east/1`, because `prod-` is not a prefix of `prod/`.

> Earlier releases used Go's `path/filepath.Match`, where `*` and `?` refuse to
> cross `/`, escaping is disabled on Windows, and a malformed pattern such as
> `prod-[` returns an error that the guard swallowed — silently protecting
> **nothing**. Upgrading is safe: for any context or namespace name, a pattern
> that was protected before is still protected. The new matcher only ever widens
> what a pattern matches. (The sole exception is a name containing a multi-byte
> UTF-8 character matched by a wildcard, where `filepath.Match` matched the
> character's interior bytes; Kubernetes context and namespace names are ASCII,
> so no real configuration is affected.)

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
| `KUBECTL_GUARD_CONFIRM_MODE` | `simple` \| `type-name` \| `agent-relay`, applied on headless first-run config. |
| `KUBECTL_GUARD_AGENT_RELAY` | Truthy: emit a needs-confirmation JSON on stderr and exit `4` on a gated command instead of prompting (agent-relay). |
| `KUBECTL_GUARD_NO_PROMPT` | Truthy: skip the setup wizard (headless). The resulting posture is set by `KUBECTL_GUARD_BOOTSTRAP`. |
| `KUBECTL_GUARD_BOOTSTRAP` | `deny` (default) \| `empty` \| `prompt` — headless first-run posture when there is no config. `deny` refuses state-altering commands and writes no config. |
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
- **No output redaction — the guard blocks commands, it does not filter their
  output.** Once a command is allowed, kubectl's output flows straight to your
  terminal: the guard hands off with `exec` and never sees it. So a secret
  value that reaches you *through* a permitted command — an env var in
  `get pod -o yaml`, a token an app wrote to `logs` — is not redacted. Protect
  the resource (`config add-resource secret`) and gate the access vectors
  (`exec`, `cp`, `port-forward`) instead; those are decisions the guard can make
  from the command line, with certainty, before anything runs. This is a
  deliberate design decision — see
  [docs/redaction-decision.md](docs/redaction-decision.md) for the full
  rationale and the cost analysis behind it.

## Reliability

- **Atomic config writes** — Configuration is written to a temp file then
  renamed, preventing corruption if writes fail mid-flight.
- **Concurrent-safe audit logging** — File locking prevents interleaved or
  corrupted audit entries under concurrent use.
- **Clean output separation** — Guard messages route to stderr, keeping
  stdout clean for kubectl output and piping to other tools.
