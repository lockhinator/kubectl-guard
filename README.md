# kubectl-guard

A CLI wrapper for kubectl that protects against accidental commands on production clusters and sensitive resources.

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

## Usage

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

After setup, kubectl-guard intercepts commands and prompts for confirmation on protected contexts:

```bash
# Safe commands pass through
$ kubectl get pods
NAME    READY   STATUS
nginx   1/1     Running

# State-altering commands require confirmation on protected contexts
$ kubectl delete pod nginx
⚠️  delete pod on protected context: prod-cluster
Confirm? [y/N]: n
Aborted.
```

## Protection model

- **Protected contexts** — state-altering commands (`apply`, `delete`, `scale`,
  `exec`, `config use-context`, …) require confirmation. Read-only commands
  (`get`, `describe`, `logs`, `config view`, …) pass through.
- **Protected resources** — any command touching the resource is **blocked
  everywhere** (reads included), regardless of context. Use this to block all
  access to secrets, for example.
- **No bypass** — the `--context` and `--kubeconfig` flags are honored, so
  `kubectl --context=prod delete pod x` is still gated.
- Every confirmed, aborted, and blocked action on a protected context/resource
  is written to the **audit log**.

## Blocking all secret access

To block **all** access to a resource on every cluster, context, and verb
(reads included), add it as a protected resource:

```bash
# Enable: block all secret access everywhere
$ kubectl-guard config add-resource secret
✓ Blocked resource: secret

# Disable: stop blocking secrets
$ kubectl-guard config remove-resource secret
✓ Unblocked resource: secret
```

Once enabled, every command targeting that resource is refused with exit 1:

```bash
$ kubectl get secret
⚠️  Blocked: get secret targets a protected resource (context: prod-cluster)

$ kubectl get secrets -A           # plural form also blocked
$ kubectl create secret generic x  # writes blocked
$ kubectl apply -f secret.yaml     # manifests scanned for kind: Secret
$ kubectl get secret,configmap     # comma-separated lists matched per-part
$ kubectl get all                  # "all"/"*" blocked (they span secrets)
```

Everything else is allowed — non-protected resources pass through normally.

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
audit_log: ~/.kubectl-guard-audit.log   # optional; defaults to this path
```

Fields:
- **`protected_contexts`** — glob patterns of contexts that gate
  state-altering commands (require confirmation)
- **`protected_resources`** — resources blocked everywhere, reads included
- **`confirm_mode`** — `simple` (y/N prompt) or `type-name` (type the
  context name to confirm)
- **`audit_log`** — optional override for the audit log path

Manage via CLI:

```bash
kubectl-guard config list                 # Show contexts, resources, modes
kubectl-guard config add-context prod-*   # Protect matching contexts
kubectl-guard config remove-context staging
kubectl-guard config add-resource secret  # Block a resource everywhere
kubectl-guard config remove-resource secret
kubectl-guard config confirm-mode type-name  # Stronger confirmation prompt
kubectl-guard config audit                # Show audit log path + recent entries
kubectl-guard config setup                # Re-run setup wizard
kubectl-guard config path                 # Print config file path
```

## How It Works

- **Safe commands** (get, describe, logs, config view, auth can-i, …) pass through without prompts
- **State-altering commands** (apply, delete, scale, exec, config use-context, auth reconcile, …) require confirmation on protected contexts
- **Protected resources** are blocked on every context, including reads
- Uses glob pattern matching for contexts and singular/plural matching for resources
