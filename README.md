# kubectl-guard

A CLI wrapper for kubectl that protects against accidental commands on production clusters.

## Installation

```bash
# From source
git clone https://github.com/lockhinator/kubectl-guard
cd kubectl-guard
make install

# Add alias to your shell config (~/.zshrc or ~/.bashrc)
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

# State-altering commands require confirmation
$ kubectl delete pod nginx
⚠️  delete pod on protected context: prod-cluster
Confirm? [y/N]: n
Aborted.
```

## Configuration

Config file: `~/.kubectl-guard.yaml`

```yaml
protected_contexts:
  - prod-cluster
  - prod-*           # Glob patterns supported
```

Manage via CLI:

```bash
kubectl-guard config list          # List protected contexts
kubectl-guard config add prod-*    # Add a context/pattern
kubectl-guard config remove staging
kubectl-guard config setup         # Re-run setup wizard
```

## How It Works

- **Safe commands** (get, describe, logs, etc.) pass through without prompts
- **State-altering commands** (apply, delete, scale, exec, etc.) require confirmation on protected contexts
- Uses glob pattern matching for flexible context protection
