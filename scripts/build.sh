#!/usr/bin/env bash
# Build script for kubectl-guard with optional version injection.
# Usage: ./scripts/build.sh [version]
#   Without version: builds with version="dev"
#   With version: ./scripts/build.sh 0.2.2 builds with version="0.2.2"

set -euo pipefail

VERSION="${1:-dev}"
LDFLAGS="-X main.version=${VERSION}"

echo "Building kubectl-guard version ${VERSION}..."
go build -ldflags "${LDFLAGS}" -o kubectl-guard .
echo "Built: ./kubectl-guard"
./kubectl-guard --version