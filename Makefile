.PHONY: build install install-shim install-local uninstall uninstall-shim test clean lint fmt

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
BINARY := kubectl-guard
INSTALL_PATH ?= /usr/local/bin
SHIM_DIR ?= $(HOME)/.local/share/kubectl-guard/shims

build:
	go build $(LDFLAGS) -o $(BINARY) .

install: build
	install -m 755 $(BINARY) $(INSTALL_PATH)/$(BINARY)
	@echo "Installed to $(INSTALL_PATH)/$(BINARY)"
	@echo ""
	@echo "Add this alias to your shell config (~/.zshrc or ~/.bashrc):"
	@echo '  alias kubectl="kubectl-guard"'

install-local: build
	install -m 755 $(BINARY) $(HOME)/go/bin/$(BINARY)
	@echo "Installed to $(HOME)/go/bin/$(BINARY)"

# install-shim sets up PATH-shadowing interception: it installs the guard and
# a `kubectl` symlink that points at it, earlier in PATH than the real
# kubectl. Unlike an alias, this also intercepts non-interactive shells and
# agents that exec kubectl by name. The guard detects it is the shim and
# forwards to the REAL kubectl (skipping itself on PATH).
install-shim: build
	@mkdir -p $(SHIM_DIR)
	install -m 755 $(BINARY) $(SHIM_DIR)/$(BINARY)
	@ln -sf $(BINARY) $(SHIM_DIR)/kubectl
	@echo "Installed guard + kubectl shim to $(SHIM_DIR)"
	@echo ""
	@echo "The shim intercepts kubectl even in non-interactive shells and agents."
	@echo "Prepend the shim directory to PATH in your shell config (~/.zshrc or ~/.bashrc):"
	@echo '  export PATH="$(SHIM_DIR):$$PATH"'
	@echo ""
	@echo "Reload your shell, then verify interception is active:"
	@echo "  kubectl-guard doctor"

uninstall:
	rm -f $(INSTALL_PATH)/$(BINARY)
	rm -f $(HOME)/go/bin/$(BINARY)
	rm -f $(SHIM_DIR)/$(BINARY) $(SHIM_DIR)/kubectl

# uninstall-shim removes just the PATH-shadowing shim via the guard's own
# `uninstall` command, which also reports the PATH line to strip from your shell
# config and verifies interception is inactive. Use `kubectl-guard uninstall
# --purge` to additionally remove the config + audit log.
uninstall-shim: build
	./$(BINARY) uninstall

test:
	go test ./... -v

test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint:
	golangci-lint run

fmt:
	go fmt ./...

clean:
	rm -f $(BINARY)
	rm -f coverage.out coverage.html

run: build
	./$(BINARY) $(ARGS)

# Development helpers
dev-setup:
	@echo "Setting up development environment..."
	go mod download
	@echo "Done!"
