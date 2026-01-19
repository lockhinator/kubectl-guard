.PHONY: build install test clean lint fmt

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
BINARY := kubectl-guard
INSTALL_PATH ?= /usr/local/bin

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

uninstall:
	rm -f $(INSTALL_PATH)/$(BINARY)
	rm -f $(HOME)/go/bin/$(BINARY)

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
