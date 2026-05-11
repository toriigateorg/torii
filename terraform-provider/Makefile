BINARY  := terraform-provider-torii
VERSION := dev
INSTALL_DIR := $(HOME)/.terraform.d/plugins/registry.terraform.io/toriigateorg/torii/$(VERSION)/$(shell go env GOOS)_$(shell go env GOARCH)

.PHONY: build install fmt vet tidy

build:
	go build -o $(BINARY) .

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/

fmt:
	gofmt -s -w .

vet:
	go vet ./...

tidy:
	go mod tidy
