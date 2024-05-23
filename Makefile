all: secfixes-cli
.PHONY: all

GO_FILES=$(shell find . -type f -name '*.go')

secfixes-cli: $(GO_FILES) go.mod go.sum
	go build -o secfixes-cli ./importer/cmd/secfixes-cli
