exec >&2

{ echo go.work go.mod | xargs -n1; find . -type f -name '*.go'; } | redo-ifchange

go build -o $3 ./importer/cmd/secfixes-cli/
