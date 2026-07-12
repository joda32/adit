.PHONY: build test vet run tidy

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

# Example: make run DC=192.168.1.10 FQDN=dc01.example.local
run:
	go run ./cmd/adit -dc $(DC) -fqdn $(FQDN)

tidy:
	go mod tidy
