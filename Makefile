.PHONY: build test lint

build:
	go build -o bgproof ./main.go

test:
	go test ./circuit -v
	go test ./core -v

lint:
	golangci-lint run