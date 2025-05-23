.PHONY: build

build:
	go build -o bgproof ./main.go

test:
	go test ./circuit -v
	go test ./core -v