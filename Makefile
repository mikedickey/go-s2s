.PHONY: s2s fmt lint

all: s2s

s2s:
	@go build -o s2s ./cmd

fmt:
	@gofmt -l -w `find ./ -name "*.go"`

lint:
	@docker run --rm -v `pwd`:/app -w /app golangci/golangci-lint:v1.57.2 golangci-lint run -v
