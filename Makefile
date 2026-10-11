.PHONY: build test vet validate-design

build:
	go build -o bin/eolscan .

test:
	go test -race ./...

vet:
	go vet ./...

validate-design:
	uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
