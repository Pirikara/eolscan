.PHONY: build test vet validate-design validate-real-packages

build:
	go build -o bin/eolscan ./cmd/eolscan

test:
	go test -race ./...

vet:
	go vet ./...

validate-design:
	uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py

# Live validation reports unmet detection goals with a nonzero exit code.
validate-real-packages: build
	python3 scripts/validate_real_packages.py
