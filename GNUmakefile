default: fmt lint test generate

build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

vuln:
	govulncheck ./...

generate:
	cd tools && go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name airlock --provider-dir ..

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -timeout=120s ./...

testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

.PHONY: build install lint vuln generate fmt test testacc
