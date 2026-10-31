.PHONY: build check test dist release
build:
	go build -trimpath -o bin/korta ./cmd/korta
check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
test:
	go test ./...
dist:
	scripts/dist.sh $(VERSION)
# make release VERSION=v0.2.0 tags main; CI publishes the release.
release:
	scripts/release.sh $(VERSION)
