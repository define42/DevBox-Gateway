all: ui
	docker compose build

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run 
lint2:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --enable=stylecheck --enable=gochecknoinits
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
test:
	 go test ./...  -coverpkg=./... -cover

run: 
	docker compose stop
	docker compose build
	docker compose up

ui:
	tsc -p tsconfig.json
