all: ui
	docker compose build

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run
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

