lint:
	@go run golang.org/x/lint/golint ./...

build: lint
	@go build -o bin/chirpy .

run: build
	@./bin/chirpy
