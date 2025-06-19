include .env
export

lint:
	@go run golang.org/x/lint/golint ./...

dbup:
	cd sql/schema && \
	goose postgres "$(DB_URL)" up

dbdown:
	cd sql/schema && \
	goose postgres "$(DB_URL)" down

gen_code:
	@sqlc generate

build: lint
	@go build -o bin/chirpy .

run: build
	@./bin/chirpy
