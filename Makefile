lint:
	@go run golang.org/x/lint/golint ./...

dbup:
	cd sql/schema && \
	goose postgres "postgres://postgres:postgres@localhost:5432/chirpy?sslmode=disable" up

dbdown:
	cd sql/schema && \
	goose postgres "postgres://postgres:postgres@localhost:5432/chirpy?sslmode=disable" down

gen_code:
	@sqlc generate 

build: lint
	@go build -o bin/chirpy .

run: build
	@./bin/chirpy
