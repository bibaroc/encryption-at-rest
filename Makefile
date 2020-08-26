VERSION?=dev
GO_FLAGS?=CGO_ENABLED=0

build:
	$(GO_FLAGS) go build \
		-a \
		-trimpath \
		-gcflags='-e -l' \
		-ldflags='-w -s -extldflags "-static" -X main.version=${VERSION} -X main.gitCommit=$(GIT_COMMIT)' \
		-o bin/web \
		./cmd/web

run: build
	@$(shell cat .env) ./bin/web

postgres:
	@docker start postgres || \
		docker run \
			-d \
			--name postgres \
			-v $(PWD)/initdb.d/:/docker-entrypoint-initdb.d/ \
			-e POSTGRES_DB=postgres \
			-e POSTGRES_PASSWORD=FtMQJMfwX9cb9mKsjYJi \
			-e POSTGRES_USER=postgres \
			-p 5433:5432 \
			postgres:12.3-alpine
	@sleep 2

test: postgres
	@$(shell cat .env) go test ./... -run . -bench . -benchmem -cover -count 1 -v