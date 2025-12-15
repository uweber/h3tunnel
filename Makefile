DATE=$(shell date +'%Y.%m.%d %H:%M:%S')
GITREV=$(shell git rev-parse --short HEAD)

LDFLAGS="-X 'main.BUILD_VERSION=${GITREV}' -X 'main.BUILD_DATE=${DATE}'"
TINY_LDFLAGS="-s -w -X 'main.BUILD_VERSION=${GITREV}' -X 'main.BUILD_DATE=${DATE}'"

all:	bin/h3tunnel bin/h3tunnel_client

bin/h3tunnel: *.go
	go build -tags=server -ldflags=$(LDFLAGS) -o $@ .

bin/h3tunnel_client: *.go
	go build -tags=client -ldflags=$(LDFLAGS) -o $@ .

bin/benchmark: *.go
	go build -tags=benchmark -ldflags=$(LDFLAGS) -o $@ .

update:
	go mod tidy

clean:
	rm -f bin/*
