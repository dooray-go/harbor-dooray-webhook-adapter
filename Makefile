BINARY := harbor-dooray-webhook-adapter
PKG := .
DIST := dist

.PHONY: all build build-linux build-windows build-darwin build-all test clean run

all: build

build:
	go build -o $(DIST)/$(BINARY) $(PKG)

build-linux:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(DIST)/$(BINARY)-linux-amd64 $(PKG)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(DIST)/$(BINARY)-linux-arm64 $(PKG)

build-windows:
	mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(DIST)/$(BINARY)-windows-amd64.exe $(PKG)

build-darwin:
	mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o $(DIST)/$(BINARY)-darwin-amd64 $(PKG)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(DIST)/$(BINARY)-darwin-arm64 $(PKG)

build-all: build-linux build-windows build-darwin

test:
	go test ./...

run:
	go run $(PKG)

clean:
	rm -rf $(DIST)