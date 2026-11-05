BINARY_NAME=naa-dump-offline
SRC=cmd/naa-dump-offline/main.go

.PHONY: all build build-all clean

all: build

build:
	go build -ldflags="-s -w" -o $(BINARY_NAME) $(SRC)

build-all:
	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME)-linux-amd64 $(SRC)
	GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o $(BINARY_NAME)-linux-arm64 $(SRC)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME).exe $(SRC)
	GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME)-darwin-amd64 $(SRC)
	GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o $(BINARY_NAME)-darwin-arm64 $(SRC)

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe $(BINARY_NAME)-*
