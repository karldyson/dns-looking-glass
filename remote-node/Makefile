VERSION    := $(shell git -C .. describe --always --dirty --tags 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -ldflags "-X dns-looking-glass/internal/version.Version=$(VERSION) \
                         -X dns-looking-glass/internal/version.BuildTime=$(BUILD_TIME)"

.PHONY: all linux-amd64 linux-arm64 darwin-intel darwin-apple clean version-json

all: linux-amd64 linux-arm64 darwin-intel darwin-apple

version-json:
	@printf '{"version":"%s","built":"%s"}\n' "$(VERSION)" "$(BUILD_TIME)" > ../webserver/version.json

linux-amd64: version-json
	GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -buildvcs=true -o build/linux-amd64/dnslg-api ./cmd/dnslg-api

linux-arm64: version-json
	GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -buildvcs=true -o build/linux-arm64/dnslg-api ./cmd/dnslg-api

darwin-intel: version-json
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -buildvcs=true -o build/darwin-amd64/dnslg-api ./cmd/dnslg-api

darwin-apple: version-json
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -buildvcs=true -o build/darwin-arm64/dnslg-api ./cmd/dnslg-api

clean:
	rm -rf build/
