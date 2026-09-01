BINARY := daemons
DIST_DIR := dist
STAGING_DIR := $(DIST_DIR)/.release-staging
SUPPORTED_TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
VERSION ?= $(shell \
	if git describe --tags --exact-match --match 'v[0-9]*' >/dev/null 2>&1; then \
		git describe --tags --exact-match --match 'v[0-9]*'; \
	else \
		sha=$$(git rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown'); printf 'dev+%s' "$$sha"; \
		if [ -n "$$(git status --porcelain -- . 2>/dev/null)" ]; then printf '.dirty'; fi; \
	fi)
LDFLAGS := -s -w -X main.version=$(VERSION)

DARWIN_ARCHIVES := $(foreach ARCH,amd64 arm64,$(DIST_DIR)/$(BINARY)_$(VERSION)_darwin_$(ARCH).zip)
LINUX_ARCHIVES := $(foreach ARCH,amd64 arm64,$(DIST_DIR)/$(BINARY)_$(VERSION)_linux_$(ARCH).tar.gz)
RELEASE_ARCHIVES := $(DARWIN_ARCHIVES) $(LINUX_ARCHIVES)
RELEASE_ARCHIVE_NAMES := $(notdir $(RELEASE_ARCHIVES))
SHA256_COMMAND := $(shell if command -v shasum >/dev/null 2>&1; then printf 'shasum -a 256'; else printf 'sha256sum'; fi)

.PHONY: build build-windows checksums clean package release test verify-archives verify-checksums verify-release verify-version

test:
	go test ./...

build:
	mkdir -p $(DIST_DIR)
	@set -eu; \
	for target in $(SUPPORTED_TARGETS); do \
		os=$${target%/*}; \
		arch=$${target#*/}; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -ldflags="$(LDFLAGS)" -o "$(DIST_DIR)/$(BINARY)-$$os-$$arch" ./cmd/daemons; \
	done

# Windows is compiled only to catch portability regressions. It is never packaged or published.
build-windows:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-windows-amd64.exe ./cmd/daemons

package:
	@set -eu; \
	for target in $(SUPPORTED_TARGETS); do \
		os=$${target%/*}; \
		arch=$${target#*/}; \
		test -x "$(DIST_DIR)/$(BINARY)-$$os-$$arch"; \
		dir="$(STAGING_DIR)/$$os-$$arch"; \
		rm -rf "$$dir"; \
		mkdir -p "$$dir"; \
		cp "$(DIST_DIR)/$(BINARY)-$$os-$$arch" "$$dir/$(BINARY)"; \
		cp LICENSE NOTICE "$$dir/"; \
		if [ "$$os" = darwin ]; then \
			archive="$$(pwd)/$(DIST_DIR)/$$(printf '%s_%s_%s_%s.zip' "$(BINARY)" "$(VERSION)" "$$os" "$$arch")"; \
			(cd "$$dir" && zip -q -X "$$archive" $(BINARY) LICENSE NOTICE); \
		else \
			archive="$$(pwd)/$(DIST_DIR)/$$(printf '%s_%s_%s_%s.tar.gz' "$(BINARY)" "$(VERSION)" "$$os" "$$arch")"; \
			(cd "$$dir" && tar --create --gzip --file "$$archive" $(BINARY) LICENSE NOTICE); \
		fi; \
	done

checksums:
	@set -eu; \
	for archive in $(RELEASE_ARCHIVES); do test -f "$$archive"; done; \
	(cd $(DIST_DIR) && $(SHA256_COMMAND) $(RELEASE_ARCHIVE_NAMES) > SHA256SUMS)

release: build
	$(MAKE) package VERSION="$(VERSION)"
	$(MAKE) checksums VERSION="$(VERSION)"

verify-checksums:
	@set -eu; \
	(cd $(DIST_DIR) && $(SHA256_COMMAND) -c SHA256SUMS)

verify-archives:
	@set -eu; \
	for archive in $(DARWIN_ARCHIVES); do \
		test "$$(unzip -Z1 "$$archive" | sort)" = "$$(printf '%s\n' $(BINARY) LICENSE NOTICE | sort)"; \
	done; \
	for archive in $(LINUX_ARCHIVES); do \
		test "$$(tar -tzf "$$archive" | sort)" = "$$(printf '%s\n' $(BINARY) LICENSE NOTICE | sort)"; \
	done

verify-version:
	@set -eu; \
	host_binary="$(DIST_DIR)/$(BINARY)-$$(go env GOOS)-$$(go env GOARCH)"; \
	test -x "$$host_binary"; \
	test "$$($$host_binary --version)" = "$(VERSION)"

verify-release: release
	$(MAKE) verify-checksums VERSION="$(VERSION)"
	$(MAKE) verify-archives VERSION="$(VERSION)"
	$(MAKE) verify-version VERSION="$(VERSION)"

clean:
	rm -rf $(DIST_DIR)
