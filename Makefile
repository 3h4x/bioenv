.PHONY: setup build install install-from-source

RELEASE_URL := https://github.com/3h4x/bioenv/releases/latest/download/bioenv-arm64

setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured. Pre-push hook will run swift build before each push."

build:
	swift build -c release
	codesign -s - -f .build/release/bioenv

install:
	@mkdir -p ~/bin
	curl -fL $(RELEASE_URL) -o ~/bin/bioenv
	chmod +x ~/bin/bioenv
	codesign -s - -f ~/bin/bioenv

install-from-source: build
	@mkdir -p ~/bin
	cp .build/release/bioenv ~/bin/bioenv
