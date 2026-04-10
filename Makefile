.PHONY: setup build install

setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured. Pre-push hook will run swift build before each push."

build:
	swift build -c release
	codesign -s - -f .build/release/bioenv

install: build
	cp .build/release/bioenv ~/bin/bioenv
