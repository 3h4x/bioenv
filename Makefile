.PHONY: setup build install install-from-source

RELEASE_URL := https://github.com/3h4x/bioenv/releases/latest/download/bioenv-arm64

setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured. Pre-push hook will run swift build before each push."

build:
	swift build -c release
	codesign -s - -f .build/release/bioenv

# Both install targets remove the old binary before writing the new one. Overwriting an
# executable in place (curl -o / cp onto an existing file) keeps the same inode, and macOS
# caches code-signature state per vnode — the next launch dies with
# "SIGKILL (Code Signature Invalid) / Taskgated Invalid Signature" even though
# `codesign --verify` reports the file as valid on disk.
install:
	@mkdir -p ~/bin
	curl -fL $(RELEASE_URL) -o ~/bin/bioenv.tmp
	chmod +x ~/bin/bioenv.tmp
	codesign -s - -f ~/bin/bioenv.tmp
	rm -f ~/bin/bioenv
	mv ~/bin/bioenv.tmp ~/bin/bioenv

install-from-source: build
	@mkdir -p ~/bin
	rm -f ~/bin/bioenv
	cp .build/release/bioenv ~/bin/bioenv
