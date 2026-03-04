INSTALL_DIR := $(HOME)/.cargo/bin

.PHONY: build install clean

build:
	cargo build --release

install: build
	cp target/release/shush $(INSTALL_DIR)/shush
	@echo "Installed shush to $(INSTALL_DIR)/shush"

clean:
	cargo clean
