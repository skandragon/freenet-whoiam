# whoiam build tooling — adapted from freenet-freebird.
# Homebrew rust shadows the rustup toolchain and lacks the wasm32 target, and
# apple's make 3.81 ignores exported PATH on its direct-exec fast path — so
# tools are addressed absolutely.
RUSTUP_BIN := $(HOME)/.rustup/toolchains/stable-aarch64-apple-darwin/bin
CARGO := $(RUSTUP_BIN)/cargo
DX := $(HOME)/.cargo/bin/dx
# wasm-tools may come from cargo or homebrew; a missing binary must FAIL the
# import check, not silently pass it (grep of no output looks "clean").
WASM_TOOLS := $(shell command -v wasm-tools || command -v $(HOME)/.cargo/bin/wasm-tools || echo /opt/homebrew/bin/wasm-tools)
# dx shells out to cargo/rustc — give it the right toolchain first.
export PATH := $(RUSTUP_BIN):$(HOME)/.cargo/bin:$(PATH)

WASM_TARGET := wasm32-unknown-unknown
WASM_DIR := target/$(WASM_TARGET)/release

.PHONY: all contracts delegate ui test check-imports check-addresses pin-hashes publish clean

all: test contracts delegate ui

contracts:
	$(CARGO) build -p identity-contract --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/identity_contract.wasm
	cp $(WASM_DIR)/identity_contract.wasm ui/contracts/
	$(MAKE) check-addresses

delegate:
	$(CARGO) build -p whoiam-delegate --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/whoiam_delegate.wasm
	cp $(WASM_DIR)/whoiam_delegate.wasm ui/contracts/
	$(MAKE) check-addresses

# Contract/delegate addresses are content-derived: if these bytes change,
# every identity's contract address rotates and the delegate key changes —
# published identities and stored seeds become unreachable to the new build.
# Rotation must be a deliberate, reviewed act with a migration story — never
# a rebuild side effect. (Freebird learned this the hard way, 2026-08-10.)
check-addresses:
	@shasum -a 256 -c scripts/wasm-hashes.txt >/dev/null 2>&1 || { \
	  echo "ERROR: contract wasm bytes changed — all derived addresses will ROTATE"; \
	  echo "and published identities / stored seeds become unreachable."; \
	  echo "If this rotation is intentional (with a migration plan), re-pin:"; \
	  echo "  make pin-hashes"; \
	  shasum -a 256 -c scripts/wasm-hashes.txt 2>/dev/null | grep -v ': OK$$'; \
	  exit 1; }
	@echo "contract addresses stable"

pin-hashes:
	shasum -a 256 ui/contracts/*.wasm > scripts/wasm-hashes.txt

# Fail if a wasm imports anything outside the freenet host namespaces —
# a wasm-bindgen placeholder import means the getrandom poison is back
# (freenet/river#241) and the module will not instantiate under wasmtime.
check-imports:
	@test -x "$(WASM_TOOLS)" || { echo "wasm-tools not found — cannot verify imports"; exit 1; }
	@bad=$$($(WASM_TOOLS) print $(W) | grep '(import' | grep -v '"freenet_' || true); \
	if [ -n "$$bad" ]; then echo "FORBIDDEN IMPORTS in $(W):"; echo "$$bad"; exit 1; fi
	@echo "$(W): imports clean"

# The UI embeds the VENDORED wasm in ui/contracts/ (include_bytes) — the
# committed bytes are the source of truth, because compiled bytes are not
# reproducible across toolchains and any byte change rotates every derived
# address. `make contracts`/`make delegate` are the deliberate acts that
# refresh them (guarded by check-addresses); the ui build never does.
ui:
	$(MAKE) check-addresses
	cd ui && $(DX) build --release

test:
	$(CARGO) test --workspace

publish:
	scripts/publish-ui.sh

clean:
	$(CARGO) clean
