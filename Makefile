# ============================================================================
# PuzzlePod — Top-Level Makefile
#
# Targets RHEL 10+, Fedora 42+, CentOS Stream 10 on x86_64 and aarch64.
# All components are userspace-only; no kernel modules required.
# ============================================================================

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------

PREFIX          ?= /usr/local
DESTDIR         ?=
CARGO           ?= cargo
CARGO_FLAGS     ?=
CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
CONTAINER_IMAGE ?= puzzlepod
CONTAINER_TAG   ?= latest

# Derived paths
BINDIR          = $(DESTDIR)$(PREFIX)/bin
DATADIR         = $(DESTDIR)$(PREFIX)/share
MANDIR          = $(DATADIR)/man
POLICYDIR       = $(DATADIR)/puzzled/policies
# System config paths — these must be /etc and /usr/lib/systemd regardless of PREFIX
SYSCONFDIR      = $(DESTDIR)/etc
UNITDIR         = $(DESTDIR)/usr/lib/systemd/system
DBUSCONFDIR     = $(SYSCONFDIR)/dbus-1/system.d

# Version from puzzled crate
VERSION         = $(shell grep '^version' crates/puzzled/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Colors for help output
BOLD            = \033[1m
CYAN            = \033[36m
GREEN           = \033[32m
YELLOW          = \033[33m
RESET           = \033[0m

# Root check helper
define REQUIRE_ROOT
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: 'make $(1)' requires root privileges. Run with sudo."; \
		exit 1; \
	fi
endef

# Container engine check helper
define REQUIRE_CONTAINER_ENGINE
	@if [ -z "$(CONTAINER_ENGINE)" ]; then \
		echo "Error: Neither podman nor docker found. Install one to use container targets."; \
		exit 1; \
	fi
endef

# ----------------------------------------------------------------------------
# Default target
# ----------------------------------------------------------------------------

.DEFAULT_GOAL := all

# ----------------------------------------------------------------------------
# .PHONY declarations
# ----------------------------------------------------------------------------

.PHONY: all build release release-full bpf selinux
.PHONY: check lint fmt fmt-check clippy deny audit
.PHONY: test test-unit test-integration test-dbus test-security test-all
.PHONY: container image container-ci container-run
.PHONY: install install-bin install-config install-policies uninstall
.PHONY: install-selinux install-systemd install-dbus install-man
.PHONY: dev-setup dev-start dev-stop
.PHONY: srpm srpm-all rpm rpm-lint
.PHONY: docs man
.PHONY: clean clean-all distclean
.PHONY: help version check-deps ci

# ============================================================================
# Build targets
# ============================================================================

## Build everything (Rust workspace + BPF + SELinux)
all: build bpf selinux

## Build Rust workspace (debug)
build:
	$(CARGO) build --workspace $(CARGO_FLAGS)

## Build Rust workspace — edge-optimized release (opt-level=s, LTO, strip)
release:
	$(CARGO) build --workspace --profile release $(CARGO_FLAGS)

## Build Rust workspace — data center release (opt-level=2, unwind, symbols)
release-full:
	$(CARGO) build --workspace --profile release-full $(CARGO_FLAGS)

## Build BPF programs (delegates to bpf/Makefile)
bpf:
	$(MAKE) -C bpf all

## Build SELinux policy module (delegates to selinux/Makefile)
selinux:
	$(MAKE) -C selinux all

# ============================================================================
# Quality targets
# ============================================================================

## Run all lints (cargo fmt --check + clippy)
check: fmt-check clippy
lint: check

fmt-check:
	$(CARGO) fmt --all -- --check

## Format all Rust code
fmt:
	$(CARGO) fmt --all

## Run clippy with warnings as errors
clippy:
	$(CARGO) clippy --workspace --all-targets $(CARGO_FLAGS) -- -D warnings

## Run cargo-deny license and dependency checks
deny:
	cargo-deny check

## Run cargo-deny advisory database check
audit:
	cargo-deny check advisories

# ============================================================================
# Test targets
# ============================================================================

## Run unit tests (excludes live_dbus_integration)
test:
	$(CARGO) test -p puzzled --lib $(CARGO_FLAGS)
	$(CARGO) test -p puzzled $(CARGO_FLAGS) \
		--test dbus_validation --test diff_engine --test crash_recovery \
		--test ima_integration --test phase2_features --test policy_evaluation \
		--test profile_validation --test seccomp_validation --test security_hardening \
		--test wal_recovery_execution --test wal_recovery --test wal_safety
	$(CARGO) test -p puzzlectl $(CARGO_FLAGS)
	$(CARGO) test -p puzzled-types $(CARGO_FLAGS)
	$(CARGO) test -p puzzle-proxy $(CARGO_FLAGS) # R4: Include all crate tests
	$(CARGO) test -p puzzle-hook $(CARGO_FLAGS) # R4: Include all crate tests
	$(CARGO) test -p puzzle-init $(CARGO_FLAGS) # R4: Include all crate tests

## Alias for test
test-unit: test

## Run integration tests including ignored (requires root, single-threaded)
test-integration:
	$(call REQUIRE_ROOT,$@)
	$(CARGO) test -p puzzled --lib $(CARGO_FLAGS) -- --include-ignored --test-threads=1
	$(CARGO) test -p puzzled $(CARGO_FLAGS) \
		--test branch_lifecycle --test concurrent_branches --test sandbox_containment \
		--test e2e_adversarial --test e2e_scenarios --test crash_recovery \
		--test fanotify_monitoring --test bpf_lsm_hooks --test rogue_agent \
		--test seccomp_notif_handler \
		--test dbus_validation --test diff_engine --test ima_integration \
		--test phase2_features --test policy_evaluation --test profile_validation \
		--test seccomp_validation --test security_hardening \
		--test wal_recovery_execution --test wal_recovery --test wal_safety \
		--test podman_native_integration --test cross_module_integration \
		-- --include-ignored --test-threads=1
	$(CARGO) test -p puzzlectl $(CARGO_FLAGS) -- --include-ignored --test-threads=1
	$(CARGO) test -p puzzled-types $(CARGO_FLAGS) -- --include-ignored --test-threads=1

## Run live D-Bus integration tests (requires running puzzled)
test-dbus:
	$(CARGO) test -p puzzled --test live_dbus_integration $(CARGO_FLAGS) -- --test-threads=1

## Run security escape tests (requires root)
test-security:
	$(call REQUIRE_ROOT,$@)
	tests/security/run_all.sh

## Run the full test suite via scripts/run_all_tests.sh (requires root)
test-all:
	$(call REQUIRE_ROOT,$@)
	scripts/run_all_tests.sh

# ============================================================================
# Container targets
# ============================================================================

## Build container image from root Containerfile
container:
	$(call REQUIRE_CONTAINER_ENGINE)
	$(CONTAINER_ENGINE) build -t $(CONTAINER_IMAGE):$(CONTAINER_TAG) .

## Alias for container
image: container

## Build CI container image from ci/Containerfile
container-ci:
	$(call REQUIRE_CONTAINER_ENGINE)
	$(CONTAINER_ENGINE) build -t $(CONTAINER_IMAGE)-ci:$(CONTAINER_TAG) -f ci/Containerfile .

## Run the container image interactively with --privileged
container-run:
	$(call REQUIRE_CONTAINER_ENGINE)
	$(CONTAINER_ENGINE) run --privileged --rm -it $(CONTAINER_IMAGE):$(CONTAINER_TAG)

# ============================================================================
# Install targets
# ============================================================================

## Install binaries, configs, man pages, systemd units, D-Bus config, policies
install: install-bin install-config install-man install-systemd install-dbus install-policies

install-bin:
	@test -f target/release/puzzled || { echo "Error: Release binaries not found. Run 'make release' first."; exit 1; }
	install -d $(BINDIR)
	install -m 0755 target/release/puzzled    $(BINDIR)/puzzled
	install -m 0755 target/release/puzzlectl  $(BINDIR)/puzzlectl
	install -m 0755 podman/puzzle-podman      $(BINDIR)/puzzle-podman

install-config:
	install -d $(SYSCONFDIR)/puzzled
	install -m 0644 config/puzzled.conf.example $(SYSCONFDIR)/puzzled/puzzled.conf.example

## Install systemd unit files
install-systemd:
	install -d $(UNITDIR)
	install -m 0644 systemd/puzzled.service  $(UNITDIR)/puzzled.service
	install -m 0644 systemd/puzzle@.service  $(UNITDIR)/puzzle@.service
	install -m 0644 systemd/puzzle.slice     $(UNITDIR)/puzzle.slice

## Install D-Bus configuration
install-dbus:
	install -d $(DBUSCONFDIR)
	install -m 0644 dbus/org.lobstertrap.PuzzlePod1.conf $(DBUSCONFDIR)/org.lobstertrap.PuzzlePod1.conf
	install -d $(DATADIR)/dbus-1/interfaces
	install -m 0644 dbus/org.lobstertrap.PuzzlePod1.Manager.xml $(DATADIR)/dbus-1/interfaces/org.lobstertrap.PuzzlePod1.Manager.xml

## Install man pages
install-man:
	install -d $(MANDIR)/man1 $(MANDIR)/man5 $(MANDIR)/man8
	install -m 0644 man/puzzlectl.1      $(MANDIR)/man1/puzzlectl.1
	install -m 0644 man/puzzled.8        $(MANDIR)/man8/puzzled.8
	install -m 0644 man/puzzled.conf.5   $(MANDIR)/man5/puzzled.conf.5
	install -m 0644 man/puzzlepod-profile.5 $(MANDIR)/man5/puzzlepod-profile.5

install-policies:
	install -d $(POLICYDIR)/profiles $(POLICYDIR)/rules $(POLICYDIR)/schemas
	install -m 0644 policies/profiles/*.yaml  $(POLICYDIR)/profiles/
	install -m 0644 policies/rules/*.rego     $(POLICYDIR)/rules/
	install -m 0644 policies/schemas/*.json   $(POLICYDIR)/schemas/

## Install SELinux policy module (delegates to selinux/Makefile)
install-selinux:
	$(MAKE) -C selinux install

## Uninstall all installed files
uninstall:
	rm -f  $(BINDIR)/puzzled $(BINDIR)/puzzlectl $(BINDIR)/puzzle-podman
	rm -rf $(SYSCONFDIR)/puzzled
	rm -f  $(UNITDIR)/puzzled.service $(UNITDIR)/puzzle@.service $(UNITDIR)/puzzle.slice
	rm -f  $(DBUSCONFDIR)/org.lobstertrap.PuzzlePod1.conf
	rm -f  $(DATADIR)/dbus-1/interfaces/org.lobstertrap.PuzzlePod1.Manager.xml
	rm -f  $(MANDIR)/man1/puzzlectl.1 $(MANDIR)/man8/puzzled.8
	rm -f  $(MANDIR)/man5/puzzled.conf.5 $(MANDIR)/man5/puzzlepod-profile.5
	rm -rf $(POLICYDIR)

# ============================================================================
# Development targets
# ============================================================================

## Set up development environment (requires root)
dev-setup:
	$(call REQUIRE_ROOT,$@)
	scripts/dev-setup.sh setup

## Start development puzzled instance (requires root)
dev-start:
	$(call REQUIRE_ROOT,$@)
	scripts/dev-setup.sh start

## Stop development puzzled instance (requires root)
dev-stop:
	$(call REQUIRE_ROOT,$@)
	scripts/dev-setup.sh stop

# ============================================================================
# Packaging targets
# ============================================================================

## Build source RPM via .copr/Makefile
srpm:
	$(MAKE) -C .copr srpm

## Build all source RPMs for local development
srpm-all:
	packaging/build-srpm.sh

## Build binary RPMs locally via mock
rpm: srpm-all
	@FEDORA_VER=$$(. /etc/os-release 2>/dev/null && echo "$${VERSION_ID}"); \
	if [ -z "$$FEDORA_VER" ] || [ "$$(. /etc/os-release 2>/dev/null && echo "$$ID")" != "fedora" ]; then \
		FEDORA_VER=42; \
		echo "Not on Fedora — using fedora-$$FEDORA_VER mock profile"; \
	fi; \
	ARCH=$$(uname -m); \
	MOCK_ROOT="fedora-$${FEDORA_VER}-$${ARCH}"; \
	echo "=== Building RPMs with mock ($$MOCK_ROOT) ==="; \
	mkdir -p packaging/rpms; \
	FAILED=""; \
	for srpm in packaging/srpms/*.src.rpm; do \
		echo "--- mock: $$srpm ---"; \
		if mock -r "$$MOCK_ROOT" --enable-network --isolation=simple --rebuild "$$srpm" --resultdir=packaging/rpms/; then \
			echo "--- OK: $$srpm ---"; \
		else \
			echo "--- FAILED: $$srpm ---"; \
			FAILED="$$FAILED $$srpm"; \
		fi; \
	done; \
	echo ""; \
	echo "=== RPMs built ==="; \
	ls -1 packaging/rpms/*.rpm 2>/dev/null || true; \
	if [ -n "$$FAILED" ]; then \
		echo ""; \
		echo "=== FAILED builds ==="; \
		for f in $$FAILED; do echo "  $$f"; done; \
		exit 1; \
	fi

## Lint RPM spec files with rpmlint
rpm-lint:
	rpmlint packaging/*.spec

# ============================================================================
# Documentation targets
# ============================================================================

## Generate Rust API documentation
docs:
	$(CARGO) doc --workspace --no-deps $(CARGO_FLAGS)

## Install man pages (alias for install-man)
man: install-man

# ============================================================================
# Cleanup targets
# ============================================================================

## Remove build artifacts (Rust + BPF + SELinux)
clean:
	$(CARGO) clean
	$(MAKE) -C bpf clean
	$(MAKE) -C selinux clean

## Clean everything including runtime state (WARNING: deletes branch data)
clean-all: clean
	$(MAKE) -C selinux clean-all 2>/dev/null || true
	rm -rf /var/lib/puzzled/branches/* 2>/dev/null || true
	rm -rf /run/puzzled 2>/dev/null || true

## Full clean including Cargo.lock
distclean: clean-all
	rm -f Cargo.lock

# ============================================================================
# Utility targets
# ============================================================================

## Print version information
version:
	@echo "PuzzlePod v$(VERSION)"
	@echo "Rust toolchain: $$(rustc --version 2>/dev/null || echo 'not found')"
	@echo "Cargo: $$($(CARGO) --version 2>/dev/null || echo 'not found')"

## Verify required build dependencies are installed
check-deps:
	@echo "Checking build dependencies..."
	@command -v cargo    >/dev/null 2>&1 && echo "  [ok] cargo"    || echo "  [MISSING] cargo"
	@command -v rustc    >/dev/null 2>&1 && echo "  [ok] rustc"    || echo "  [MISSING] rustc"
	@command -v clang    >/dev/null 2>&1 && echo "  [ok] clang"    || echo "  [MISSING] clang (needed for BPF)"
	@command -v llvm-strip >/dev/null 2>&1 && echo "  [ok] llvm-strip" || echo "  [MISSING] llvm-strip (needed for BPF)"
	@command -v cargo-deny >/dev/null 2>&1 && echo "  [ok] cargo-deny" || echo "  [MISSING] cargo-deny (optional, for 'make deny')"
	@command -v rpmlint  >/dev/null 2>&1 && echo "  [ok] rpmlint"  || echo "  [MISSING] rpmlint (optional, for 'make rpm-lint')"
	@command -v mock     >/dev/null 2>&1 && echo "  [ok] mock"     || echo "  [MISSING] mock (optional, for 'make rpm')"
	@command -v podman   >/dev/null 2>&1 && echo "  [ok] podman"   || echo "  [MISSING] podman (optional, for container targets)"
	@command -v semodule >/dev/null 2>&1 && echo "  [ok] semodule" || echo "  [MISSING] semodule (optional, for SELinux targets)"
	@echo "Done."

## Run the same checks as CI (fmt + clippy + test + deny)
ci: check test deny

## Print all available targets with descriptions
help:
	@echo ""
	@printf "$(BOLD)PuzzlePod v$(VERSION) — Makefile Targets$(RESET)\n"
	@echo ""
	@printf "$(CYAN)Build:$(RESET)\n"
	@printf "  $(GREEN)make$(RESET)                 Build everything (Rust + BPF + SELinux)\n"
	@printf "  $(GREEN)make build$(RESET)            Build Rust workspace (debug)\n"
	@printf "  $(GREEN)make release$(RESET)          Build edge-optimized release (opt-level=s, LTO, strip)\n"
	@printf "  $(GREEN)make release-full$(RESET)     Build data center release (opt-level=2, symbols)\n"
	@printf "  $(GREEN)make bpf$(RESET)              Build BPF programs\n"
	@printf "  $(GREEN)make selinux$(RESET)          Build SELinux policy module\n"
	@echo ""
	@printf "$(CYAN)Quality:$(RESET)\n"
	@printf "  $(GREEN)make check$(RESET)            Run fmt --check + clippy (alias: make lint)\n"
	@printf "  $(GREEN)make fmt$(RESET)              Format all Rust code\n"
	@printf "  $(GREEN)make clippy$(RESET)           Run clippy with -D warnings\n"
	@printf "  $(GREEN)make deny$(RESET)             Run cargo-deny license and dependency checks\n"
	@printf "  $(GREEN)make audit$(RESET)            Run cargo-deny advisory database check\n"
	@echo ""
	@printf "$(CYAN)Testing:$(RESET)\n"
	@printf "  $(GREEN)make test$(RESET)             Run unit tests (alias: make test-unit)\n"
	@printf "  $(GREEN)make test-integration$(RESET) Run integration tests $(YELLOW)[requires root]$(RESET)\n"
	@printf "  $(GREEN)make test-dbus$(RESET)        Run live D-Bus integration tests $(YELLOW)[requires running puzzled]$(RESET)\n"
	@printf "  $(GREEN)make test-security$(RESET)    Run security escape tests $(YELLOW)[requires root]$(RESET)\n"
	@printf "  $(GREEN)make test-all$(RESET)         Run full test suite $(YELLOW)[requires root]$(RESET)\n"
	@echo ""
	@printf "$(CYAN)Containers:$(RESET)\n"
	@printf "  $(GREEN)make container$(RESET)        Build container image (alias: make image)\n"
	@printf "  $(GREEN)make container-ci$(RESET)     Build CI container image\n"
	@printf "  $(GREEN)make container-run$(RESET)    Run container interactively with --privileged\n"
	@echo ""
	@printf "$(CYAN)Install:$(RESET)\n"
	@printf "  $(GREEN)make install$(RESET)          Install binaries, configs, man pages, units, policies\n"
	@printf "  $(GREEN)make uninstall$(RESET)        Remove all installed files\n"
	@printf "  $(GREEN)make install-selinux$(RESET)  Install SELinux policy module\n"
	@printf "  $(GREEN)make install-systemd$(RESET)  Install systemd unit files\n"
	@printf "  $(GREEN)make install-dbus$(RESET)     Install D-Bus configuration\n"
	@printf "  $(GREEN)make install-man$(RESET)      Install man pages\n"
	@echo ""
	@printf "$(CYAN)Development:$(RESET)\n"
	@printf "  $(GREEN)make dev-setup$(RESET)        Set up dev environment $(YELLOW)[requires root]$(RESET)\n"
	@printf "  $(GREEN)make dev-start$(RESET)        Start dev puzzled instance $(YELLOW)[requires root]$(RESET)\n"
	@printf "  $(GREEN)make dev-stop$(RESET)         Stop dev puzzled instance $(YELLOW)[requires root]$(RESET)\n"
	@echo ""
	@printf "$(CYAN)Packaging:$(RESET)\n"
	@printf "  $(GREEN)make srpm$(RESET)             Build source RPM (single, via .copr/Makefile)\n"
	@printf "  $(GREEN)make srpm-all$(RESET)         Build all source RPMs for local development\n"
	@printf "  $(GREEN)make rpm$(RESET)              Build binary RPMs locally via mock\n"
	@printf "  $(GREEN)make rpm-lint$(RESET)          Lint RPM spec files\n"
	@echo ""
	@printf "$(CYAN)Documentation:$(RESET)\n"
	@printf "  $(GREEN)make docs$(RESET)             Generate Rust API documentation\n"
	@printf "  $(GREEN)make man$(RESET)              Install man pages\n"
	@echo ""
	@printf "$(CYAN)Cleanup:$(RESET)\n"
	@printf "  $(GREEN)make clean$(RESET)            Remove build artifacts\n"
	@printf "  $(GREEN)make clean-all$(RESET)        Clean + remove runtime state $(YELLOW)[deletes branch data]$(RESET)\n"
	@printf "  $(GREEN)make distclean$(RESET)        Full clean including Cargo.lock\n"
	@echo ""
	@printf "$(CYAN)Utility:$(RESET)\n"
	@printf "  $(GREEN)make help$(RESET)             Show this help message\n"
	@printf "  $(GREEN)make version$(RESET)          Print version info\n"
	@printf "  $(GREEN)make check-deps$(RESET)       Verify build dependencies are installed\n"
	@printf "  $(GREEN)make ci$(RESET)               Run CI checks (fmt + clippy + test + deny)\n"
	@echo ""
	@printf "$(CYAN)Variables:$(RESET)\n"
	@printf "  PREFIX=$(PREFIX)  DESTDIR=$(DESTDIR)  CARGO=$(CARGO)\n"
	@printf "  CONTAINER_ENGINE=$(CONTAINER_ENGINE)\n"
	@printf "  CONTAINER_IMAGE=$(CONTAINER_IMAGE)  CONTAINER_TAG=$(CONTAINER_TAG)\n"
	@echo ""
