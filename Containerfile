# PuzzlePod — Multi-stage container build
#
# Build:
#   podman build -t puzzlepod .
#
# Run (interactive shell with puzzled running):
#   podman run --privileged -it puzzlepod
#
# Run all simulator scenarios and exit:
#   podman run --privileged puzzlepod puzzlectl sim --run-all
#
# Q5: Container runs as root because puzzled requires elevated privileges for
# clone3, mount (OverlayFS), cgroup management, and Landlock configuration.
# Agent processes are isolated in separate namespaces with dropped privileges.
#
# NOTE: --privileged is required for kernel primitives (namespaces, cgroups,
# Landlock, seccomp, OverlayFS). Alternatively use specific capabilities:
#
#   podman run --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add BPF \
#              --security-opt seccomp=unconfined -it puzzlepod

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
# T33/T38: TODO — pin base images by digest (@sha256:...) for supply chain integrity.
FROM registry.fedoraproject.org/fedora:42 AS builder

RUN dnf install -y \
        gcc \
        clang \
        llvm \
        make \
        git \
        pkg-config \
        elfutils-libelf-devel \
        zlib-devel \
        libseccomp-devel \
        dbus-devel \
        openssl-devel \
        rust \
        cargo \
        clippy \
        rustfmt \
    && dnf clean all

WORKDIR /build
COPY . .

# Build only the two needed binaries (not the full workspace).
# Override the release profile to reduce memory pressure during linking:
#   - thin LTO instead of fat (less RAM)
#   - 16 codegen units (faster compile, lower peak memory)
#   - -j2 limits parallel rustc jobs to avoid OOM in constrained VMs
ENV CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
RUN cargo fmt --all -- --check
RUN cargo clippy --all --all-targets -- -D warnings # R6: Match CI parity with --all-targets
# V8: Build puzzled and puzzlectl with default features (tui + sim).
# Default features include: tui (interactive terminal UI with ratatui) and
# sim (governance simulator + puzzle-sim-worker binary).
# The --features sim is redundant with defaults but kept for explicitness.
RUN cargo build --release -j2 -p puzzled -p puzzlectl --features sim

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM registry.fedoraproject.org/fedora-minimal:42

RUN microdnf install -y \
        libseccomp \
        dbus-daemon \
        dbus-libs \
        iproute \
        iptables-nft \
        xfsprogs \
        util-linux \
        procps-ng \
        bash \
    && microdnf clean all

# Copy binaries
COPY --from=builder /build/target/release/puzzled /usr/bin/puzzled
COPY --from=builder /build/target/release/puzzlectl /usr/bin/puzzlectl
COPY --from=builder /build/target/release/puzzle-sim-worker /usr/bin/puzzle-sim-worker

# Copy default configuration and policies
# The policy loader scans /etc/puzzled/policies/ (non-recursive), so copy
# the rules/*.rego files directly into the policies directory.
COPY --from=builder /build/policies/rules/ /etc/puzzled/policies/
COPY --from=builder /build/policies/profiles /etc/puzzled/profiles

# Copy agent simulator scenarios
COPY --from=builder /build/examples/scenarios /etc/puzzled/scenarios

# Create runtime directories
RUN mkdir -p /var/lib/puzzled/branches /var/log/puzzled /etc/puzzled /run/dbus /run/puzzled \
    && chmod 0700 /var/lib/puzzled /var/lib/puzzled/branches /var/log/puzzled

# D-Bus policy — allow puzzled to own its bus name and puzzlectl to call it
RUN cat > /etc/dbus-1/system.d/org.lobstertrap.PuzzlePod1.conf << 'EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.lobstertrap.PuzzlePod1"/>
    <allow send_destination="org.lobstertrap.PuzzlePod1"/>
    <allow receive_sender="org.lobstertrap.PuzzlePod1"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.lobstertrap.PuzzlePod1"/>
    <allow receive_sender="org.lobstertrap.PuzzlePod1"/>
  </policy>
</busconfig>
EOF

COPY scripts/entrypoint.sh /usr/bin/entrypoint.sh

# Q6: Removed unused EXPOSE 8080 — no service binds to this port.
# Prometheus metrics endpoint is planned but not yet implemented.

# U44: Container runs as root because puzzled requires CAP_SYS_ADMIN for namespaces,
# OverlayFS, cgroups, and Landlock. Agent processes are isolated in separate namespaces.
# See Q5 comment at top of file.
ENTRYPOINT ["/usr/bin/entrypoint.sh"]
