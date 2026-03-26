#!/bin/bash
#
# libvirt-dev.sh -- libvirt/KVM VM convenience script for PuzzlePod development
#
# Fedora Linux equivalent of scripts/lima-dev.sh (macOS/Lima).
# Creates a Fedora 42 VM with all kernel primitives required by puzzled,
# rsyncs the project source into the VM, and runs demos inside it.
#
# Runs entirely as your user (qemu:///session) -- no sudo required for VM
# management. The demos themselves run as root inside the VM via the 'fedora'
# user's passwordless sudo.
#
# Prerequisites:
#   sudo dnf install libvirt virt-install qemu-kvm rsync
#   sudo systemctl enable --now libvirtd
#
# Usage:
#   ./scripts/libvirt-dev.sh setup      # Create + start VM, sync source (idempotent)
#   ./scripts/libvirt-dev.sh shell      # SSH into VM at project directory
#   ./scripts/libvirt-dev.sh sync       # Rsync project source into VM
#   ./scripts/libvirt-dev.sh build      # cargo build --workspace --release inside VM
#   ./scripts/libvirt-dev.sh test       # cargo test --workspace inside VM
#   ./scripts/libvirt-dev.sh security   # sudo tests/security/run_all.sh inside VM
#   ./scripts/libvirt-dev.sh demo <name> # Run a demo inside VM (phase1|phase2|sandbox|e2e|rootless|tui)
#   ./scripts/libvirt-dev.sh stop       # Shutdown VM
#   ./scripts/libvirt-dev.sh start      # Start a stopped VM
#   ./scripts/libvirt-dev.sh destroy    # Delete VM and all storage
#   ./scripts/libvirt-dev.sh status     # Show VM status
#   ./scripts/libvirt-dev.sh ssh [cmd]  # Run a command via SSH (or open shell)

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VM_NAME="puzzled-dev"
VM_USER="fedora"
VM_MEMORY=8192   # MiB
VM_VCPUS=4
VM_DISK_SIZE=50  # GiB

# All storage under user's home -- no root needed
VM_DIR="${HOME}/.local/share/puzzled-dev-vm"
DISK_PATH="${VM_DIR}/${VM_NAME}.qcow2"
SSH_KEY="${VM_DIR}/id_ed25519"
CLOUD_INIT_USERDATA="${PROJECT_DIR}/puzzled-dev-libvirt.yaml"

# Fedora Cloud image (same as puzzled-dev.yaml for Lima)
FEDORA_ARCH="$(uname -m)"
FEDORA_QCOW2_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/${FEDORA_ARCH}/images/Fedora-Cloud-Base-Generic-42-1.1.${FEDORA_ARCH}.qcow2"
FEDORA_QCOW2="${VM_DIR}/Fedora-Cloud-Base-Generic-42-1.1.${FEDORA_ARCH}.qcow2"

# libvirt connection -- user session, no root required
LIBVIRT_URI="qemu:///session"
VIRSH=(virsh --connect "${LIBVIRT_URI}")
VIRT_INSTALL=(virt-install --connect "${LIBVIRT_URI}")

# SSH port forwarding -- session VMs use passt networking.
# We forward a host port to guest port 22.
SSH_HOST_PORT="${SSH_HOST_PORT:-2222}"
SSH_OPTS=(-i "${SSH_KEY}" -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=${VM_DIR}/known_hosts" -o LogLevel=ERROR -p "${SSH_HOST_PORT}")

# Remote project path inside the VM
VM_PROJECT_DIR="/home/${VM_USER}/puzzlepod"

# Timeouts
PROVISION_TIMEOUT=900   # 15 minutes
RUST_POLL_INTERVAL=15
SSH_CONNECT_TIMEOUT=600 # 10 minutes for VM to become SSH-reachable

# --- Helpers ---
die() { echo "Error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# Validate SSH_HOST_PORT early (after die() is defined)
if ! [[ "$SSH_HOST_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_HOST_PORT" -lt 1024 ] || [ "$SSH_HOST_PORT" -gt 65535 ]; then
    die "SSH_HOST_PORT must be a number between 1024 and 65535, got '$SSH_HOST_PORT'"
fi

check_prerequisites() {
    local missing=()
    for cmd in virsh virt-install qemu-img rsync; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing required commands: ${missing[*]}
Install with: sudo dnf install libvirt virt-install qemu-kvm rsync
Then: sudo systemctl enable --now libvirtd"
    fi

    # Check libvirtd is running
    if ! systemctl is-active --quiet libvirtd; then
        die "libvirtd is not running. Start with: sudo systemctl enable --now libvirtd"
    fi

    # Check the SSH host port is not already in use (by something other than us)
    if ss -tlnH sport = ":${SSH_HOST_PORT}" 2>/dev/null | grep -q .; then
        local state
        state="$(vm_state)"
        if [ "$state" != "running" ]; then
            die "Port ${SSH_HOST_PORT} is already in use. Set SSH_HOST_PORT to a different value or free the port."
        fi
    fi
}

vm_state() {
    local raw
    raw=$("${VIRSH[@]}" domstate "$VM_NAME" 2>/dev/null) && echo "$raw" | xargs || echo "not-found"
}

wait_for_ssh() {
    info "Waiting for VM to become SSH-reachable (up to ${SSH_CONNECT_TIMEOUT}s)..."
    local elapsed=0
    while [ $elapsed -lt $SSH_CONNECT_TIMEOUT ]; do
        if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=3 "${VM_USER}@localhost" true 2>/dev/null; then
            info "SSH connection established (localhost:${SSH_HOST_PORT})"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        if (( elapsed % 30 == 0 )); then
            echo "  ... still waiting (${elapsed}s / ${SSH_CONNECT_TIMEOUT}s)"
        fi
    done
    die "Timed out waiting for SSH after ${SSH_CONNECT_TIMEOUT}s"
}

wait_for_provisioning() {
    info "Waiting for cloud-init provisioning to complete (up to ${PROVISION_TIMEOUT}s)..."
    local elapsed=0
    while [ $elapsed -lt $PROVISION_TIMEOUT ]; do
        if run_ssh "test -f /var/lib/cloud/instance/puzzled-dev-ready" 2>/dev/null; then
            info "Provisioning complete."
            return 0
        fi
        sleep "$RUST_POLL_INTERVAL"
        elapsed=$((elapsed + RUST_POLL_INTERVAL))
        if (( elapsed % 60 == 0 )); then
            echo "  ... still provisioning (${elapsed}s / ${PROVISION_TIMEOUT}s)"
        fi
    done
    die "Timed out waiting for provisioning after ${PROVISION_TIMEOUT}s"
}

run_ssh() {
    ssh "${SSH_OPTS[@]}" "${VM_USER}@localhost" "$@"
}

# NOTE: $1 is evaluated by the remote shell. Only pass trusted, hardcoded command strings.
run_in_vm() {
    run_ssh "cd ${VM_PROJECT_DIR} && $1"
}

ensure_running() {
    local state
    state="$(vm_state)"
    case "$state" in
        running) ;;
        *) die "VM '$VM_NAME' is not running (state: $state). Run: ./scripts/libvirt-dev.sh setup" ;;
    esac
}

# --- Commands ---

cmd_setup() {
    check_prerequisites

    local state
    state="$(vm_state)"

    case "$state" in
        running)
            info "VM '$VM_NAME' is already running."
            wait_for_ssh
            cmd_sync
            return 0
            ;;
        "shut off")
            info "VM '$VM_NAME' exists but is stopped. Starting..."
            "${VIRSH[@]}" start "$VM_NAME"
            wait_for_ssh
            cmd_sync
            return 0
            ;;
        not-found)
            ;;
        *)
            die "VM '$VM_NAME' is in unexpected state: $state"
            ;;
    esac

    info "Creating VM '$VM_NAME'..."
    mkdir -p "$VM_DIR"
    chmod 700 "$VM_DIR"

    # --- Generate SSH key if needed ---
    if [ ! -f "$SSH_KEY" ]; then
        info "Generating SSH key pair..."
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "puzzled-dev-vm"
    fi
    local ssh_pubkey
    ssh_pubkey=$(cat "${SSH_KEY}.pub")

    # --- Download Fedora Cloud image if needed ---
    local expected_sha256=""
    case "$FEDORA_ARCH" in
        x86_64)  expected_sha256="e401a4db2e5e04d1967b6729774faa96da629bcf3ba90b67d8d9cce9906bec0f" ;;
        aarch64) expected_sha256="e10658419a8d50231037dc781c3155aa94180a8c7a74e5cac2a6b09eaa9342b7" ;;
        *)       warn "No known checksum for ${FEDORA_ARCH} — skipping verification" ;;
    esac
    if [ ! -f "$FEDORA_QCOW2" ]; then
        info "Downloading Fedora 42 Cloud image for ${FEDORA_ARCH}..."
        curl -fL -o "$FEDORA_QCOW2" "$FEDORA_QCOW2_URL"
    fi
    # Verify image integrity on every setup (catches partial downloads from
    # interrupted previous runs).
    if [ -n "${expected_sha256}" ]; then
        info "Verifying SHA256 checksum..."
        echo "${expected_sha256}  ${FEDORA_QCOW2}" | sha256sum -c - || {
            rm -f "$FEDORA_QCOW2"
            die "SHA256 checksum verification failed for ${FEDORA_QCOW2}. File removed — re-run setup to download again."
        }
    fi

    # --- Create VM disk (backed by cloud image) ---
    info "Creating VM disk (${VM_DISK_SIZE}G)..."
    qemu-img create -f qcow2 -b "$FEDORA_QCOW2" -F qcow2 "$DISK_PATH" "${VM_DISK_SIZE}G"

    # --- Prepare cloud-init user-data ---
    # Inject SSH key into the cloud-init template
    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064  # Intentional: expand $tmpdir now
    trap "rm -rf -- \"$tmpdir\"" EXIT
    awk -v key="$ssh_pubkey" '{gsub(/REPLACE_WITH_SSH_PUBKEY/, key); print}' "$CLOUD_INIT_USERDATA" > "${tmpdir}/user-data"

    # --- Determine OS variant ---
    local os_variant="fedora-unknown"
    if virt-install --os-variant list 2>/dev/null | grep -q "fedora42"; then
        os_variant="fedora42"
    elif virt-install --osinfo list 2>/dev/null | grep -q "fedora42"; then
        os_variant="fedora42"
    fi

    # --- Create and start the VM ---
    # Uses QEMU's built-in SLiRP user networking (no passt, no SELinux issues,
    # no root required). SSH port forwarding is added via QEMU monitor after boot.
    # virt-install --cloud-init handles the NoCloud datasource ISO internally.
    info "Running virt-install..."
    "${VIRT_INSTALL[@]}" \
        --name "$VM_NAME" \
        --memory "$VM_MEMORY" \
        --vcpus "$VM_VCPUS" \
        --os-variant "$os_variant" \
        --disk "path=${DISK_PATH},format=qcow2" \
        --network user,model=virtio \
        --cloud-init "user-data=${tmpdir}/user-data" \
        --noautoconsole \
        --import

    rm -rf "$tmpdir"
    trap - EXIT

    # Add SSH port forwarding via QEMU monitor (SLiRP hostfwd).
    info "Adding SSH port forwarding (host:${SSH_HOST_PORT} -> guest:22)..."
    local retries=0
    while [ $retries -lt 15 ]; do
        if "${VIRSH[@]}" qemu-monitor-command "$VM_NAME" --hmp \
            "hostfwd_add hostnet0 tcp::${SSH_HOST_PORT}-:22" 2>/dev/null; then
            break
        fi
        retries=$((retries + 1))
        sleep 1
    done
    if [ $retries -eq 15 ]; then
        die "Failed to add SSH port forwarding after 15 attempts"
    fi

    wait_for_ssh
    wait_for_provisioning

    # Sync source into the VM
    cmd_sync

    info ""
    info "VM '$VM_NAME' is ready."
    info "  Shell:    ./scripts/libvirt-dev.sh shell"
    info "  Sync:     ./scripts/libvirt-dev.sh sync"
    info "  Build:    ./scripts/libvirt-dev.sh build"
    info "  Demo:     ./scripts/libvirt-dev.sh demo phase1"
}

cmd_sync() {
    ensure_running
    info "Syncing project source into VM..."
    rsync -az --delete \
        --exclude='target/' \
        --exclude='.git/' \
        --exclude='*.o' \
        --exclude='*.so' \
        --exclude='*.d' \
        -e "ssh ${SSH_OPTS[*]}" \
        "${PROJECT_DIR}/" \
        "${VM_USER}@localhost:${VM_PROJECT_DIR}/"
    info "Sync complete."
}

cmd_shell() {
    ensure_running
    ssh "${SSH_OPTS[@]}" \
        -t "${VM_USER}@localhost" \
        "cd ${VM_PROJECT_DIR} && exec bash -l"
}

cmd_ssh() {
    ensure_running
    if [ $# -eq 0 ]; then
        cmd_shell
    else
        run_ssh "$@"
    fi
}

cmd_build() {
    ensure_running
    info "Building workspace in VM..."
    run_in_vm 'cargo build --workspace --release'
}

cmd_test() {
    ensure_running
    info "Running tests in VM..."
    run_in_vm 'cargo test --workspace'
}

cmd_security() {
    ensure_running
    info "Running security tests in VM (requires root)..."
    run_in_vm 'sudo -E env PATH="$PATH" bash tests/security/run_all.sh'
}

cmd_demo() {
    ensure_running
    local demo_name="${1:-}"
    if [ -z "$demo_name" ]; then
        echo "Usage: $(basename "$0") demo <name>"
        echo ""
        echo "Available demos:"
        echo "  phase1    Phase 1: Core Fork-Explore-Commit lifecycle"
        echo "  phase2    Phase 2: Hardening features"
        echo "  sandbox   Sandbox Live: real agent under kernel enforcement"
        echo "  e2e       E2E Governance: trust scoring, provenance, attestation"
        echo "  rootless  Rootless: governance without root (fuse-overlayfs, session bus)"
        echo "  tui       TUI: interactive terminal UI with live governance events"
        echo "  all       Run all demos sequentially (excludes tui)"
        exit 1
    fi

    case "$demo_name" in
        phase1)
            info "Running Phase 1 demo in VM..."
            # Use -t for TTY allocation (enables color output and interactive prompts)
            ssh "${SSH_OPTS[@]}" -t "${VM_USER}@localhost" \
                "cd ${VM_PROJECT_DIR} && sudo -E env PATH=\"\$PATH\" demo/run_demo_phase1.sh"
            ;;
        phase2)
            info "Running Phase 2 demo in VM..."
            ssh "${SSH_OPTS[@]}" -t "${VM_USER}@localhost" \
                "cd ${VM_PROJECT_DIR} && sudo -E env PATH=\"\$PATH\" demo/run_demo_phase2.sh"
            ;;
        sandbox)
            info "Running Sandbox Live demo in VM (setting up + starting puzzled first)..."
            ssh "${SSH_OPTS[@]}" -t "${VM_USER}@localhost" 'bash -s' << 'SANDBOX_SCRIPT'
cd ~/puzzlepod
sudo -E env PATH="$PATH" bash -c '
    cd ~/puzzlepod
    scripts/dev-setup.sh setup
    scripts/dev-setup.sh start &
    PUZZLED_PID=$!
    sleep 5
    demo/sandbox-live-demo.sh
    EXIT_CODE=$?
    scripts/dev-setup.sh stop 2>/dev/null || true
    wait $PUZZLED_PID 2>/dev/null || true
    exit $EXIT_CODE
'
SANDBOX_SCRIPT
            ;;
        e2e)
            info "Running E2E Governance demo in VM..."
            ssh "${SSH_OPTS[@]}" -t "${VM_USER}@localhost" \
                "cd ${VM_PROJECT_DIR} && sudo -E env PATH=\"\$PATH\" demo/e2e_governance_demo.sh"
            ;;
        rootless)
            info "Running Rootless demo in VM (as unprivileged user)..."
            ssh "${SSH_OPTS[@]}" -t "${VM_USER}@localhost" \
                "cd ${VM_PROJECT_DIR} && demo/run_demo_rootless.sh"
            ;;
        tui)
            info "Running TUI demo in VM (interactive — press q to exit)..."
            ssh "${SSH_OPTS[@]}" -t "${VM_USER}@localhost" \
                "cd ${VM_PROJECT_DIR} && demo/run_demo_tui.sh"
            ;;
        all)
            # Note: tui is excluded from 'all' because it is interactive and
            # blocks until the user presses q. Run it separately.
            info "Running all demos sequentially (excluding tui)..."
            cmd_demo phase1
            echo ""
            cmd_demo phase2
            echo ""
            cmd_demo sandbox
            echo ""
            cmd_demo e2e
            echo ""
            cmd_demo rootless
            ;;
        *)
            die "Unknown demo: $demo_name. Use: phase1, phase2, sandbox, e2e, rootless, tui, or all"
            ;;
    esac
}

cmd_start() {
    local state
    state="$(vm_state)"
    case "$state" in
        running)
            info "VM '$VM_NAME' is already running."
            ;;
        "shut off")
            info "Starting VM '$VM_NAME'..."
            "${VIRSH[@]}" start "$VM_NAME"
            wait_for_ssh
            ;;
        not-found)
            die "VM '$VM_NAME' does not exist. Run: ./scripts/libvirt-dev.sh setup"
            ;;
        *)
            die "VM '$VM_NAME' is in unexpected state: $state"
            ;;
    esac
}

cmd_stop() {
    local state
    state="$(vm_state)"
    case "$state" in
        running)
            info "Shutting down VM '$VM_NAME'..."
            "${VIRSH[@]}" shutdown "$VM_NAME"
            # Wait for graceful shutdown
            local elapsed=0
            while [ $elapsed -lt 60 ]; do
                state="$(vm_state)"
                if [ "$state" = "shut off" ]; then
                    info "VM stopped."
                    return 0
                fi
                sleep 2
                elapsed=$((elapsed + 2))
            done
            info "Graceful shutdown timed out, forcing off..."
            "${VIRSH[@]}" destroy "$VM_NAME" 2>/dev/null || true
            ;;
        "shut off")
            info "VM '$VM_NAME' is already stopped."
            ;;
        not-found)
            info "VM '$VM_NAME' does not exist."
            ;;
        *)
            info "VM '$VM_NAME' state: $state"
            ;;
    esac
}

cmd_destroy() {
    info "Destroying VM '$VM_NAME'..."

    # Stop if running
    local state
    state="$(vm_state)"
    if [ "$state" = "running" ]; then
        "${VIRSH[@]}" destroy "$VM_NAME" 2>/dev/null || true
    fi

    # Undefine the domain
    if [ "$state" != "not-found" ]; then
        "${VIRSH[@]}" undefine "$VM_NAME" --remove-all-storage 2>/dev/null || \
            "${VIRSH[@]}" undefine "$VM_NAME" --nvram 2>/dev/null || \
            "${VIRSH[@]}" undefine "$VM_NAME" 2>/dev/null || true
    fi

    # Clean up our storage directory
    if [ -d "$VM_DIR" ]; then
        info "Removing ${VM_DIR}..."
        rm -rf "$VM_DIR"
    fi

    info "VM '$VM_NAME' destroyed."
}

cmd_status() {
    local state
    state="$(vm_state)"
    echo "VM '$VM_NAME': $state"

    if [ "$state" = "running" ]; then
        echo "  SSH:      ssh ${SSH_OPTS[*]} ${VM_USER}@localhost"
        echo "  SSH key:  ${SSH_KEY}"
        "${VIRSH[@]}" dominfo "$VM_NAME" 2>/dev/null | grep -E "^(CPU|Max memory|Used memory)" | sed 's/^/  /'
    elif [ "$state" = "not-found" ]; then
        echo "  Run './scripts/libvirt-dev.sh setup' to create the VM."
    fi
}

# --- Main ---
case "${1:-}" in
    setup)    cmd_setup ;;
    sync)     cmd_sync ;;
    shell)    cmd_shell ;;
    ssh)      shift; cmd_ssh "$@" ;;
    build)    cmd_build ;;
    test)     cmd_test ;;
    security) cmd_security ;;
    demo)     shift; cmd_demo "$@" ;;
    start)    cmd_start ;;
    stop)     cmd_stop ;;
    destroy)  cmd_destroy ;;
    status)   cmd_status ;;
    *)
        echo "Usage: $(basename "$0") <command>"
        echo ""
        echo "PuzzlePod development VM (libvirt/KVM)"
        echo ""
        echo "Commands:"
        echo "  setup      Create + provision VM, sync source (idempotent)"
        echo "  sync       Rsync project source into VM"
        echo "  shell      SSH into VM at project directory"
        echo "  build      cargo build --workspace --release inside VM"
        echo "  test       cargo test --workspace inside VM"
        echo "  security   Run security tests (sudo) inside VM"
        echo "  demo <n>   Run a demo inside VM (phase1|phase2|sandbox|e2e|rootless|tui|all)"
        echo "  start      Start a stopped VM"
        echo "  stop       Shutdown VM"
        echo "  destroy    Delete VM and all storage"
        echo "  status     Show VM status"
        echo "  ssh [cmd]  Run a command via SSH (or open shell)"
        echo ""
        echo "Prerequisites (one-time, requires sudo):"
        echo "  sudo dnf install libvirt virt-install qemu-kvm rsync"
        echo "  sudo systemctl enable --now libvirtd"
        echo ""
        echo "After initial setup, all VM operations run as your user (no sudo)."
        exit 1
        ;;
esac
