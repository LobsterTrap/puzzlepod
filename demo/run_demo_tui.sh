#!/bin/bash
# run_demo_tui.sh -- TUI demo with live background governance scenarios
#
# Launches the PuzzlePod TUI in the foreground while running governance
# simulation scenarios in the background. The user watches D-Bus signals
# flow into the TUI in real time: branches created, committed, rejected.
#
# Usage (inside VM, as puzzlepod user — NOT root):
#   demo/run_demo_tui.sh
#
# From host via libvirt-dev.sh:
#   ./scripts/libvirt-dev.sh demo tui
#
# Prerequisites:
#   - cargo build --workspace --release
#   - D-Bus system bus policy installed (cloud-init / dev-setup.sh setup)
#   - User in wheel group (cloud-init does this)

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Binary resolution (same pattern as dev-setup.sh)
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/var/tmp/puzzlepod-target}"
PUZZLECTL="$CARGO_TARGET_DIR/release/puzzlectl"
[ -x "$PUZZLECTL" ] || PUZZLECTL="$REPO_DIR/target/release/puzzlectl"

# Scenario and profile paths (not installed to /etc by dev-setup.sh)
SCENARIOS_DIR="$REPO_DIR/examples/scenarios"
PROFILES_DIR="$REPO_DIR/policies/profiles"
STORAGE_BASE="/tmp/puzzled-demo"

# ─── Preflight checks ───────────────────────────────────────────────────────

if [ "$(id -u)" -eq 0 ]; then
    echo "Error: Do not run as root. The TUI runs as a wheel-group user."
    echo "puzzled will be started via sudo internally."
    exit 1
fi

if [ ! -x "$PUZZLECTL" ]; then
    echo "Error: puzzlectl not found at $PUZZLECTL"
    echo "Build first: cargo build --workspace --release"
    exit 1
fi

if [ ! -d "$SCENARIOS_DIR" ]; then
    echo "Error: scenarios not found at $SCENARIOS_DIR"
    exit 1
fi

# Ensure TERM is set (ratatui needs it)
: "${TERM:=xterm-256color}"
export TERM

# ─── Cleanup trap ────────────────────────────────────────────────────────────

SCENARIO_PID=""
PUZZLED_STARTED=false

cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$SCENARIO_PID" ]; then
        sudo kill "$SCENARIO_PID" 2>/dev/null || true
        wait "$SCENARIO_PID" 2>/dev/null || true
    fi
    if [ "$PUZZLED_STARTED" = true ]; then
        sudo -E env PATH="$PATH" "$REPO_DIR/scripts/dev-setup.sh" stop 2>/dev/null || true
    fi
    echo "Done."
}
trap cleanup EXIT INT TERM

# ─── Start puzzled ───────────────────────────────────────────────────────────

if busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1"; then
    echo "puzzled already running on system bus."
else
    echo "Setting up puzzled..."
    sudo -E env PATH="$PATH" "$REPO_DIR/scripts/dev-setup.sh" setup

    echo "Starting puzzled..."
    sudo -E env PATH="$PATH" "$REPO_DIR/scripts/dev-setup.sh" startbg
    PUZZLED_STARTED=true

    # Wait for D-Bus registration (fail-closed, 15s timeout)
    for i in $(seq 1 30); do
        if busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1"; then
            break
        fi
        sleep 0.5
    done

    if ! busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1"; then
        echo "Error: puzzled failed to register on D-Bus within 15s"
        exit 1
    fi
    echo "puzzled is running."
fi

# Create demo storage directory
mkdir -p "$STORAGE_BASE"

# ─── Background scenario player ─────────────────────────────────────────────

SIM_ARGS="--scenarios-dir $SCENARIOS_DIR --profile-dir $PROFILES_DIR --storage-base $STORAGE_BASE"

sudo -E env PATH="$PATH" bash -c "
PUZZLECTL='$PUZZLECTL'
SIM_ARGS='$SIM_ARGS'

# Wait for splash screen (3s) + dashboard settle (5s)
sleep 8

# Scenario 1: Safe code edit (should commit successfully)
\$PUZZLECTL sim --run safe_code_edit --pace \$SIM_ARGS || true
sleep 4

# Scenario 2: Credential leak (policy violation — rejected)
\$PUZZLECTL sim --run credential_leak --pace \$SIM_ARGS || true
sleep 4

# Scenario 3: Persistence attack (policy violation — rejected)
\$PUZZLECTL sim --run persistence_attack --pace \$SIM_ARGS || true
sleep 4

# Scenario 4: Network exfiltration (policy violation — rejected)
\$PUZZLECTL sim --run network_exfiltration --pace \$SIM_ARGS || true
sleep 4

# Scenario 5: Multi-file refactor (should commit)
\$PUZZLECTL sim --run multi_file_refactor --pace \$SIM_ARGS || true
sleep 4

# Scenario 6: Mixed safe and sensitive (rejected — sensitive content)
\$PUZZLECTL sim --run mixed_safe_and_sensitive --pace \$SIM_ARGS || true
sleep 4

# Scenario 7: Exec attempt (rejected)
\$PUZZLECTL sim --run exec_attempt --pace \$SIM_ARGS || true

# Idle until TUI exits
sleep infinity
" >/dev/null 2>&1 &
SCENARIO_PID=$!

# ─── Launch TUI (foreground) ────────────────────────────────────────────────

echo ""
echo "Starting PuzzlePod TUI..."
echo "Governance scenarios will run in the background every ~8 seconds."
echo "Watch the dashboard for branches being created, committed, and rejected."
echo ""
echo "Press q to exit."
echo ""
sleep 1

"$PUZZLECTL" tui --bus system

# cleanup() runs automatically via EXIT trap
