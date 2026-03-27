#!/bin/bash
# Build source RPMs for COPR submission.
#
# Usage:
#   cd packaging && ./build-srpm.sh [--release]
#
# Without --release, builds a git snapshot SRPM with the current HEAD commit
# hash in the release field (e.g., 0.1.0-0.20260309.gitabc1234.fc42).
#
# With --release, builds a tagged release SRPM (e.g., 0.1.0-1.fc42).
#
# Output: SRPMs in packaging/srpms/
#
# To submit to COPR:
#   copr-cli build puzzlepod srpms/puzzled-0.1.0-0.20260309.gitabc1234.fc42.src.rpm
#   copr-cli build puzzlepod srpms/puzzlectl-0.1.0-0.20260309.gitabc1234.fc42.src.rpm
#   ... (repeat for each SRPM)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRPM_DIR="$SCRIPT_DIR/srpms"

RELEASE_MODE=0
if [[ "${1:-}" == "--release" ]]; then
    RELEASE_MODE=1
fi

cd "$REPO_ROOT"

# Verify we're in a git repo
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "ERROR: Not in a git repository" >&2
    exit 1
fi

# Note uncommitted changes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    echo "NOTE: Uncommitted changes detected. Tarball will include working tree contents." >&2
    echo ""
fi

# Git metadata
COMMIT=$(git rev-parse HEAD)
SHORTCOMMIT=$(git rev-parse --short HEAD)
COMMITDATE=$(date +%Y%m%d -d @$(git show -s --format=%ct HEAD) 2>/dev/null \
    || date -r $(git show -s --format=%ct HEAD) +%Y%m%d)

echo "=== Building SRPMs ==="
echo "Commit:    $COMMIT"
echo "Short:     $SHORTCOMMIT"
echo "Date:      $COMMITDATE"
echo "Mode:      $([ $RELEASE_MODE -eq 1 ] && echo 'release' || echo 'git snapshot')"
echo ""

# Create source tarball from working tree (includes uncommitted changes)
SOURCE_NAME="puzzlepod-${COMMIT}"
TARBALL="${SOURCE_NAME}.tar.gz"

echo "--- Creating source tarball ---"
tar -czf "/tmp/${TARBALL}" \
    --transform "s,^\./,${SOURCE_NAME}/," \
    --transform "s,^\.,${SOURCE_NAME}," \
    --exclude='./.git' \
    --exclude='./target' \
    --exclude='./packaging/srpms' \
    --exclude='./packaging/rpms' \
    -C "$REPO_ROOT" .
echo "Created /tmp/${TARBALL}"

# Set up rpmbuild tree
RPMBUILD_DIR=$(mktemp -d)
mkdir -p "$RPMBUILD_DIR"/{SOURCES,SPECS,SRPMS}
cp "/tmp/${TARBALL}" "$RPMBUILD_DIR/SOURCES/"

# Build SRPMs for each spec
mkdir -p "$SRPM_DIR"

SPECS=(
    puzzled.spec
    puzzlectl.spec
    puzzlepod-selinux.spec
    puzzled-profiles.spec
    puzzled-policies.spec
    puzzle-podman.spec
    puzzlepod.spec
)

for spec in "${SPECS[@]}"; do
    echo ""
    echo "--- Building SRPM: $spec ---"

    if [[ $RELEASE_MODE -eq 0 ]]; then
        # Inject %global macros directly into the spec so they survive
        # SRPM extraction (--define flags are not stored in the SRPM).
        sed -e "1i %global commit $COMMIT" \
            -e "1i %global shortcommit $SHORTCOMMIT" \
            -e "1i %global commitdate $COMMITDATE" \
            "$SCRIPT_DIR/$spec" > "$RPMBUILD_DIR/SPECS/$spec"
    else
        cp "$SCRIPT_DIR/$spec" "$RPMBUILD_DIR/SPECS/"
    fi

    rpmbuild -bs \
        --define "_topdir $RPMBUILD_DIR" \
        "$RPMBUILD_DIR/SPECS/$spec"
done

# Collect SRPMs
cp "$RPMBUILD_DIR/SRPMS/"*.src.rpm "$SRPM_DIR/"

echo ""
echo "=== SRPMs built ==="
ls -1 "$SRPM_DIR/"*.src.rpm
echo ""
echo "To submit to internal COPR:"
echo "  for srpm in $SRPM_DIR/*.src.rpm; do"
echo "    copr-cli build puzzlepod \"\$srpm\""
echo "  done"

# Preserve source tarball for CI artifact upload
TARBALL_DIR="$SCRIPT_DIR/source-tarball"
mkdir -p "$TARBALL_DIR"
cp "/tmp/${TARBALL}" "$TARBALL_DIR/" || {
    echo "ERROR: Failed to preserve source tarball" >&2
    exit 1
}
echo ""
echo "Source tarball: $TARBALL_DIR/${TARBALL}"

# Cleanup
rm -rf "$RPMBUILD_DIR" "/tmp/${TARBALL}"
