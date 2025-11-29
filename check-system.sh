#!/usr/bin/env bash
set -euo pipefail

# check-system.sh
# Interactive script for Dandy employees to check their system for Shai Hulud vulnerabilities.

# Full path to this parent dir
THIS_SCRIPT_DIR=$(dirname $(readlink -f "$0"))

# Escape codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
NC='\033[0m' # No Color

# Constants: Upstream Hashes for Drift Detection
# These are the SHA256 hashes of the *original* scripts at the time of our last manual update.
# If the upstream script changes, we want to know so we can manually review and pull updates.
HASH_ORIGINAL_OPCTIM="9526e0e7a11d9d4fc79c52d7f1804d5ef22a9c157f02d90c32afa8012d0d0b10"
URL_ORIGINAL_OPCTIM="https://raw.githubusercontent.com/opctim/shai-hulud-2-check/main/check-shai-hulud-2.sh"

HASH_ORIGINAL_COBENIAN="1f3f94cfecbfaab20d9cc9252add1136a416e075b58844035b218ed44d2764ce"
URL_ORIGINAL_COBENIAN="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/shai-hulud-detector.sh"
URL_PACKAGES_COBENIAN="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt"

# Argument Parsing
PARANOID_MODE=0
DEBUG_MODE=0
TEST_MODE=0
for arg in "$@"; do
    if [[ "$arg" == "--paranoid" ]]; then
        PARANOID_MODE=1
    elif [[ "$arg" == "--debug" ]]; then
        DEBUG_MODE=1
    elif [[ "$arg" == "--test" ]]; then
        TEST_MODE=1
    fi
done

# Output helpersj
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}
log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}
log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}
log_success() {
    echo -e "${GREEN}[SUCCESS] $1 ${NC}"
}
log_critical() {
    echo -e "${RED}[CRITICAL] $1 ${NC}"
}

# Function to check fork consistency
check_upstream_drift() {
    local name="$1"
    local pinned_url="$2"
    local expected_hash="$3"
    local current_hash
    if current_hash=$(curl -sSkL "$pinned_url" | shasum -a 256 | awk '{print $1}'); then
        if [[ "$current_hash" != "$expected_hash" ]]; then
            log_warn "⚠️ DRIFT DETECTED: The upstream source for $name has changed!"
            log_warn "   Stored Hash: $expected_hash"
            log_warn "   Current Hash: $current_hash"
            log_warn "   Review the most recent changes and update the fork"
        else
            log_info "$name is up to date with upstream"
        fi
    else
        log_warn "Failed to check upstream drift for $name (network issue?)"
    fi
}

# Check for dependencies
check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 is required but not installed"
        return 1
    fi
}
check_dependency curl || exit 1
check_dependency bash || exit 1
# shasum is usually available on macOS (part of perl utils or standalone)
if ! command -v shasum &>/dev/null; then
    log_warn "shasum command not found, drift checks will be skipped"
    SKIP_DRIFT=1
else
    SKIP_DRIFT=0
fi

# fd is optional but highly recommended
if ! command -v fd &>/dev/null; then
    log_warn "⚠️ fd is not installed, it is recommended for faster searching"
    log_warn "   You can install it via brew: ${MAGENTA}brew install fd${NC}"
    log_warn "   The script will proceed, but the home directory checks will be skipped"
    read -p "Continue without fd? [y/N] " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    HAS_FD=0
else
    HAS_FD=1
fi

# Run drift checks immediately (non-blocking would be nicer but keep it simple)
if [[ "$SKIP_DRIFT" -eq 0 ]]; then
    check_upstream_drift "check-shai-hulud-2.sh (opctim)" "$URL_ORIGINAL_OPCTIM" "$HASH_ORIGINAL_OPCTIM"
    check_upstream_drift "shai-hulud-detector.sh (Cobenian)" "$URL_ORIGINAL_COBENIAN" "$HASH_ORIGINAL_COBENIAN"
fi

if [[ "$TEST_MODE" -eq 1 ]]; then
    log_info "Running tests only..."
    SCRIPT_1_FILE="./scripts/opctim/test.sh"
    SCRIPT_2_FILE="./scripts/Cobenian/test.sh"
    PACKAGES_FILE="./scripts/Cobenian/compromised-packages.txt"
    # Validate local files exist
    if [[ ! -f "$SCRIPT_1_FILE" ]]; then
        log_error "$SCRIPT_1_FILE not found"
        exit 1
    fi
    if [[ ! -f "$SCRIPT_2_FILE" ]]; then
        log_error "$SCRIPT_2_FILE not found"
        exit 1
    fi
    if [[ ! -f "$PACKAGES_FILE" ]]; then
        log_error "$PACKAGES_FILE not found"
        exit 1
    fi
    # Run tests
    log_warn "Test mode enabled, checks won't be run on your system"
    if ! "$SCRIPT_1_FILE"; then
        log_critical "check-shai-hulud-2.sh test failed"
    fi
    if ! "$SCRIPT_2_FILE"; then
        log_critical "shai-hulud-detector.sh test failed"
    fi
    log_success "Tests completed successfully"
    exit 0
fi

# Ask for core directory containing repos to scan
log_info "🐛 Welcome to the Shai Hulud system checker 🐛"
echo "Please enter the parent directory where your code repositories are located (e.g. ~/code)"

# Autocomplete helper: Use readline with -e to allow basic tab completion
# -i works in bash 4.0+, but macOS defaults to bash 3.2.
# We try to detect if -i is supported or fallback to manually suggesting it.
if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
    read -e -p "Directory path: " -i "$HOME/" USER_DIR
else
    # For bash 3.x (macOS default), we can't use -i.
    # We just show the default and if user hits enter, we use HOME.
    read -e -p "Directory path [Default: ~/]: " USER_DIR
    if [[ -z "$USER_DIR" ]]; then
        USER_DIR="$HOME"
    fi
fi

# Expand tilde manually if needed
if [[ "$USER_DIR" == ~* ]]; then
    USER_DIR="${USER_DIR/#\~/$HOME}"
fi

# Abort if home dir is not readable
if [ ! -d "$USER_DIR" ]; then
    log_error "Directory does not exist: $USER_DIR"
    exit 1
fi
if [ ! -r "$USER_DIR" ]; then
    log_error "Directory is not readable: $USER_DIR"
    exit 1
fi

# Verify it contains cloned projects
log_info "Verifying repositories in $USER_DIR..."
REPOS=()
while IFS= read -r dir; do
    if [ -d "$dir/.git" ]; then
        if [[ $(basename "$dir") == $(basename "$THIS_SCRIPT_DIR") ]]; then
            log_warn "Skipping self-repo: $dir"
            continue
        fi
        REPOS+=("$dir")
    fi
done < <(find "$USER_DIR" -mindepth 1 -maxdepth 1 -type d)

# If no repos found, ask to proceed recursively
if [ ${#REPOS[@]} -eq 0 ]; then
    log_warn "No git repositories found in immediate subdirectories of $USER_DIR"
    read -p "Do you want to proceed checking $USER_DIR recursively instead? [y/N] " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REPOS=("$USER_DIR")
    else
        exit 1
    fi
else
    log_info "Found ${#REPOS[@]} repositories to check"
fi

# Setup locations based on DEBUG_MODE
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
if [[ "$DEBUG_MODE" -eq 1 ]]; then
    log_info "Running in DEBUG MODE - using local scripts."
    SCRIPT_1_FILE="./scripts/opctim/check-shai-hulud-2.sh"
    SCRIPT_2_FILE="./scripts/Cobenian/shai-hulud-detector.sh"
    PACKAGES_FILE="./scripts/Cobenian/compromised-packages.txt"
    # Validate local files exist
    if [[ ! -f "$SCRIPT_1_FILE" ]]; then
        log_error "Debug: $SCRIPT_1_FILE not found"
        exit 1
    fi
    if [[ ! -f "$SCRIPT_2_FILE" ]]; then
        log_error "Debug: $SCRIPT_2_FILE not found"
        exit 1
    fi
else
    # Production Mode - Download from our repo (dnery/shai-hulud-detect)
    SCRIPT_1_FILE="$TMP_DIR/check-shai-hulud-2.sh"
    SCRIPT_2_FILE="$TMP_DIR/shai-hulud-detector.sh"
    PACKAGES_FILE="$TMP_DIR/compromised-packages.txt"
    # URLs pointing to our fork structure
    SCRIPT_1_URL="https://raw.githubusercontent.com/dnery/shai-hulud-detect/main/scripts/opctim/check-shai-hulud-2.sh"
    SCRIPT_2_URL="https://raw.githubusercontent.com/dnery/shai-hulud-detect/main/scripts/Cobenian/shai-hulud-detector.sh"
    PACKAGES_URL="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt"
fi

# Run check-shai-hulud-2.sh
ISSUES_DETECTED_1=0
echo # newline
log_info "🐛 Script 1: ${MAGENTA}check-shai-hulud-2.sh${NC}"
log_info "ℹ️ Scans lockfiles for known malicious package versions."
log_info "ℹ️ Consolidates latest security IOCs. ${GREEN}Recommended for all users.${NC}"
read -p "Run script 1? [Y/n] " -r
if [[ $REPLY =~ ^[Nn]$ ]]; then
    log_info "Skipping check-shai-hulud-2.sh"
else
    if [[ "$DEBUG_MODE" -eq 0 ]]; then
        log_info "Downloading check-shai-hulud-2.sh..."
        if curl -fsSL "$SCRIPT_1_URL" -o "$SCRIPT_1_FILE"; then
            chmod +x "$SCRIPT_1_FILE"
        else
            log_error "Failed to download check-shai-hulud-2.sh"
            # Skipping execution if download failed
            SCRIPT_1_FILE=""
        fi
    fi

    if [[ -n "$SCRIPT_1_FILE" ]]; then
        log_info "Running check-shai-hulud-2.sh..."
        if ! "$SCRIPT_1_FILE" "${REPOS[@]}"; then
            log_critical "Issues detected by check-shai-hulud-2.sh"
            ISSUES_DETECTED_1=1
        fi
    fi
fi

# Run shai-hulud-detector.sh
ISSUES_DETECTED_2=0
echo # newline
log_info "🐛 Script 2: ${MAGENTA}shai-hulud-detector.sh${NC}"
log_info "ℹ️ Deep scan for IOCs, suspicious files, and patterns."
log_info "ℹ️ Very slow paranoid scan. ${RED}Not recommended unless you want have time to spare.${NC}"
read -p "Run script 2? [y/N] " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Skipping shai-hulud-detector.sh"
else
    if [[ "$DEBUG_MODE" -eq 0 ]]; then
        log_info "Downloading shai-hulud-detector.sh and assets..."
        # Download packages file
        curl -fsSL "$PACKAGES_URL" -o "$PACKAGES_FILE" || log_error "Failed to download packages list"
        # Download script
        if curl -fsSL "$SCRIPT_2_URL" -o "$SCRIPT_2_FILE"; then
            chmod +x "$SCRIPT_2_FILE"
        else
            log_error "Failed to download shai-hulud-detector.sh"
            SCRIPT_2_FILE=""
        fi
    else
        cp "$SCRIPT_2_FILE" "$TMP_DIR/shai-hulud-detector.sh"
        cp "$PACKAGES_FILE" "$TMP_DIR/compromised-packages.txt"
        SCRIPT_2_FILE="$TMP_DIR/shai-hulud-detector.sh"
        PACKAGES_FILE="$TMP_DIR/compromised-packages.txt"
    fi
    if [[ -n "$SCRIPT_2_FILE" ]]; then
        log_info "Preparing to run shai-hulud-detector.sh..."
        if command -v shasum &>/dev/null; then
            # Verify compromised-packages.txt checksum against upstream
            UPSTREAM_CHECKSUM=$(curl -fsSL "$URL_PACKAGES_COBENIAN" | shasum -a 256 | awk '{print $1}')
            LOCAL_CHECKSUM=$(shasum -a 256 "$PACKAGES_FILE" | awk '{print $1}')
            if [[ "$UPSTREAM_CHECKSUM" != "$LOCAL_CHECKSUM" ]]; then
                log_warn "compromised-packages.txt checksum mismatch!"
                log_warn "Local:    $LOCAL_CHECKSUM"
                log_warn "Upstream: $UPSTREAM_CHECKSUM"
                log_info "Downloading updated compromised-packages.txt from upstream..."
                if curl -fsSL "$URL_PACKAGES_COBENIAN" -o "$PACKAGES_FILE"; then
                    log_info "Updated compromised-packages.txt"
                    log_warn "⚠️ A new commit is necessary to update scripts/Cobenian/compromised-packages.txt"
                else
                    log_error "Failed to download updated compromised-packages.txt"
                fi
            else
                log_success "compromised-packages.txt checksum matches upstream"
            fi
        fi
        for repo in "${REPOS[@]}"; do
            log_info "Running shai-hulud-detector.sh in ${MAGENTA}${repo}${NC}..."
            # Ensure we run from the proper script dir containing compromised-packages.txt
            if ! (cd $(dirname "$SCRIPT_2_FILE") && "./$(basename "$SCRIPT_2_FILE")" "$repo"); then
                ISSUES_DETECTED_2=1
            fi
        done
        if ((ISSUES_DETECTED_2)); then
            log_critical "Issues detected by shai-hulud-detector.sh"
        fi
    fi
fi

# Run fd checks on user home
if [ "$HAS_FD" -eq 1 ]; then
    log_info "Running fd checks on home directory ($HOME)..."
    # Directories to exclude from chec
    EXCLUDE_ARGS=(
        --exclude "$THIS_SCRIPT_DIR"
    )
    # Check for bun_environment.js
    if fd -u -g "bun_environment.js" "${EXCLUDE_ARGS[@]}" "$HOME" | grep -q .; then
        log_critical "Found 'bun_environment.js' in home directory!"
        fd -u -g "bun_environment.js" "${EXCLUDE_ARGS[@]}" "$HOME"
    else
        log_success "No 'bun_environment.js' found"
    fi
    # Check for .truffler-cache directory
    if fd -u -t d -g ".truffler-cache" "${EXCLUDE_ARGS[@]}" "$HOME" | grep -q .; then
        log_critical "Found '.truffler-cache' directory in home directory!"
        fd -u -t d -g ".truffler-cache" "${EXCLUDE_ARGS[@]}" "$HOME"
    else
        log_success "No '.truffler-cache' found"
    fi
fi

log_info "System check complete"
if ((ISSUES_DETECTED_1 || ISSUES_DETECTED_2)); then
    log_critical "High risk issues were detected"
    exit 1
else
    log_success "No issues detected"
    exit 0
fi
