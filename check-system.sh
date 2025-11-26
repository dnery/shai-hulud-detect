#!/usr/bin/env bash
set -euo pipefail

# check-system.sh
# Interactive script for Dandy employees to check their system for Shai Hulud vulnerabilities.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for dependencies
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is required but not installed."
        return 1
    fi
}

check_dependency curl || exit 1
check_dependency bash || exit 1

# Check for fd
if ! command -v fd &> /dev/null; then
    log_warn "fd is not installed. It is recommended for faster searching."
    log_warn "You can install it via brew: brew install fd"
    log_warn "The script will proceed, but the home directory checks will be skipped."
    
    read -p "Continue without fd? [y/N] " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    HAS_FD=0
else
    HAS_FD=1
fi

# 1. Ask for directory
log_info "Welcome to the Shai Hulud System Checker."
echo "Please enter the directory where your 'orthly' repositories are located."
read -p "Directory Path: " USER_DIR

# Expand tilde manually if needed (shell usually handles it if not quoted, but read stores it literally)
if [[ "$USER_DIR" == ~* ]]; then
    USER_DIR="${USER_DIR/#\~/$HOME}"
fi

if [ ! -d "$USER_DIR" ]; then
    log_error "Directory does not exist: $USER_DIR"
    exit 1
fi

if [ ! -r "$USER_DIR" ]; then
    log_error "Directory is not readable: $USER_DIR"
    exit 1
fi

# Verify it contains cloned projects (look for .git directories in immediate subdirs)
log_info "Verifying repositories in $USER_DIR..."
REPOS=()
while IFS= read -r dir; do
    if [ -d "$dir/.git" ]; then
        if [[ "$(basename "$dir")" == "shai-hulud-detect" || "$(basename "$dir")" == "shai-hulud-detector" || "$(basename "$dir")" == "shai-hulud-detect-fork" ]]; then
             log_info "Skipping self-repo: $dir"
             continue
        fi
        REPOS+=("$dir")
    fi
done < <(find "$USER_DIR" -mindepth 1 -maxdepth 1 -type d)

if [ ${#REPOS[@]} -eq 0 ]; then
    log_warn "No git repositories found in immediate subdirectories of $USER_DIR."
    read -p "Do you want to proceed checking $USER_DIR recursively instead? [y/N] " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REPOS=("$USER_DIR")
    else
        exit 1
    fi
else
    log_info "Found ${#REPOS[@]} repositories to check."
fi

# 2. Setup temp dir
TMP_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# 3. Pull and run check-shai-hulud-2.sh
CHECK_SCRIPT_2="$TMP_DIR/check-shai-hulud-2.sh"
URL_CHECK_2="https://raw.githubusercontent.com/dnery/shai-hulud-detect/main/check-shai-hulud-2.sh"

log_info "Downloading check-shai-hulud-2.sh from dnery/shai-hulud-detect..."
if curl -fsSL "$URL_CHECK_2" -o "$CHECK_SCRIPT_2"; then
    chmod +x "$CHECK_SCRIPT_2"
    log_info "Running check-shai-hulud-2.sh against repositories..."
    "$CHECK_SCRIPT_2" "${REPOS[@]}" || log_warn "check-shai-hulud-2.sh reported potential issues."
else
    log_error "Failed to download check-shai-hulud-2.sh"
fi

# 4. Pull and run shai-hulud-detector.sh
DETECTOR_SCRIPT="$TMP_DIR/shai-hulud-detector.sh"
URL_DETECTOR="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/shai-hulud-detector.sh"

log_info "Downloading shai-hulud-detector.sh from Cobenian/shai-hulud-detect..."
if curl -fsSL "$URL_DETECTOR" -o "$DETECTOR_SCRIPT"; then
    chmod +x "$DETECTOR_SCRIPT"
    log_info "Running shai-hulud-detector.sh..."
    
    # Iterate over repos as we are unsure if it supports multiple args
    for repo in "${REPOS[@]}"; do
        echo "Checking $repo with shai-hulud-detector.sh..."
        "$DETECTOR_SCRIPT" "$repo" || log_warn "Issue detected in $repo by shai-hulud-detector.sh"
    done
else
    log_warn "Failed to download shai-hulud-detector.sh from $URL_DETECTOR. Skipping this check."
fi

# 5. fd checks
if [ "$HAS_FD" -eq 1 ]; then
    log_info "Running fd checks on home directory ($HOME)..."
    
    # bun_environment.js
    # -H: search hidden files/directories
    # -I: respect ignore files (default), maybe we want -u (unrestricted) to search everywhere?
    # The prompt says "anywhere in their home folder tree".
    # fd default ignores .gitignore patterns. We probably want to search ignored files too just in case.
    # So -I (no-ignore) or -u (unrestricted: no-ignore + hidden).
    # -H enables hidden.
    # -I disables .gitignore.
    # Let's use -H -I (or -u which implies -I).
    # Actually, let's stick to -H. If it's in a gitignored folder but not hidden, we might miss it if we respect gitignore.
    # Malicious files might be anywhere.
    # So `fd -u` (or `fd -H -I`) is safer for detection.
    
    if fd -u -g "bun_environment.js" "$HOME" | grep -q .; then
        log_error "Found 'bun_environment.js' in home directory!"
        fd -u -g "bun_environment.js" "$HOME"
    else
        log_info "No 'bun_environment.js' found."
    fi
    
    # .truffler-cache
    if fd -u -t d -g ".truffler-cache" "$HOME" | grep -q .; then
        log_error "Found '.truffler-cache' directory in home directory!"
        fd -u -t d -g ".truffler-cache" "$HOME"
    else
        log_info "No '.truffler-cache' found."
    fi
fi

log_info "System check complete."

