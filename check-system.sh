#!/usr/bin/env bash
set -euo pipefail

# check-system.sh
# Interactive script for Dandy employees to check their system for Shai Hulud vulnerabilities.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BRIGHT_BLUE='\033[1;34m'
BRIGHT_MAGENTA='\033[1;35m'
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
echo "Please enter the parent directory where your code repositories are located (e.g. ~/code)."
read -p "Directory path: " USER_DIR

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

echo # newline
echo -e "🐛 ${BRIGHT_MAGENTA}Script 1: https://github.com/dnery/shai-hulud-detect/blob/main/scripts/check-shai-hulud-2.sh${NC}"
echo -e "  ℹ️ ${BRIGHT_MAGENTA}Scans your cloned repository lockfiles for known malicious packages associated with the novel Shai Hulud attack.${NC}"
echo -e "  ℹ️ ${BRIGHT_MAGENTA}Consolidates latest package lists published by security researchers, ${GREEN}recommended for all users.${NC}"
echo -e "  ℹ️ ${BRIGHT_MAGENTA}Forked from @opctim's https://github.com/opctim/shai-hulud-2-check script.${NC}"
read -p "Run script 1? [Y/n] " -r
if [[ $REPLY =~ ^[Nn]$ ]]; then
    log_info "Skipping check-shai-hulud-2.sh"
else
    log_info "Downloading check-shai-hulud-2.sh from dnery/shai-hulud-detect..."
    if curl -fsSL "$URL_CHECK_2" -o "$CHECK_SCRIPT_2"; then
        chmod +x "$CHECK_SCRIPT_2"
        log_info "Running check-shai-hulud-2.sh against repositories..."
        "$CHECK_SCRIPT_2" "${REPOS[@]}" || log_warn "check-shai-hulud-2.sh reported potential issues."
    else
        log_error "Failed to download check-shai-hulud-2.sh"
    fi
fi

# 4. Pull and run shai-hulud-detector.sh
DETECTOR_SCRIPT="$TMP_DIR/shai-hulud-detector.sh"
URL_DETECTOR="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/shai-hulud-detector.sh"
URL_PACKAGES="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt"
PACKAGES_FILE="$TMP_DIR/compromised-packages.txt"

echo # newline
echo -e "🐛 ${BRIGHT_MAGENTA}Script 2: https://github.com/Cobenian/shai-hulud-detect/blob/main/shai-hulud-detector.sh${NC}"
echo -e "  ℹ️ ${BRIGHT_MAGENTA}Aside from lockfile checks, does fancy IOC sniffing for suspicious files, patterns and a lot more.${NC}"
echo -e "  ℹ️ ${BRIGHT_MAGENTA}Very slow paranoid scan, ${RED}NOT recommended unless you already suspect something.${NC}"
echo -e "  ℹ️ ${BRIGHT_MAGENTA}Sources @Cobenian's https://github.com/Cobenian/shai-hulud-detect script.${NC}"
read -p "Run script 2? (Very slow) [y/N] " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Skipping shai-hulud-detector.sh"
else
    log_info "Downloading shai-hulud-detector.sh and compromised-packages.txt from Cobenian/shai-hulud-detect..."

    # Download the packages list first so the script finds it
    if curl -fsSL "$URL_PACKAGES" -o "$PACKAGES_FILE"; then
        log_info "Downloaded compromised-packages.txt successfully."
    else
        log_warn "Failed to download compromised-packages.txt. The script might rely on embedded list."
    fi

    if curl -fsSL "$URL_DETECTOR" -o "$DETECTOR_SCRIPT"; then
        chmod +x "$DETECTOR_SCRIPT"
        log_info "Running shai-hulud-detector.sh..."
        
        # Iterate over repos as we are unsure if it supports multiple args
        for repo in "${REPOS[@]}"; do
            echo "Checking $repo with shai-hulud-detector.sh..."
            # Run from TMP_DIR so it finds the packages file
            (cd "$TMP_DIR" && "./$(basename "$DETECTOR_SCRIPT")" "$repo") || log_warn "Issue detected in $repo by shai-hulud-detector.sh"
        done
    else
        log_warn "Failed to download shai-hulud-detector.sh from $URL_DETECTOR. Skipping this check."
    fi
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
    
    # Exclude patterns for self-repos
    EXCLUDE_ARGS=(
      --exclude "shai-hulud-detect"
      --exclude "shai-hulud-detector"
      --exclude "shai-hulud-detect-fork"
    )

    if fd -u -g "bun_environment.js" "${EXCLUDE_ARGS[@]}" "$HOME" | grep -q .; then
        log_error "Found 'bun_environment.js' in home directory!"
        fd -u -g "bun_environment.js" "${EXCLUDE_ARGS[@]}" "$HOME"
    else
        log_info "No 'bun_environment.js' found."
    fi
    
    # .truffler-cache
    if fd -u -t d -g ".truffler-cache" "${EXCLUDE_ARGS[@]}" "$HOME" | grep -q .; then
        log_error "Found '.truffler-cache' directory in home directory!"
        fd -u -t d -g ".truffler-cache" "${EXCLUDE_ARGS[@]}" "$HOME"
    else
        log_info "No '.truffler-cache' found."
    fi
fi

log_info "System check complete."

