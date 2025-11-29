#!/usr/bin/env bash
set -euo pipefail

# Constants: upstream consolidated IOC lists
WIZ_RESEARCH_CSV_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"
DD_LABS_IOCS_CSV_URL="https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv"

# Escape codes
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[1;34m'
CYAN=$'\033[0;36m'
CR=$'\r\033[K' # Carriage return
NC=$'\033[0m'  # No color

# Output helpers
log_info() {
    echo "${GREEN}[INFO]${NC} $1"
}
log_warn() {
    echo "${YELLOW}[WARN]${NC} $1"
}
log_debug() {
    echo "${CYAN}[DEBUG]${NC} $1$"
}
log_error() {
    echo "${RED}[ERROR]${NC} $1"
}
log_success() {
    echo "${GREEN}[SUCCESS] $1${NC}"
}
log_critical() {
    echo "${RED}[CRITICAL] $1${NC}"
}
progress() {
    local current=$1
    local total=$2
    local percent=0
    [[ $total -gt 0 ]] && percent=$((current * 100 / total))
    echo -ne "${CR}${CYAN}$current / $total packages checked ($percent %)${NC}"
}

# Check for dependencies
check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 is required but not installed."
        return 1
    fi
}

# Main execution begins here
check_dependency jq || exit 1
check_dependency curl || exit 1
check_dependency awk || exit 1
check_dependency yq || exit 1

# fd is optional but recommended
HAS_FD=0
if command -v fd &>/dev/null; then
    HAS_FD=1
elif ! command -v find &>/dev/null; then
    log_error "Neither 'fd' nor 'find' is available."
    exit 1
fi

# Check for usage arguments, show help
if [ $# -eq 0 ]; then
    log_error "Usage: $0 DIRECTORY..."
    exit 2
fi

# Set dirs to scan if requested
DIRS=()
for arg in "$@"; do
    if [ -d "$arg" ]; then
        DIRS+=("$arg")
    else
        log_error "Error: not a directory: $arg"
        exit 2
    fi
done

# Temp files
TMP_DL="$(mktemp)"
TMP_WR="$(mktemp)"
TMP_CSV="$(mktemp)"
trap 'rm -f "$TMP_WR" "$TMP_CSV" "$TMP_DL"' EXIT

# Function to find files (abstracts fd vs find)
find_files() {
    local filename="$1"
    shift
    local dirs=("$@")

    if [ "$HAS_FD" -eq 1 ]; then
        # To match `find` behavior (search everything):
        # - `-u` (no ignore file, includes hidden)
        # - `-I` (no ignore file)
        # - `-H` includes hidden files/dirs
        fd -u -t f --glob "$filename" "${dirs[@]}"
    else
        find "${dirs[@]}" -type f -name "$filename"
    fi
}

# Function to download vulnerability data (up-to-date list of IOCs)
download_vulnerability_data() {
    # Decide CSV source: env var or download
    if [ -n "${SHAI_HULUD_CSV:-}" ]; then
        if [ ! -f "$SHAI_HULUD_CSV" ]; then
            log_error "Error: SHAI_HULUD_CSV is set, but file does not exist: $SHAI_HULUD_CSV"
            exit 2
        fi
        cp -f "$SHAI_HULUD_CSV" "$TMP_WR"
        log_info "Using vulnerability CSV from SHAI_HULUD_CSV: $SHAI_HULUD_CSV"
    else
        # Download Wiz Research CSV -> TMP_WR
        log_info "Downloading Wiz Research affected packages CSV: ${BLUE}$WIZ_RESEARCH_CSV_URL${NC}"
        curl -fsSL "$WIZ_RESEARCH_CSV_URL" -o "$TMP_WR"

        # Download and process Datadog Labs CSV -> TMP_DL
        log_info "Downloading DataDog Labs consolidated IOCs CSV: ${BLUE}$DD_LABS_IOCS_CSV_URL${NC}"
        curl -fsSL "$DD_LABS_IOCS_CSV_URL" -o "$TMP_DL"

    fi
    # Normalize TMP_WR -> lines: "package<TAB>version" -> append to CSV_SOURCE
    cat "$TMP_WR" | awk -F, 'NR>1 {
        gsub(/"/,"");                   # drop quotes around package name
        pkg=$1; vers=$2;                # extract package name and version string from CSV columns
        n=split(vers, parts, /\|\|/);   # split version string on "||" delimiter into array
        for (i=1; i<=n; i++) {
          gsub(/^ *= */,"", parts[i]);  # strip leading " = "
          gsub(/ *$/,"",  parts[i]);    # trim trailing spaces
          if (parts[i] != "") {         # only output non-empty version strings
            print pkg "\t" parts[i];    # output package and version as tab-separated values
          }
        }
      }' >>"$TMP_CSV"
    # Normalize TMP_DL -> lines: "package<TAB>version" -> append to CSV_SOURCE
    tr -d '\r' <"$TMP_DL" | sed '1d; s/,"[^"]*"$//' | awk '{
        idx = index($0, ",");              # find first comma position in the line
        if (idx > 0) {                     # if comma was found
          pkg = substr($0, 1, idx-1);      # extract package name (everything before comma)
          ver_str = substr($0, idx+1);     # extract version string (everything after comma)
          gsub(/"/, "", ver_str);          # remove quotes from version string
          n = split(ver_str, vers, ",");   # split version string on comma delimiter into array
          for (i=1; i<=n; i++) {
            gsub(/^ */, "", vers[i]);      # strip leading spaces from version
            gsub(/ *$/, "", vers[i]);      # strip trailing spaces from version
            if (vers[i] != "") {           # only output non-empty version strings
              print pkg "\t" vers[i];      # output package and version as tab-separated values
            }
          }
        }
      }' >>"$TMP_CSV"

    # Remove duplicates from consolidated CSV
    cat $TMP_CSV | sort -u -o "$TMP_CSV"
    CSV_SOURCE="$TMP_CSV"

    log_info "Wiz Research IOCs: ${BLUE}${TMP_WR}${NC} ($(cat $TMP_WR | wc -l | tr -d ' ') lines)"
    log_info "DataDog Labs IOCs: ${BLUE}${TMP_DL}${NC} ($(cat $TMP_DL | wc -l | tr -d ' ') lines)"
    log_info "Final consolidated IOCs: ${GREEN}${CSV_SOURCE}${NC} ($(cat $CSV_SOURCE | wc -l | tr -d ' ') lines)"
}

# Function to check if a package is vulnerable given a name, version, and file path
check_vulnerable_package() {
    local name="$1"
    local ver="$2"
    local fp="$3"

    if awk -v n="$name" -v v="$ver" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$CSV_SOURCE"; then
        log_critical "${CR}Vulnerable: $name@$ver (in $fp)"
        return 0
    fi
    return 1
}

# Function to scan npm lockfiles given a set of dirs
scan_npm_lockfiles() {
    local lockfiles=$(find_files "package-lock.json" "${@}")
    # jq program used to scan npm lockfiles (below)
    local jq_program
    read -r -d '' jq_program <<'EOF' || true
      if .packages then
        .packages
        | to_entries[]
        | select(.key | startswith("node_modules/"))
        | "\(.key | sub("^node_modules/";"")) \(.value.version)"
      else
        def walk_deps:
          to_entries[]
          | .key as $name
          | .value as $v
          | ($v.version // empty) as $ver
          | if $ver != "" then "\($name) \($ver)" else empty end,
            ( $v.dependencies // {} | walk_deps );
        .dependencies // {} | walk_deps
      end
EOF
    for lockfile in $lockfiles; do
        log_info "Scanning ~${lockfile#$HOME}"

        local installed_packages=$(jq -r "$jq_program" "$lockfile" 2>/dev/null || true)
        local total_packages=$(echo "$installed_packages" | wc -l)
        local current_package=0

        while read -r NAME VER; do
            current_package=$((current_package + 1))
            progress $current_package $total_packages
            [ -z "$NAME" ] || [ -z "$VER" ] && continue
            if check_vulnerable_package "$NAME" "$VER" "$lockfile"; then
                FOUND_ANY=1
            fi
        done <<<"$installed_packages"
        echo # newline
    done
}

# Function to scan pnpm lockfiles given a set of dirs
scan_pnpm_lockfiles() {
    local lockfiles=$(find_files "pnpm-lock.yaml" "${@}")
    for lockfile in $lockfiles; do
        log_info "Scanning ~${lockfile#$HOME}"

        local yq_program='.packages // {} | to_entries[].key'
        local installed_packages=$(yq -r "$yq_program" "$lockfile" 2>/dev/null | awk '
          {
            key = $0
            gsub(/^\/+/, "", key)        # remove leading "/"
            sub(/\([^)]*\)$/, "", key)   # drop "(...)" peer suffix if present

            # Split at last "@": before -> name, after -> version
            i = match(key, /@[^@]*$/)
            if (i > 0) {
              name = substr(key, 1, i-1)
              ver  = substr(key, i+1)
              if (name != "" && ver != "") {
                print name " " ver
              }
            }
          }
        ')
        local total_packages=$(echo "$installed_packages" | wc -l)
        local current_package=0

        while read -r NAME VER; do
            current_package=$((current_package + 1))
            progress $current_package $total_packages
            [ -z "$NAME" ] || [ -z "$VER" ] && continue
            if check_vulnerable_package "$NAME" "$VER" "$lockfile"; then
                FOUND_ANY=1
            fi
        done <<<"$installed_packages"
        echo # newline
    done
}

# Function to scan yarn lockfiles given a set of dirs
scan_yarn_lockfiles() {
    local lockfiles=$(find_files "yarn.lock" "${@}")
    for lockfile in $lockfiles; do
        log_info "Scanning ~${lockfile#$HOME}"

        local installed_packages=$(awk '
          /^[^[:space:]].*:$/ {
            # remove trailing colon + quotes
            line = $0
            gsub(/"/, "", line)
            sub(/:$/, "", line)

            # extract name before the last "@"
            i = match(line, /@[^@]*$/)
            if (i > 0) {
              name = substr(line, 1, i-1)
            } else {
              next
            }
            next
          }

          /version / {
            gsub(/"/, "", $0)
            ver = $2
            if (name != "" && ver != "")
              print name, ver
          }
        ' "$lockfile")
        local total_packages=$(echo "$installed_packages" | wc -l)
        local current_package=0

        while read -r NAME VER; do
            current_package=$((current_package + 1))
            progress $current_package $total_packages
            [ -z "$NAME" ] || [ -z "$VER" ] && continue
            if check_vulnerable_package "$NAME" "$VER" "$lockfile"; then
                FOUND_ANY=1
            fi
        done <<<"$installed_packages"
        echo # newline
    done
}

# Run scans
download_vulnerability_data
log_info "Beginning scans..."
FOUND_ANY=0

scan_npm_lockfiles "${DIRS[@]}"
scan_pnpm_lockfiles "${DIRS[@]}"
scan_yarn_lockfiles "${DIRS[@]}"

if ((FOUND_ANY)); then
    log_critical "Vulnerable packages found"
    exit 1
else
    log_success "No vulnerable packages detected"
    exit 0
fi
