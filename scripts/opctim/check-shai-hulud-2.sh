#!/usr/bin/env bash
set -euo pipefail

WIZ_RESEARCH_CSV_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"
DD_LABS_IOCS_CSV_URL="https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv"

# Escape codes
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BRIGHT_BLUE=$'\033[1;34m'
BRIGHT_MAGENTA=$'\033[1;35m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
CR=$'\r\033[K'
NC=$'\033[0m' # No Color

# Logging helpers
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
carriage_return() {
    echo -ne "$CR"
}

# Function: show_progress
# Purpose: Display real-time progress indicator for file scanning operations
# Args: $1 = current files processed, $2 = total files to process
# Modifies: None (outputs to stderr with ANSI escape codes)
# Returns: Prints "X / Y checked (Z %)" with line clearing
show_progress() {
    local current=$1
    local total=$2
    local percent=0
    [[ $total -gt 0 ]] && percent=$((current * 100 / total))
    echo -ne "$current / $total checked ($percent %)${CR}"
}

# Check for dependencies
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is required but not installed."
        return 1
    fi
}

# Main execution begins here
check_dependency jq || exit 1
check_dependency curl || exit 1
check_dependency awk || exit 1
check_dependency yq || exit 1

# fd is optional, find is required if fd is missing
HAS_FD=0
if command -v fd &> /dev/null; then
  HAS_FD=1
elif ! command -v find &> /dev/null; then
  log_error "Neither 'fd' nor 'find' is available."
  exit 1
fi

# Check for usage arguments
if [ $# -eq 0 ]; then
  log_error "Usage: $0 DIRECTORY..."
  exit 2
fi

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
TMP_DD="$(mktemp)"
TMP_CSV="$(mktemp)"
TMP_VULN="$(mktemp)"
trap 'rm -f "$TMP_CSV" "$TMP_VULN" "$TMP_DD"' EXIT

# Function to find files (abstracts fd vs find)
find_files() {
    local filename="$1"
    shift
    local dirs=("$@")
    
    if [ "$HAS_FD" -eq 1 ]; then
        # Usually node_modules is ignored by fd by default.
        # find command used to be `find "$DIR" -type f -name "package-lock.json"`
        # shai-hulud usually targets package-lock.json, often in project root or subdirs.
        # We probably want to search ignored directories too (like if someone committed it inside a gitignored folder?)
        # But standard `find` doesn't care about gitignore, and `fd` respects gitignore by default.
        # To match `find` behavior (search everything):
        # - `-u` (no ignore file, includes hidden) 
        # - `-I` (no ignore file)
        # - `-H` includes hidden files/dirs
        # Let's use `-u` to match `find`'s broad scope.
        fd -u -t f --glob "$filename" "${dirs[@]}"
    else
        find "${dirs[@]}" -type f -name "$filename"
    fi
}

download_vulnerability_data() {
    # Decide CSV source: env var or download
    if [ -n "${SHAI_HULUD_CSV:-}" ]; then
      if [ ! -f "$SHAI_HULUD_CSV" ]; then
        log_error "Error: SHAI_HULUD_CSV is set, but file does not exist: $SHAI_HULUD_CSV"
        exit 2
      fi
      CSV_SOURCE="$SHAI_HULUD_CSV"
      log_info "Using vulnerability CSV from SHAI_HULUD_CSV: $CSV_SOURCE"
    else
      CSV_SOURCE="$TMP_CSV"
      log_info "Downloading Wiz Research affected packages CSV: $WIZ_RESEARCH_CSV_URL"
      curl -fsSL "$WIZ_RESEARCH_CSV_URL" -o "$CSV_SOURCE"
    fi

    # Normalize CSV -> lines: "package<TAB>version"
    awk -F, 'NR>1 {
      gsub(/"/,"");          # drop quotes
      pkg=$1; vers=$2;
      n=split(vers, parts, /\|\|/);
      for (i=1; i<=n; i++) {
        gsub(/^ *= */,"", parts[i]); # strip leading " = "
        gsub(/ *$/,"",  parts[i]);   # trim trailing spaces
        if (parts[i] != "") {
          print pkg "\t" parts[i];
        }
      }
    }' "$CSV_SOURCE" > "$TMP_VULN"

    # Download and process Datadog CSV
    log_info "Downloading DataDog Labs consolidated IOCs CSV: $DD_LABS_IOCS_CSV_URL"
    curl -fsSL "$DD_LABS_IOCS_CSV_URL" -o "$TMP_DD"

    # Normalize Datadog CSV -> append to TMP_VULN
    tr -d '\r' < "$TMP_DD" | sed '1d; s/,"[^"]*"$//' | awk '{
      idx = index($0, ",");
      if (idx > 0) {
        pkg = substr($0, 1, idx-1);
        ver_str = substr($0, idx+1);
        gsub(/"/, "", ver_str);
        n = split(ver_str, vers, ",");
        for (i=1; i<=n; i++) {
          gsub(/^ */, "", vers[i]);
          gsub(/ *$/, "", vers[i]);
          if (vers[i] != "") {
            print pkg "\t" vers[i];
          }
        }
      }
    }' >> "$TMP_VULN"
}

check_vulnerable_package() {
    local name="$1"
    local ver="$2"
    local file="$3"
    
    if awk -v n="$name" -v v="$ver" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      log_critical "Vulnerable: $name@$ver (in $file)"
      return 0
    fi
    return 1
}

scan_npm_lockfiles() {
    local dirs=("${@}")
    
    # jq program reused for each npm package-lock.json
    local JQ_PROG
    read -r -d '' JQ_PROG <<'EOF' || true
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

    local total_npm_lockfiles=$(find_files "package-lock.json" "${dirs[@]}" | wc -l)
    local current_npm_lockfile=0
    while IFS= read -r LOCKFILE; do
      current_npm_lockfile=$((current_npm_lockfile + 1))
      log_info "Scanning npm lockfile: $LOCKFILE"
      show_progress $current_npm_lockfile $total_npm_lockfiles

      local INSTALLED_PACKAGES
      INSTALLED_PACKAGES="$(jq -r "$JQ_PROG" "$LOCKFILE" 2>/dev/null || true)"

      while read -r NAME VER; do
        [ -z "$NAME" ] || [ -z "$VER" ] && continue
        if check_vulnerable_package "$NAME" "$VER" "$LOCKFILE"; then
             FOUND_ANY=1
        fi
      done <<< "$INSTALLED_PACKAGES"

    done < <(find_files "package-lock.json" "${dirs[@]}")
}

scan_pnpm_lockfiles() {
    local dirs=("${@}")
    local total_pnpm_lockfiles=$(find_files "pnpm-lock.yaml" "${dirs[@]}" | wc -l)
    local current_pnpm_lockfile=0
    while IFS= read -r PLOCK; do
      current_pnpm_lockfile=$((current_pnpm_lockfile + 1))
      log_info "Scanning pnpm lockfile: $PLOCK"
      show_progress $current_pnpm_lockfile $total_pnpm_lockfiles

      local INSTALLED_PACKAGES
      INSTALLED_PACKAGES="$(
        yq -r '.packages // {} | to_entries[].key' "$PLOCK" 2>/dev/null \
        | awk '
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
        '
      )"

      while read -r NAME VER; do
        [ -z "$NAME" ] || [ -z "$VER" ] && continue
        if check_vulnerable_package "$NAME" "$VER" "$PLOCK"; then
             FOUND_ANY=1
        fi
      done <<< "$INSTALLED_PACKAGES"

    done < <(find_files "pnpm-lock.yaml" "${dirs[@]}")
}

scan_yarn_lockfiles() {
    local dirs=("${@}")
    local total_yarn_lockfiles=$(find_files "yarn.lock" "${dirs[@]}" | wc -l)
    local current_yarn_lockfile=0
    while IFS= read -r YLOCK; do
      current_yarn_lockfile=$((current_yarn_lockfile + 1))
      log_info "Scanning yarn lockfile: $YLOCK"
      show_progress $current_yarn_lockfile $total_yarn_lockfiles

      local INSTALLED_PACKAGES
      INSTALLED_PACKAGES="$(
        awk '
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
        ' "$YLOCK"
      )"

      while read -r NAME VER; do
        [ -z "$NAME" ] || [ -z "$VER" ] && continue
        if check_vulnerable_package "$NAME" "$VER" "$YLOCK"; then
             FOUND_ANY=1
        fi
      done <<< "$INSTALLED_PACKAGES"

    done < <(find_files "yarn.lock" "${dirs[@]}")
}

# Run scans
download_vulnerability_data
log_info "Beginning scans"
FOUND_ANY=0

scan_npm_lockfiles "${DIRS[@]}"
scan_pnpm_lockfiles "${DIRS[@]}"
scan_yarn_lockfiles "${DIRS[@]}"

if (( FOUND_ANY )); then
  log_critical "Vulnerable packages found."
  exit 1
else
  log_success "No vulnerable packages detected."
  exit 0
fi
