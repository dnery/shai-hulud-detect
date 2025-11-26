#!/usr/bin/env bash
set -euo pipefail

# Author: @opctim https://github.com/opctim/shai-hulud-2-check
# More info:
# https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains
# https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

# THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SCRIPT OR THE USE OR OTHER DEALINGS IN THE SCRIPT.

WIZ_RESEARCH_CSV_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"
DD_CONSOLIDATED_IOCS_CSV_URL="https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv"

# Colors
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color

if [ $# -eq 0 ]; then
  echo "${RED}Usage: $0 DIRECTORY...${NC}" >&2
  exit 2
fi

DIRS=()
for arg in "$@"; do
  if [ -d "$arg" ]; then
    DIRS+=("$arg")
  else
    echo "${RED}Error: not a directory: $arg${NC}" >&2
    exit 2
  fi
done

for cmd in jq curl find awk yq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "${RED}Error: $cmd is required.${NC}" >&2; exit 2; }
done

# Temp files
TMP_DD="$(mktemp)"
TMP_CSV="$(mktemp)"
TMP_VULN="$(mktemp)"
trap 'rm -f "$TMP_CSV" "$TMP_VULN" "$TMP_DD"' EXIT

# Decide CSV source: env var or download
if [ -n "${SHAI_HULUD_CSV:-}" ]; then
  if [ ! -f "$SHAI_HULUD_CSV" ]; then
    echo "${RED}Error: SHAI_HULUD_CSV is set, but file does not exist: $SHAI_HULUD_CSV${NC}" >&2
    exit 2
  fi
  CSV_SOURCE="$SHAI_HULUD_CSV"
  printf "\n${CYAN}>> Using vulnerability CSV from SHAI_HULUD_CSV: %s${NC}\n" "$CSV_SOURCE" >&2
else
  CSV_SOURCE="$TMP_CSV"
  printf "\n${CYAN}>> Downloading vulnerability CSV from Github... (%s)${NC}\n" "$WIZ_RESEARCH_CSV_URL" >&2
  curl -fsSL "$WIZ_RESEARCH_CSV_URL" -o "$CSV_SOURCE"
fi

# Normalize CSV -> lines: "package<TAB>version"
# Handles cases like: "@scope/pkg","= 1.2.3 || = 1.2.4"
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
printf "\n${CYAN}>> Downloading Datadog vulnerability CSV... (%s)${NC}\n" "$DD_CONSOLIDATED_IOCS_CSV_URL" >&2
curl -fsSL "$DD_CONSOLIDATED_IOCS_CSV_URL" -o "$TMP_DD"

# Normalize Datadog CSV -> append to TMP_VULN
# Removes CRLF, strips header, strips sources column, then parses pkg/ver
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

# jq program reused for each npm package-lock.json
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

printf "\n${CYAN}>> Beginning scans...${NC}\n" >&2
FOUND_ANY=0

# Find and scan all package-lock.json files recursively
while IFS= read -r LOCKFILE; do
  echo "${BLUE}Scanning npm lockfile: $LOCKFILE${NC}" >&2

  INSTALLED_PACKAGES="$(jq -r "$JQ_PROG" "$LOCKFILE" 2>/dev/null || true)"

  while read -r NAME VER; do
    [ -z "$NAME" ] || [ -z "$VER" ] && continue

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo "${RED}VULNERABLE: $NAME@$VER (in $LOCKFILE)${NC}"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "${DIRS[@]}" -type f -name "package-lock.json")

# Find and scan all pnpm-lock.yaml files recursively
while IFS= read -r PLOCK; do
  echo "${BLUE}Scanning pnpm lockfile: $PLOCK${NC}" >&2

  # Extract "name version" pairs from pnpm-lock.yaml
  # .packages keys look like:
  #   "/left-pad@1.3.0"
  #   "/@scope/name@2.0.0"
  #   "/foo@1.0.0(bar@2.0.0)"  (peer suffix)
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

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo "${RED}VULNERABLE: $NAME@$VER (in $PLOCK)${NC}"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "${DIRS[@]}" -type f -name "pnpm-lock.yaml")

# Find and scan all yarn.lock files recursively
while IFS= read -r YLOCK; do
  echo "${BLUE}Scanning yarn lockfile: $YLOCK${NC}" >&2

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

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo "${RED}VULNERABLE: $NAME@$VER (in $YLOCK)${NC}"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "${DIRS[@]}" -type f -name "yarn.lock")

if (( FOUND_ANY )); then
  printf "\n${RED}[EMERGENCY] Vulnerable packages found.${NC}\n" >&2
  exit 1
else
  printf "\n${GREEN}[OK] No vulnerable packages detected.${NC}\n" >&2
  exit 0
fi
