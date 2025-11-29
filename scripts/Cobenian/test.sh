#!/usr/bin/env bash

# Full path to this parent dir
THIS_SCRIPT_DIR=$(dirname $(readlink -f "$0"))
cd "$THIS_SCRIPT_DIR" # already runs in a sub-shell so no need to wrap all commands

# Download test cases from upstream repo
TEST_CASES_URL="https://github.com/Cobenian/shai-hulud-detect/trunk/test-cases"
if [[ ! -d "test-cases" ]]; then
    echo "Downloading test cases from upstream..."
    if command -v svn &>/dev/null; then
        svn export "$TEST_CASES_URL" test-cases --force
    else
        echo "svn not found, attempting git sparse checkout..."
        TMP_CLONE_DIR=$(mktemp -d)
        git clone --depth 1 --filter=blob:none --sparse https://github.com/Cobenian/shai-hulud-detect.git "$TMP_CLONE_DIR" >/dev/null 2>&1
        (cd "$TMP_CLONE_DIR" && git sparse-checkout set test-cases >/dev/null 2>&1)
        mv "$TMP_CLONE_DIR/test-cases" ./test-cases
        rm -rf "$TMP_CLONE_DIR"
    fi
    trap 'rm -rf "test-cases"' EXIT
fi

function check_output() {
    local name=$1
    local needle=$2
    local haystack=("${@:3}")

    if [[ "${haystack[@]}" == *"$needle"* ]]; then
        echo "✅ $name passed"
    else
        echo "❌ $name failed"
        EXIT_CODE=1
    fi
}

EXIT_CODE=0
SUCCESS_NEEDLE="No indicators of Shai-Hulud compromise detected."

# Test on clean project (should show no issues)
check_output "Clean project" "$SUCCESS_NEEDLE" $(./shai-hulud-detector.sh test-cases/clean-project --all)

# Test on infected project (should show multiple issues)
check_output "Infected project" "High Risk Issues: 10" $(./shai-hulud-detector.sh --all test-cases/infected-project)

# Test November 2025 "Shai-Hulud: The Second Coming" attack (should show HIGH risk for all new patterns)
check_output "The Second Coming" "Total Critical Issues: 26" $(./shai-hulud-detector.sh --all test-cases/november-2025-attack)

# Test on mixed project (should show medium risk issues)
check_output "Mixed project" "Medium Risk Issues: 1" $(./shai-hulud-detector.sh --all test-cases/mixed-project)

# Test namespace warnings (should show LOW risk namespace warnings only)
check_output "Namespace warning" "$SUCCESS_NEEDLE" $(./shai-hulud-detector.sh --all test-cases/namespace-warning)

# Test semver matching (should show MEDIUM risk for packages that could match compromised versions)
check_output "Semver matching" "Medium Risk Issues: 19" $(./shai-hulud-detector.sh --all test-cases/semver-matching)

# Test legitimate crypto libraries (should show MEDIUM risk only)
check_output "Legitimate crypto" "Total Critical Issues: 1" $(./shai-hulud-detector.sh --all test-cases/legitimate-crypto)

# Test chalk/debug attack patterns (should show HIGH risk compromised packages + MEDIUM risk crypto patterns)
check_output "Chalk/debug attack" "Total Critical Issues: 13" $(./shai-hulud-detector.sh --all test-cases/chalk-debug-attack)

# Test common crypto libraries (should not trigger HIGH risk false positives)
check_output "Common crypto libraries" "Total Critical Issues: 1" $(./shai-hulud-detector.sh --all test-cases/common-crypto-libs)

# Test legitimate XMLHttpRequest modifications (should show LOW risk only)
check_output "Legitimate XMLHttpRequest" "$SUCCESS_NEEDLE" $(./shai-hulud-detector.sh --all test-cases/xmlhttp-legitimate)

# Test malicious XMLHttpRequest with crypto patterns (should show HIGH risk crypto theft + MEDIUM risk XMLHttpRequest patterns)
check_output "Malicious XMLHttpRequest" "Total Critical Issues: 5" $(./shai-hulud-detector.sh --all test-cases/xmlhttp-malicious)

# Test lockfile false positive (should show no issues despite other package having compromised version)
check_output "Lockfile false positive" "$SUCCESS_NEEDLE" $(./shai-hulud-detector.sh --all test-cases/lockfile-false-positive)

# Test actual compromised package in lockfile (should show HIGH risk)
check_output "Compromised package in lockfile" "Total Critical Issues: 2" $(./shai-hulud-detector.sh --all test-cases/lockfile-compromised)

# Test packages with safe lockfile versions (should show LOW risk with lockfile protection message)
check_output "Packages with safe lockfile versions" "$SUCCESS_NEEDLE" $(./shai-hulud-detector.sh --all test-cases/lockfile-safe-versions)

# Test mixed lockfile scenario (should show HIGH risk for compromised + LOW risk for safe)
check_output "Mixed lockfile scenario" "Total Critical Issues: 2" $(./shai-hulud-detector.sh --all test-cases/lockfile-comprehensive-test)

# Test packages without lockfile (should show MEDIUM risk for potential update risks)
check_output "Packages without lockfile" "Total Critical Issues: 2" $(./shai-hulud-detector.sh --all test-cases/no-lockfile-test)

# Test typosquatting detection with paranoid mode (should show MEDIUM risk typosquatting warnings)
check_output "Typosquatting detection" "Total Critical Issues: 3" $(./shai-hulud-detector.sh --all --paranoid test-cases/typosquatting-project)

# Test network exfiltration detection with paranoid mode (should show HIGH risk credential harvesting + MEDIUM risk network patterns)
check_output "Network exfiltration detection" "Total Critical Issues: 8" $(./shai-hulud-detector.sh --all --paranoid test-cases/network-exfiltration-project)

# Test clean project with paranoid mode (should show no issues - verifies no false positives)
check_output "Clean project with paranoid mode" "$SUCCESS_NEEDLE" $(./shai-hulud-detector.sh --all --paranoid test-cases/clean-project)

# Test semver wildcard parsing (should correctly handle 4.x, 1.2.x patterns without errors)
check_output "Semver wildcard parsing" "$SUCCESS_NEEDLE" $(./shai-hulud-detector.sh --all test-cases/semver-wildcards)

# Test discussion workflow detection (should show CRITICAL risk for malicious discussion-triggered workflows)
check_output "Discussion workflow detection" "Total Critical Issues: 4" $(./shai-hulud-detector.sh --all test-cases/discussion-workflows)

# Test GitHub Actions runner detection (should show CRITICAL risk for SHA1HULUD self-hosted runners)
check_output "GitHub Actions runner detection" "Total Critical Issues: 3" $(./shai-hulud-detector.sh --all test-cases/github-actions-runners)

# Test file hash verification (should validate benign files against malicious hashes)
check_output "File hash verification" "Total Critical Issues: 2" $(./shai-hulud-detector.sh --all test-cases/hash-verification)

# Test destructive pattern detection (should show CRITICAL risk for data destruction commands)
check_output "Destructive pattern detection" "Total Critical Issues: 13" $(./shai-hulud-detector.sh --all test-cases/destructive-patterns)

exit $((EXIT_CODE))
