# Shai Hulud Detector

![Shai Hulud Detector Banner](banner.png)

This tool helps developers scan their local development environments for **Shai Hulud** supply chain vulnerabilities.

It runs modified versions of 2 different scripts across your locally cloned repositories and your home directory to ensure your system is clean. Projects sourced:

- [check-shai-hulud-2.sh from opctim/shai-hulud-2-check](https://github.com/opctim/shai-hulud-2-check)
- [shai-hulud-detector.sh from Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect)

## Quick Start (MacBook)

Run the following command in your terminal:

```bash
bash <(curl -s https://raw.githubusercontent.com/dnery/shai-hulud-detect/main/check-system.sh)
```

Follow the interactive prompts to complete the scan.

## What does this do?

1.  **Repository Scan**: It asks for the location of your code (e.g., `~/code`), detects all git repositories within, and scans their lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) for known malicious packages associated with the Shai Hulud attack.
2.  **Paranoid Checks**: Optionally it runs Cobenian's `shai-hulud-detector.sh` (modified) to run slower paranoid checks for malicious patterns and expressions. Takes a long time to run, so I don't recommend it unless you already suspect something.
3.  **System Scan**: It checks your home directory for known malicious indicators:
    - Files named `bun_environment.js`
    - Directories named `.truffler-cache`

## Requirements

- **curl** & **bash** (pre-installed on macOS)
- **jq** & **yq** (Needed for the base scan script)
  - Install via Homebrew: `brwe install jq yq`
- **fd** (Optional but recommended for faster scanning)
  - Install via Homebrew: `brew install fd`

## Manual Usage

If you just want to run the base scan against one more directories _without_ the interactive wizard:

```bash
# Clone the repo
git clone https://github.com/dnery/shai-hulud-detect.git
cd shai-hulud-detect

# Optionally specify a CSV containing affected package versions
# to use as core IOCs (updated lists will be downloaded by default)
export SHAI_HULUD_CSV="./my-iocs.csv"

# Run the base scan directly
./scripts/opctim/check-shai-hulud-2.sh ~/code/my-vulnerable-project ~/code/my-other-vulnerable-project
```

## References

- [Wiz Research: Shai Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Aikido: Shai Hulud Strikes Again](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [DataDog Security Labs: The Shai-Hulud 2.0 npm worm](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/#how-to-know-if-you-are-affected-iocs)
