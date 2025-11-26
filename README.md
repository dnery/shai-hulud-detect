# Shai Hulud Detector

This tool helps Dandy employees scan their local development environments for **Shai Hulud** supply chain vulnerabilities.

It runs a comprehensive check across your cloned repositories and your home directory to ensure your system is clean.

## Quick Start (MacBook)

Run the following command in your terminal:

```bash
bash <(curl -s https://raw.githubusercontent.com/dnery/shai-hulud-detect/main/check-system.sh)
```

Follow the interactive prompts to complete the scan.

## What does this do?

1.  **Repository Scan**: It asks for the location of your code (e.g., `~/orthly`), detects all git repositories within, and scans their lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) for known malicious packages associated with the Shai Hulud attack.
2.  **System Scan**: It checks your home directory for known malicious indicators:
    - Files named `bun_environment.js`
    - Directories named `.truffler-cache`

## Requirements

- **macOS** (standard employee MacBook)
- **curl** & **bash** (pre-installed on macOS)
- **fd** (Optional but recommended for faster scanning)
  - Install via Homebrew: `brew install fd`

## Manual Usage

If you prefer to run the scanner manually against a specific directory without the interactive wizard:

```bash
# Clone the repo
git clone https://github.com/dnery/shai-hulud-detect.git
cd shai-hulud-detect

# Run the check script directly
./check-shai-hulud-2.sh /path/to/your/project
```

## References

- [Wiz Research: Shai Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Aikido: Shai Hulud Strikes Again](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
