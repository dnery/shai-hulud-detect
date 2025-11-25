# shai-hulud-2-check

A simple bash script that will scan your project dir for package-lock.json files that contain vulnerabilites listed in the wiz-sec vulnerability CSV.

## Usage

    ./shai-hulud-2-check.sh /Users/jdoe/my/project

#### Example output

    Downloading vulnerability CSV from Github... (https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv)

    Scanning: /Users/jdoe/my/project/package-lock.json
    VULNERABLE: @accordproject/concerto-analysis@3.24.1 (in /Users/jdoe/my/project/package-lock.json)
    Scanning: /Users/jdoe/my/project/package-lock.json
    
    [EMERGENCY] Vulnerable packages found.

## Disclaimer

This script is provided "AS IS" without any warranties. The author assumes no liability for any damages or losses arising from the use of this script.

## More Info

https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains
https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack