#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR"
SHAI_HULUD_CSV=./test/shai-hulud-2-packages.csv ./check-shai-hulud-2.sh ./test/vulnerable_project/