#!/usr/bin/env bash

set -o pipefail

# Full path to this parent dir
THIS_SCRIPT_DIR=$(dirname $(readlink -f "$0"))
cd "$THIS_SCRIPT_DIR" # already runs in a sub-shell so no need to wrap all commands

EXIT_CODE=$(SHAI_HULUD_CSV=./test/shai-hulud-2-packages.csv ./check-shai-hulud-2.sh ./test/vulnerable_project/ | awk '
BEGIN {
    c_path=1;
    c_iocs=1;
    c_node=1;
    c_pnpm=1;
    c_yarn=1;
}
/Using vulnerability CSV from SHAI_HULUD_CSV: \.\/test\/shai-hulud-2-packages\.csv/ {
    c_path=0;
}
/Final consolidated IOCs.+\(1089 lines\)/ {
    c_iocs=0;
}
/Vulnerable: zapier-platform-core\@18\.0\.3 \(in \.\/test\/vulnerable_project\/subdirectory\/package-lock\.json\)/ {
    c_node=0;
}
/Vulnerable: zapier-platform-core\@18\.0\.3 \(in \.\/test\/vulnerable_project\/pnpm-lock\.yaml\)/ {
    c_pnpm=0;
}
/Vulnerable: zapier-platform-core\@18\.0\.3 \(in \.\/test\/vulnerable_project\/other_dir\/one_more\/yarn\.lock\)/ {
    c_yarn=0;
}
END {
    if (c_path == 1) { print "❌ Unable to source correct IOCs list (manually set)";
    } else { print "✅ Able to source correct IOCs list (manually set)"; }
    if (c_iocs == 1) { print "❌ Consolidated IOCs file has incorrect size";
    } else { print "✅ Consolidated IOCs file has correct size"; }
    if (c_node == 1) { print "❌ Node lockfile check failed";
    } else { print "✅ Node lockfile check passed"; }
    if (c_pnpm == 1) { print "❌ PNPM lockfile check failed";
    } else { print "✅ PNPM lockfile check passed"; }
    if (c_yarn == 1) { print "❌ Yarn lockfile check failed";
    } else { print "✅ Yarn lockfile check passed"; }
}' | tee /dev/tty | awk '/failed/ { test_failed=1 } END { print test_failed ? 1 : 0 }')

exit $((EXIT_CODE))
