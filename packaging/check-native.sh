#!/bin/sh
# Run against the installed package in a clean distribution baseline. ldd -r
# resolves lazy symbols too, but can exit successfully with unresolved symbols,
# so inspect its diagnostics as well as its status.
set -eu
export LC_ALL=C
binary=$1
if ! ldd -r "$binary" > /tmp/devbox-loader-check.log 2>&1; then
    cat /tmp/devbox-loader-check.log
    exit 1
fi
cat /tmp/devbox-loader-check.log
if grep -E 'not found|undefined symbol' /tmp/devbox-loader-check.log; then
    exit 1
fi

# Reach Go's configuration validation without needing a running hypervisor or
# opening a listener. Loader failures must not pass as expected startup errors.
status=0
timeout 15s env CONFIG_FILE=/dev/null LDAP_URL=' ' "$binary" > /tmp/devbox-startup-check.log 2>&1 || status=$?
cat /tmp/devbox-startup-check.log
test "$status" -eq 1
grep -F 'LDAP_URL must be set; LDAP is the required authentication backend' /tmp/devbox-startup-check.log
