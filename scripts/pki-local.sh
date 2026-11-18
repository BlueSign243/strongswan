#!/bin/sh
# Use this checkout's pki and plugins without installing into /usr or /etc.
set -eu
local_pki_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
local_pki_plugins='random x509 pubkey pkcs1 pem openssl pkcs8 pqmagic'
local_pki_preload=
for local_pki_plugin in $local_pki_plugins; do
    local_pki_file="$local_pki_root/src/libstrongswan/plugins/$local_pki_plugin/.libs/libstrongswan-$local_pki_plugin.so"
    [ -f "$local_pki_file" ] || { echo "build missing: $local_pki_file" >&2; exit 1; }
    local_pki_preload="${local_pki_preload:+$local_pki_preload:}$local_pki_file"
done
LD_LIBRARY_PATH="$local_pki_root/src/libstrongswan/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
LD_PRELOAD="$local_pki_preload" PKI_PLUGINS="$local_pki_plugins" \
    exec "$local_pki_root/src/pki/.libs/pki" "$@"
