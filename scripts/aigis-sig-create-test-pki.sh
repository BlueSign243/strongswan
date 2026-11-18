#!/bin/sh
# Disposable laboratory PKI. All private keys are created together; use CSR-only
# exchange for real two-host key custody (see docs/aigis-sig-build-and-test.md).
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: $0 /new/output/directory m1|m2" >&2
    exit 2
fi
pki_output=$1
case "$2" in
    m1) pki_ca_type=ed25519; pki_ca_name=aigisClassicalCa; pki_suffix=M1Composite ;;
    m2) pki_ca_type=aigissig2ed25519; pki_ca_name=aigisCompositeCa; pki_suffix=Composite ;;
    *) echo 'stage must be m1 or m2' >&2; exit 2 ;;
esac
pki_script_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pki_call()
{
    if [ -n "${PQMAGIC_TEST_PKI_BIN:-}" ]; then
        "$PQMAGIC_TEST_PKI_BIN" "$@"
    else
        sh "$pki_script_root/scripts/pki-local.sh" "$@"
    fi
}
umask 077
# Refuse overwrite or reuse of any existing key directory.
mkdir -- "$pki_output"
pki_output=$(CDPATH= cd -- "$pki_output" && pwd)
pki_call --gen --type "$pki_ca_type" --outform pem > "$pki_output/${pki_ca_name}Key.pem"
pki_call --self --type "$pki_ca_type" --in "$pki_output/${pki_ca_name}Key.pem" \
    --dn "CN=Aigis $2 Test CA" --ca --lifetime 3650 --outform pem > "$pki_output/${pki_ca_name}Cert.pem"
for pki_host in moon sun; do
    pki_call --gen --type aigissig2ed25519 --outform pem > "$pki_output/${pki_host}${pki_suffix}Key.pem"
    pki_call --req --type aigissig2ed25519 --in "$pki_output/${pki_host}${pki_suffix}Key.pem" \
        --dn "CN=$pki_host.strongswan.org" --san "$pki_host.strongswan.org" > "$pki_output/$pki_host.req.der"
    pki_call --issue --type pkcs10 --in "$pki_output/$pki_host.req.der" \
        --cakey "$pki_output/${pki_ca_name}Key.pem" --cacert "$pki_output/${pki_ca_name}Cert.pem" \
        --lifetime 365 --flag serverAuth --flag clientAuth --outform pem > "$pki_output/${pki_host}${pki_suffix}Cert.pem"
    pki_call --verify --in "$pki_output/${pki_host}${pki_suffix}Cert.pem" \
        --cacert "$pki_output/${pki_ca_name}Cert.pem" > "$pki_output/$pki_host.verify.txt"
    pki_call --pub --type x509 --in "$pki_output/${pki_host}${pki_suffix}Cert.pem" \
        --outform der > "$pki_output/${pki_host}${pki_suffix}Public.der"
    sha256sum "$pki_output/${pki_host}${pki_suffix}Public.der" >> "$pki_output/SPKI-SHA256.txt"
done
printf 'Created disposable %s PKI in %s\n' "$2" "$pki_output"
