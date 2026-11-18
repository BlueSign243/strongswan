#!/bin/sh
set -eu
matrix_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
matrix_source="$matrix_root/.local-pqmagic/matrix/source"
mkdir -p "$matrix_source"
rsync -a --exclude='.git' --exclude='.codegraph' --exclude='.local-pqmagic' \
  --exclude='.superpowers' --exclude='.aws' --exclude='.agents' --exclude='.codex' \
  --exclude='.libs' --exclude='.deps' --exclude='*.o' --exclude='*.lo' \
  --exclude='*.la' --exclude='core' "$matrix_root/" "$matrix_source/"
cd "$matrix_source"
common='--disable-defaults --enable-openssl --enable-random --enable-drbg --enable-pki --enable-x509 --enable-pubkey --enable-pkcs1 --enable-pkcs8 --enable-pem'
./configure $common --disable-pqmagic --enable-pqmagic-sign > ../invalid-options.log 2>&1 && exit 1
rg 'pqmagic-sign requires' ../invalid-options.log
./configure $common --enable-pqmagic --enable-pqmagic-sign \
  PQMAGIC_CFLAGS="-I$matrix_root/.local-pqmagic/install/include" \
  PQMAGIC_LIBS="-L$matrix_root/.local-pqmagic/install/lib -Wl,-rpath,$matrix_root/.local-pqmagic/install/lib -lpqmagic_std" > ../missing-api.log 2>&1 && exit 1
rg 'Aigis-sig mode 2 std APIs not found' ../missing-api.log
./configure $common --disable-pqmagic > ../disabled-config.log 2>&1
make -C src/libstrongswan -j4 > ../disabled-build.log 2>&1
TESTS_SUITES=auth_cfg make -C src/libstrongswan/tests check > ../disabled-tests.log 2>&1
./configure $common --enable-pqmagic --disable-pqmagic-sign \
  PQMAGIC_CFLAGS="-I$matrix_root/.local-pqmagic/install/include" \
  PQMAGIC_LIBS="-L$matrix_root/.local-pqmagic/install/lib -Wl,-rpath,$matrix_root/.local-pqmagic/install/lib -lpqmagic_std" > ../kem-config.log 2>&1
make -C src/libstrongswan -j4 > ../kem-build.log 2>&1
TESTS_SUITES=pqmagic_kem,auth_cfg make -C src/libstrongswan/tests check > ../kem-tests.log 2>&1
# Disabled signatures must not introduce signature references into the plugin.
if nm -D src/libstrongswan/plugins/pqmagic/.libs/libstrongswan-pqmagic.so | rg 'aigis_sig'; then exit 1; fi
printf '%s\n' 'Build matrix: disabled, legacy KEM-only, missing API and invalid options passed'
