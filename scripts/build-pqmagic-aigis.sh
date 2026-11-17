#!/bin/sh
# Build the PQMagic std Aigis-enc mode 2 SM3 subset without changing its source.
set -eu
pqmagic_src=${1:?usage: build-pqmagic-aigis.sh /path/to/PQMagic /output/prefix}
pqmagic_out=${2:?output prefix required}
pqmagic_src=$(cd "$pqmagic_src" && pwd)
mkdir -p "$pqmagic_out/lib" "$pqmagic_out/include" "$pqmagic_out/bin"
pqmagic_out=$(cd "$pqmagic_out" && pwd)
set --
for source in cbd owcpa genmatrix kem ntt poly polyvec reduce verify hashkdf sm3kdf; do
    set -- "$@" "$pqmagic_src/kem/aigis-enc/std/$source.c"
done
set -- "$@" "$pqmagic_src/utils/randombytes.c" \
    "$pqmagic_src/hash/sm3/x86-64/sm3.c" \
    "$pqmagic_src/hash/sm3/sm3_extended.c"
${CC:-cc} -O2 -fPIC -shared -DAIGIS_ENC_MODE=2 \
    -I"$pqmagic_src" -I"$pqmagic_src/include" \
    -I"$pqmagic_src/kem/aigis-enc/std" \
    -Wl,-soname,libpqmagic_std.so -o "$pqmagic_out/lib/libpqmagic_std.so" "$@"
cp "$pqmagic_src/include/pqmagic_api.h" \
   "$pqmagic_src/include/pqmagic_reference_api.h" "$pqmagic_out/include/"
${CC:-cc} -O2 -DAIGIS_ENC_MODE=2 \
    -I"$pqmagic_src" -I"$pqmagic_src/kem/aigis-enc/std" \
    "$pqmagic_src/kem/aigis-enc/std/test/test_aigis_enc.c" \
    -L"$pqmagic_out/lib" -Wl,-rpath,"$pqmagic_out/lib" -lpqmagic_std \
    -o "$pqmagic_out/bin/test_aigis_enc_2"
"$pqmagic_out/bin/test_aigis_enc_2" > "$pqmagic_out/correctness.log"
# Upstream's test main returns zero even on failure: check its actual result.
grep -F '[+] Success.' "$pqmagic_out/correctness.log"
git -C "$pqmagic_src" rev-parse HEAD > "$pqmagic_out/PQMAGIC_COMMIT"
cat "$pqmagic_out/correctness.log"
