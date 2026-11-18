#!/bin/sh
# Build the PQMagic std Aigis-enc mode 2 SM3 subset without changing its source.
set -eu
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 /path/to/PQMagic /output/prefix [--with-sign]" >&2
    exit 2
fi
with_sign=false
if [ "$#" -eq 3 ]; then
    [ "$3" = --with-sign ] || { echo "unknown option: $3" >&2; exit 2; }
    with_sign=true
fi
pqmagic_src=$(cd "$1" && pwd)
pqmagic_out=$2
mkdir -p "$pqmagic_out/lib" "$pqmagic_out/include" "$pqmagic_out/bin" \
    "$pqmagic_out/objects/kem" "$pqmagic_out/objects/sign" "$pqmagic_out/objects/shared"
pqmagic_out=$(cd "$pqmagic_out" && pwd)
set --
for source in cbd owcpa genmatrix kem ntt poly polyvec reduce verify hashkdf sm3kdf; do
    object="$pqmagic_out/objects/kem/$source.o"
    ${CC:-cc} -O2 -fPIC -DAIGIS_ENC_MODE=2 \
        -I"$pqmagic_src" -I"$pqmagic_src/include" \
        -I"$pqmagic_src/kem/aigis-enc/std" -c \
        "$pqmagic_src/kem/aigis-enc/std/$source.c" -o "$object"
    set -- "$@" "$object"
done
if "$with_sign"; then
    for source in ntt packing poly polyvec reduce rounding sign; do
        object="$pqmagic_out/objects/sign/$source.o"
        ${CC:-cc} -O2 -fPIC -DAIGIS_SIG_MODE=2 \
            -I"$pqmagic_src" -I"$pqmagic_src/include" \
            -I"$pqmagic_src/sig/aigis-sig/std" -c \
            "$pqmagic_src/sig/aigis-sig/std/$source.c" -o "$object"
        set -- "$@" "$object"
    done
fi
for source in utils/randombytes hash/sm3/x86-64/sm3 hash/sm3/sm3_extended; do
    object="$pqmagic_out/objects/shared/$(basename "$source").o"
    ${CC:-cc} -O2 -fPIC -I"$pqmagic_src" -I"$pqmagic_src/include" \
        -c "$pqmagic_src/$source.c" -o "$object"
    set -- "$@" "$object"
done
${CC:-cc} -shared -Wl,-soname,libpqmagic_std.so \
    -o "$pqmagic_out/lib/libpqmagic_std.so" "$@"
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

if "$with_sign"; then
    ${CC:-cc} -O2 -DAIGIS_SIG_MODE=2 \
        -I"$pqmagic_src" -I"$pqmagic_src/include" -I"$pqmagic_src/sig/aigis-sig/std" \
        "$pqmagic_src/sig/aigis-sig/std/test/test_aigis.c" \
        -L"$pqmagic_out/lib" -Wl,-rpath,"$pqmagic_out/lib" -lpqmagic_std \
        -o "$pqmagic_out/bin/test_aigis_sig_2"
    "$pqmagic_out/bin/test_aigis_sig_2" > "$pqmagic_out/signature-correctness.log" 2>&1
    grep -F '[+] Test success.' "$pqmagic_out/signature-correctness.log"
fi
{
    echo "PQMagic std mode 2 SM3; with_sign=$with_sign"
    git -C "$pqmagic_src" rev-parse HEAD
    ${CC:-cc} --version
    sha256sum "$pqmagic_out/lib/libpqmagic_std.so"
    nm -D --defined-only "$pqmagic_out/lib/libpqmagic_std.so"
} > "$pqmagic_out/build-manifest.txt"
