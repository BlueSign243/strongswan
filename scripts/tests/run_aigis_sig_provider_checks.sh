#!/bin/sh
set -eu
provider_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
provider_source=${PQMAGIC_SOURCE:-/home/lxh/PQMagic}
provider_dir="$provider_root/.local-pqmagic/provider-test"
mkdir -p "$provider_dir/bad-sig/lib" "$provider_dir/bad-sig/include" "$provider_dir/objects"
${CC:-cc} -g -O1 -rdynamic -include "$provider_root/config.h" \
    -I"$provider_root/src/libstrongswan" \
    -DPLUGINDIR=\""$provider_root/src/libstrongswan/plugins"\" \
    "$provider_root/scripts/tests/test_pqmagic_capabilities.c" \
    -L"$provider_root/src/libstrongswan/.libs" -lstrongswan \
    -Wl,-rpath,"$provider_root/src/libstrongswan/.libs" -o "$provider_dir/capabilities"
for provider_mode in full no-ed no-sha512; do
    "$provider_dir/capabilities" "$provider_mode"
done
# A deliberately wrong same-symbol library: keep the KEM on SM3 and replace
# only the signature objects by SHAKE. It must disable signatures alone.
set -- "$provider_root"/.local-pqmagic/sign/objects/kem/*.o \
    "$provider_root"/.local-pqmagic/sign/objects/shared/*.o
for provider_unit in ntt packing poly polyvec reduce rounding sign; do
    provider_obj="$provider_dir/objects/$provider_unit.o"
    ${CC:-cc} -O2 -fPIC -DUSE_SHAKE -DAIGIS_SIG_MODE=2 \
        -I"$provider_source" -I"$provider_source/include" -I"$provider_source/sig/aigis-sig/std" \
        -c "$provider_source/sig/aigis-sig/std/$provider_unit.c" -o "$provider_obj"
    set -- "$@" "$provider_obj"
done
${CC:-cc} -O2 -fPIC -I"$provider_source" -I"$provider_source/include" \
    -c "$provider_source/hash/keccak/fips202.c" -o "$provider_dir/objects/fips202.o"
${CC:-cc} -shared -Wl,-soname,libpqmagic_std.so -o "$provider_dir/bad-sig/lib/libpqmagic_std.so" \
    "$@" "$provider_dir/objects/fips202.o"
cp "$provider_root"/.local-pqmagic/sign/include/*.h "$provider_dir/bad-sig/include/"
LD_LIBRARY_PATH="$provider_dir/bad-sig/lib" "$provider_dir/capabilities" bad-sig
PRIMITIVE_TEST_MODE=--expect-shake sh "$provider_root/scripts/tests/run_aigis_sig_primitive.sh" "$provider_dir/bad-sig"
