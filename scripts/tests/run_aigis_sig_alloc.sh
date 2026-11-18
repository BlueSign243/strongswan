#!/bin/sh
set -eu
alloc_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
alloc_prefix="$alloc_root/.local-pqmagic/sign"
alloc_dir="$alloc_root/.local-pqmagic/alloc-test"
mkdir -p "$alloc_dir"
${CC:-cc} -g -O1 -include "$alloc_root/config.h" \
    -I"$alloc_root/src/libstrongswan" -I"$alloc_prefix/include" \
    -DPLUGINDIR=\""$alloc_root/src/libstrongswan/plugins"\" \
    "$alloc_root/scripts/tests/test_aigis_sig_alloc.c" \
    "$alloc_root/src/libstrongswan/plugins/pqmagic/pqmagic_aigis_sig.c" \
    "$alloc_root/src/libstrongswan/plugins/pqmagic/pqmagic_composite_sig.c" \
    "$alloc_root/src/libstrongswan/plugins/pqmagic/pqmagic_sig_encoding.c" \
    -L"$alloc_root/src/libstrongswan/.libs" -lstrongswan \
    -L"$alloc_prefix/lib" -lpqmagic_std \
    -Wl,-rpath,"$alloc_root/src/libstrongswan/.libs" -Wl,-rpath,"$alloc_prefix/lib" \
    -lcrypto -Wl,--wrap=malloc -Wl,--wrap=free ${ALLOC_TEST_CFLAGS:-} -o "$alloc_dir/test_alloc"
"$alloc_dir/test_alloc"
