#!/bin/sh
set -eu
primitive_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
primitive_prefix=${1:-"$primitive_root/.local-pqmagic/sign"}
primitive_dir="$primitive_root/.local-pqmagic/primitive-test"
mkdir -p "$primitive_dir"
# gc-sections drops the credential-object wrappers: this test isolates the helper.
${CC:-cc} -g -O1 -ffunction-sections -fdata-sections -include "$primitive_root/config.h" \
    -I"$primitive_root/src/libstrongswan" -I"$primitive_prefix/include" \
    "$primitive_root/scripts/tests/test_aigis_sig_primitive.c" \
    "$primitive_root/src/libstrongswan/plugins/pqmagic/pqmagic_aigis_sig.c" \
    -L"$primitive_root/src/libstrongswan/.libs" -lstrongswan \
    -L"$primitive_prefix/lib" -lpqmagic_std \
    -Wl,-rpath,"$primitive_root/src/libstrongswan/.libs" \
    -Wl,-rpath,"$primitive_prefix/lib" -Wl,--gc-sections -Wl,--wrap=malloc -pthread \
    ${PRIMITIVE_TEST_CFLAGS:-} -o "$primitive_dir/test_primitive"
"$primitive_dir/test_primitive" ${PRIMITIVE_TEST_MODE:-}
