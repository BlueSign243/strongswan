#!/bin/sh
set -eu
vici_test_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
vici_test_out="$vici_test_root/.local-pqmagic/vici-profile-test"
${CC:-cc} -g -O1 -include "$vici_test_root/config.h" \
  -DIPSEC_PIDDIR=\"/tmp\" -DPLUGINDIR=\""$vici_test_root/src/libstrongswan/plugins"\" \
  -I"$vici_test_root/src/libstrongswan" -I"$vici_test_root/src/libcharon" \
  "$vici_test_root/scripts/tests/test_aigis_sig_vici.c" \
  -L"$vici_test_root/src/libcharon/plugins/vici/.libs" -Wl,-rpath,"$vici_test_root/src/libcharon/plugins/vici/.libs" -lstrongswan-vici \
  -L"$vici_test_root/src/libcharon/.libs" -Wl,-rpath,"$vici_test_root/src/libcharon/.libs" -lcharon \
  -L"$vici_test_root/src/libstrongswan/.libs" -Wl,-rpath,"$vici_test_root/src/libstrongswan/.libs" -lstrongswan \
  -o "$vici_test_out"
"$vici_test_out"
