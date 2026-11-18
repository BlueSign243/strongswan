/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PQMAGIC_SIG_ENCODING_H_
#define PQMAGIC_SIG_ENCODING_H_
#include <library.h>
#include <credentials/keys/public_key.h>
int pqmagic_sig_oid(key_type_t type);
chunk_t pqmagic_sig_encode(key_type_t type, bool secret, chunk_t raw);
/* Exact canonical header comparison with fixed size/profile; returns a borrowed
 * raw slice only after every byte of DER framing has been checked. */
bool pqmagic_sig_decode(key_type_t type, bool secret, chunk_t der, chunk_t *raw);
#endif
