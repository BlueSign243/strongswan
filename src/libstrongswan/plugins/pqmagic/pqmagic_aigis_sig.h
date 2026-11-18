/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PQMAGIC_AIGIS_SIG_H_
#define PQMAGIC_AIGIS_SIG_H_
#include <library.h>
#include <credentials/keys/private_key.h>
/* Inputs borrowed. On failure outputs are empty. Caller owns successful outputs;
 * wipe the expanded secret and any secret seed/encoding using chunk_clear(). */
bool pqmagic_aigis_sig_expand_seed(chunk_t seed, chunk_t *pk, chunk_t *sk);
bool pqmagic_aigis_sig_sign(chunk_t sk, chunk_t data, chunk_t context, chunk_t *signature);
bool pqmagic_aigis_sig_verify(chunk_t pk, chunk_t data, chunk_t context, chunk_t signature);
bool pqmagic_aigis_sig_check_variant(void);
private_key_t *pqmagic_aigis_sig_private_key_gen(key_type_t type, va_list args);
private_key_t *pqmagic_aigis_sig_private_key_load(key_type_t type, va_list args);
public_key_t *pqmagic_aigis_sig_public_key_load(key_type_t type, va_list args);
#endif
