/*
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PQMAGIC_KEM_H_
#define PQMAGIC_KEM_H_

#include <crypto/key_exchange.h>

/** Create an ephemeral Aigis-enc mode 2 SM3 KEM, NULL for other methods. */
key_exchange_t *pqmagic_kem_create(key_exchange_method_t method);

/** Check the linked library's hash variant (SM3 and SHAKE share API names). */
bool pqmagic_kem_check_variant(void);

#endif
