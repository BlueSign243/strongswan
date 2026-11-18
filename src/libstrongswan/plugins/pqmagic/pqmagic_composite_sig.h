/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PQMAGIC_COMPOSITE_SIG_H_
#define PQMAGIC_COMPOSITE_SIG_H_
#include <library.h>
#include <credentials/keys/private_key.h>
/* Shared ownership/encoding implementation; both fixed-profile constructors
 * dispatch here, keeping single and composite lifecycle behavior identical. */
private_key_t *pqmagic_sig_private_key_gen(key_type_t type, va_list args);
private_key_t *pqmagic_sig_private_key_load(key_type_t type, va_list args);
public_key_t *pqmagic_sig_public_key_load(key_type_t type, va_list args);
private_key_t *pqmagic_composite_sig_private_key_gen(key_type_t type, va_list args);
private_key_t *pqmagic_composite_sig_private_key_load(key_type_t type, va_list args);
public_key_t *pqmagic_composite_sig_public_key_load(key_type_t type, va_list args);
#endif
