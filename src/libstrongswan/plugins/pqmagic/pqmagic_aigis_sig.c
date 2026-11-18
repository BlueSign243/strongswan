/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#include "pqmagic_aigis_sig.h"
#include "pqmagic_sig_params.h"
#include "pqmagic_composite_sig.h"
#include <pqmagic_api.h>

_Static_assert(AIGIS_SIG2_PUBLICKEYBYTES == PQMAGIC_SIG_PUBLIC_BYTES, "Aigis public size");
_Static_assert(AIGIS_SIG2_SECRETKEYBYTES == PQMAGIC_SIG_SECRET_BYTES, "Aigis secret size");
_Static_assert(AIGIS_SIG2_SIGBYTES == PQMAGIC_SIG_BYTES, "Aigis signature size");

bool pqmagic_aigis_sig_expand_seed(chunk_t seed, chunk_t *pk, chunk_t *sk)
{
	*pk = *sk = chunk_empty;
	if (seed.len != PQMAGIC_SIG_SEED_BYTES || !seed.ptr)
	{
		return FALSE;
	}
	*pk = chunk_alloc(PQMAGIC_SIG_PUBLIC_BYTES);
	*sk = chunk_alloc(PQMAGIC_SIG_SECRET_BYTES);
	if (!pk->ptr || !sk->ptr ||
		pqmagic_aigis_sig2_std_keypair_internal(pk->ptr, sk->ptr, seed.ptr))
	{
		chunk_free(pk);
		chunk_clear(sk);
		*sk = chunk_empty;
		return FALSE;
	}
	return TRUE;
}

/* Include internal signing's 2*SEEDBYTES + CRHBYTES overhead, not just
 * wrapper framing. Verification requires only CRHBYTES but uses same bound. */
static bool frame_message(chunk_t data, chunk_t context, chunk_t *frame)
{
	*frame = chunk_empty;
	if (context.len > 255 || (context.len && !context.ptr) ||
		(data.len && !data.ptr) || data.len > SIZE_MAX - 112 - 2 - context.len)
	{
		return FALSE;
	}
	*frame = chunk_alloc(data.len + context.len + 2);
	if (!frame->ptr)
	{
		*frame = chunk_empty;
		return FALSE;
	}
	frame->ptr[0] = 0;
	frame->ptr[1] = context.len;
	if (context.len)
	{
		memcpy(frame->ptr + 2, context.ptr, context.len);
	}
	if (data.len)
	{
		memcpy(frame->ptr + 2 + context.len, data.ptr, data.len);
	}
	return TRUE;
}

bool pqmagic_aigis_sig_sign(chunk_t sk, chunk_t data, chunk_t context,
							chunk_t *signature)
{
	chunk_t frame;
	bool success;

	*signature = chunk_empty;
	if (sk.len != PQMAGIC_SIG_SECRET_BYTES || !sk.ptr ||
		!frame_message(data, context, &frame))
	{
		return FALSE;
	}
	*signature = chunk_alloc(PQMAGIC_SIG_BYTES);
	if (!signature->ptr)
	{
		chunk_clear(&frame);
		*signature = chunk_empty;
		return FALSE;
	}
	success = !pqmagic_aigis_sig2_std_signature_internal(signature->ptr,
		&signature->len, frame.ptr, frame.len, sk.ptr) &&
		signature->len == PQMAGIC_SIG_BYTES;
	chunk_clear(&frame);
	if (!success)
	{
		/* The output capacity remains fixed even if a provider changed len. */
		signature->len = PQMAGIC_SIG_BYTES;
		chunk_clear(signature);
	}
	return success;
}

bool pqmagic_aigis_sig_verify(chunk_t pk, chunk_t data, chunk_t context,
							  chunk_t signature)
{
	chunk_t frame;
	bool success;

	if (pk.len != PQMAGIC_SIG_PUBLIC_BYTES || !pk.ptr ||
		signature.len != PQMAGIC_SIG_BYTES || !signature.ptr ||
		!frame_message(data, context, &frame))
	{
		return FALSE;
	}
	success = !pqmagic_aigis_sig2_std_verify_internal(signature.ptr,
		signature.len, frame.ptr, frame.len, pk.ptr);
	chunk_clear(&frame);
	return success;
}

bool pqmagic_aigis_sig_check_variant(void)
{
	/* Direct upstream API fixture: seed 00..1f, message including interior NUL,
	 * context empty. Full fixture lives in tests/data/aigis_sig_vectors.h. */
	static const uint8_t expected_pk[] = {
		0x69,0x18,0x33,0x6b,0x26,0xad,0xeb,0xdf,0xfa,0x83,0xca,0x27,0xb1,0xd2,0xe0,0xb1,
		0xef,0x68,0x44,0x65,0x4c,0x9e,0xca,0x85,0xf7,0x20,0x42,0x64,0xb1,0xdc,0x8e,0x2c,
	};
	static const uint8_t expected_sig[] = {
		0x3f,0x0c,0x97,0x15,0x8a,0x10,0x8c,0xc1,0xd5,0xb9,0xc3,0x49,0x37,0x0a,0x7e,0x57,
		0x10,0xd6,0xe5,0x75,0x32,0x04,0x74,0x76,0x8b,0xbf,0xb8,0x00,0x24,0x65,0x77,0xfc,
	};
	uint8_t seed[32];
	chunk_t pk = chunk_empty, sk = chunk_empty, sig = chunk_empty;
	chunk_t message = chunk_from_str("Aigis composite test\0message");
	bool success;
	int i;

	/* chunk_from_str uses strlen; include the interior NUL and suffix. */
	message.len = sizeof("Aigis composite test\0message") - 1;
	for (i = 0; i < sizeof(seed); i++) { seed[i] = i; }
	success = pqmagic_aigis_sig_expand_seed(chunk_from_thing(seed), &pk, &sk) &&
		memeq(pk.ptr, expected_pk, sizeof(expected_pk)) &&
		pqmagic_aigis_sig_sign(sk, message, chunk_empty, &sig) &&
		memeq(sig.ptr, expected_sig, sizeof(expected_sig)) &&
		pqmagic_aigis_sig_verify(pk, message, chunk_empty, sig);
	chunk_free(&pk);
	chunk_clear(&sk);
	chunk_clear(&sig);
	memwipe(seed, sizeof(seed));
	return success;
}

private_key_t *pqmagic_aigis_sig_private_key_gen(key_type_t type, va_list args)
{
	return type == KEY_AIGIS_SIG2_SM3 ? pqmagic_sig_private_key_gen(type, args) : NULL;
}
private_key_t *pqmagic_aigis_sig_private_key_load(key_type_t type, va_list args)
{
	return type == KEY_AIGIS_SIG2_SM3 ? pqmagic_sig_private_key_load(type, args) : NULL;
}
public_key_t *pqmagic_aigis_sig_public_key_load(key_type_t type, va_list args)
{
	return type == KEY_AIGIS_SIG2_SM3 ? pqmagic_sig_public_key_load(type, args) : NULL;
}
