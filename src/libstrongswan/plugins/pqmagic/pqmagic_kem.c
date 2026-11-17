/*
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "pqmagic_kem.h"

#include <pqmagic_api.h>

typedef struct private_pqmagic_kem_t private_pqmagic_kem_t;

struct private_pqmagic_kem_t {
	key_exchange_t public;
	/* A non-empty private key identifies the initiator. */
	chunk_t private_key;
	/* Public key (initiator) or ciphertext (responder), cached for retransmits. */
	chunk_t public_value;
	chunk_t shared_secret;
#ifdef TESTABLE_KE
	drbg_t *drbg;
#endif
};

/* PQMagic consumes 64 keypair coins or 32 encapsulation coins. Use a fallible
 * strongSwan RNG instead of PQMagic's aborting randombytes(). */
static bool get_random(private_pqmagic_kem_t *this, size_t len, uint8_t *out)
{
	rng_t *rng;
	bool success;

#ifdef TESTABLE_KE
	if (this->drbg)
	{
		return this->drbg->generate(this->drbg, len, out);
	}
#endif
	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		return FALSE;
	}
	success = rng->get_bytes(rng, len, out);
	rng->destroy(rng);
	return success;
}

METHOD(key_exchange_t, get_public_key, bool,
	private_pqmagic_kem_t *this, chunk_t *value)
{
	uint8_t coins[64];
	int result;

	*value = chunk_empty;
	if (!this->public_value.len)
	{
		if (!get_random(this, sizeof(coins), coins))
		{
			memwipe(coins, sizeof(coins));
			return FALSE;
		}
		this->private_key = chunk_alloc(AIGIS_ENC_2_SECRETKEYBYTES);
		this->public_value = chunk_alloc(AIGIS_ENC_2_PUBLICKEYBYTES);
		result = pqmagic_aigis_enc_2_std_keypair_internal(
			this->public_value.ptr, this->private_key.ptr, coins);
		memwipe(coins, sizeof(coins));
		if (result)
		{
			chunk_clear(&this->private_key);
			chunk_free(&this->public_value);
			return FALSE;
		}
	}
	*value = chunk_clone(this->public_value);
	return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_pqmagic_kem_t *this, chunk_t value)
{
	uint8_t coins[32];
	int result;

	/* A second setter is rejected without changing an established result. */
	if (this->shared_secret.len || !value.ptr)
	{
		return FALSE;
	}
	if (this->private_key.len)
	{
		if (value.len != AIGIS_ENC_2_CIPHERTEXTBYTES)
		{
			return FALSE;
		}
		this->shared_secret = chunk_alloc(AIGIS_ENC_2_SSBYTES);
		result = pqmagic_aigis_enc_2_std_dec(this->shared_secret.ptr,
										  value.ptr, this->private_key.ptr);
	}
	else
	{
		/* The compressed public-key format accepts all bit patterns of this
		 * length; ML-KEM's modulus check does not apply. */
		if (value.len != AIGIS_ENC_2_PUBLICKEYBYTES)
		{
			return FALSE;
		}
		if (!get_random(this, sizeof(coins), coins))
		{
			memwipe(coins, sizeof(coins));
			return FALSE;
		}
		this->public_value = chunk_alloc(AIGIS_ENC_2_CIPHERTEXTBYTES);
		this->shared_secret = chunk_alloc(AIGIS_ENC_2_SSBYTES);
		result = pqmagic_aigis_enc_2_std_enc_internal(this->public_value.ptr,
								this->shared_secret.ptr, value.ptr, coins);
		memwipe(coins, sizeof(coins));
	}
	if (result)
	{
		chunk_clear(&this->shared_secret);
		if (!this->private_key.len)
		{
			chunk_free(&this->public_value);
		}
		return FALSE;
	}
	/* Decapsulation deliberately preserves PQMagic's implicit rejection. */
	return TRUE;
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_pqmagic_kem_t *this, chunk_t *secret)
{
	*secret = chunk_empty;
	if (!this->shared_secret.len)
	{
		return FALSE;
	}
	*secret = chunk_clone(this->shared_secret);
	return TRUE;
}

#ifdef TESTABLE_KE
METHOD(key_exchange_t, set_seed, bool,
	private_pqmagic_kem_t *this, chunk_t value, drbg_t *drbg)
{
	if (!drbg || value.len || this->public_value.len)
	{
		return FALSE;
	}
	drbg->get_ref(drbg);
	DESTROY_IF(this->drbg);
	this->drbg = drbg;
	return TRUE;
}
#endif

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_pqmagic_kem_t *this)
{
	return AIGIS_ENC_2_SM3;
}

METHOD(key_exchange_t, destroy, void,
	private_pqmagic_kem_t *this)
{
	chunk_clear(&this->private_key);
	chunk_clear(&this->shared_secret);
	chunk_free(&this->public_value);
#ifdef TESTABLE_KE
	DESTROY_IF(this->drbg);
#endif
	free(this);
}

key_exchange_t *pqmagic_kem_create(key_exchange_method_t method)
{
	private_pqmagic_kem_t *this;

	if (method != AIGIS_ENC_2_SM3)
	{
		return NULL;
	}
	INIT(this,
		.public = {
			.get_public_key = _get_public_key,
			.set_public_key = _set_public_key,
			.get_shared_secret = _get_shared_secret,
			.get_method = _get_method,
			.destroy = _destroy,
		},
	);
#ifdef TESTABLE_KE
	this->public.set_seed = _set_seed;
#endif
	return &this->public;
}

bool pqmagic_kem_check_variant(void)
{
	/* PQMagic 42f5b6e6, keypair coins 00..3f, enc coins 40..5f.
	 * Identical API symbols exist for SHAKE builds, so require the SM3 result. */
	static const uint8_t expected[] = {
		0x26,0x31,0x94,0xf3,0x59,0x20,0x9f,0x93,
		0xde,0x9c,0x72,0xc5,0x53,0xd4,0x82,0x4f,
		0x85,0xc1,0x9a,0xf5,0xaa,0xde,0xf8,0x61,
		0x85,0x79,0x53,0x20,0x05,0xa9,0x58,0x88,
	};
	uint8_t pk[AIGIS_ENC_2_PUBLICKEYBYTES], sk[AIGIS_ENC_2_SECRETKEYBYTES];
	uint8_t ct[AIGIS_ENC_2_CIPHERTEXTBYTES], ss[AIGIS_ENC_2_SSBYTES];
	uint8_t coins[96];
	bool success;
	int i;

	for (i = 0; i < sizeof(coins); i++)
	{
		coins[i] = i;
	}
	success = !pqmagic_aigis_enc_2_std_keypair_internal(pk, sk, coins) &&
		!pqmagic_aigis_enc_2_std_enc_internal(ct, ss, pk, coins + 64) &&
		memeq(ss, expected, sizeof(expected));
	memwipe(sk, sizeof(sk));
	memwipe(ss, sizeof(ss));
	memwipe(coins, sizeof(coins));
	return success;
}
