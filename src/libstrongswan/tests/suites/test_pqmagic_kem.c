/*
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "test_suite.h"
#include <crypto/key_exchange.h>
#include <crypto/rngs/rng_tester.h>

#define AIGIS_METHOD AIGIS_ENC_2_SM3

START_TEST(test_aigis_roundtrip)
{
	key_exchange_t *a, *b;
	chunk_t pk, ct, copy, sa, sb;

	a = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	b = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	ck_assert_msg(a && b, "Aigis-enc mode 2 provider missing");
	ck_assert_int_eq(a->get_method(a), AIGIS_METHOD);
	ck_assert(key_exchange_is_kem(AIGIS_METHOD));
	ck_assert(!a->get_shared_secret(a, &sa));
	ck_assert(!b->get_shared_secret(b, &sb));
	ck_assert(a->get_public_key(a, &pk));
	ck_assert_int_eq(pk.len, 896);
	ck_assert(a->get_public_key(a, &copy));
	ck_assert(chunk_equals(pk, copy));
	ck_assert(pk.ptr != copy.ptr);
	chunk_free(&copy);
	ck_assert(!a->get_shared_secret(a, &sa));
	ck_assert(b->set_public_key(b, pk));
	ck_assert(b->get_public_key(b, &ct));
	ck_assert_int_eq(ct.len, 992);
	ck_assert(b->get_public_key(b, &copy));
	ck_assert(chunk_equals(ct, copy));
	chunk_free(&copy);
	/* A completed exchange may not silently re-encapsulate/decapsulate. */
	ck_assert(!b->set_public_key(b, pk));
	ck_assert(a->set_public_key(a, ct));
	ck_assert(!a->set_public_key(a, ct));
	ck_assert(a->get_shared_secret(a, &sa));
	ck_assert(b->get_shared_secret(b, &sb));
	ck_assert_int_eq(sa.len, 32);
	ck_assert(chunk_equals(sa, sb));
	ck_assert(a->get_shared_secret(a, &copy));
	ck_assert(chunk_equals(copy, sa));
	ck_assert(copy.ptr != sa.ptr);
	chunk_clear(&copy);
	chunk_clear(&sa);
	chunk_clear(&sb);
	chunk_free(&pk);
	chunk_free(&ct);
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_aigis_lengths)
{
	key_exchange_t *a, *b;
	chunk_t pk, ct, secret;
	uint8_t invalid[993] = {};

	a = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	b = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	ck_assert(a && b);
	ck_assert(!b->set_public_key(b, chunk_empty));
	ck_assert(!b->set_public_key(b, chunk_create(invalid, 895)));
	ck_assert(!b->set_public_key(b, chunk_create(invalid, 897)));
	ck_assert(!b->get_shared_secret(b, &secret));
	ck_assert(a->get_public_key(a, &pk));
	ck_assert(!a->set_public_key(a, pk));
	ck_assert(!a->set_public_key(a, chunk_create(invalid, 991)));
	ck_assert(!a->set_public_key(a, chunk_create(invalid, 993)));
	ck_assert(!a->get_shared_secret(a, &secret));
	/* Rejected input must not poison an otherwise usable exchange. */
	ck_assert(b->set_public_key(b, pk));
	ck_assert(b->get_public_key(b, &ct));
	ck_assert(a->set_public_key(a, ct));
	chunk_free(&pk);
	chunk_free(&ct);
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_aigis_implicit_rejection)
{
	key_exchange_t *a, *b;
	chunk_t pk, ct, sa, sb;

	a = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	b = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	ck_assert(a && b);
	ck_assert(a->get_public_key(a, &pk));
	ck_assert(b->set_public_key(b, pk));
	ck_assert(b->get_public_key(b, &ct));
	ct.ptr[0] ^= 1;
	/* Equal-length invalid ciphertext is implicitly rejected, not an oracle. */
	ck_assert(a->set_public_key(a, ct));
	ck_assert(a->get_shared_secret(a, &sa));
	ck_assert(b->get_shared_secret(b, &sb));
	ck_assert(!chunk_equals(sa, sb));
	chunk_clear(&sa);
	chunk_clear(&sb);
	chunk_free(&pk);
	chunk_free(&ct);
	a->destroy(a);
	b->destroy(b);
}
END_TEST

#ifdef TESTABLE_KE
/* A deliberately failing entropy source tests the RNG error path, without
 * overriding production randombytes() or changing any global RNG state. */
static bool failing_generate(drbg_t *this, uint32_t len, uint8_t *out)
{
	return FALSE;
}

static drbg_t *failing_get_ref(drbg_t *this)
{
	return this;
}

static void failing_destroy(drbg_t *this)
{
}

START_TEST(test_aigis_rng_failure)
{
	drbg_t fail = {
		.generate = failing_generate,
		.get_ref = failing_get_ref,
		.destroy = failing_destroy,
	};
	key_exchange_t *a, *b;
	chunk_t pk, ct, secret;
	uint8_t entropy[48] = {};
	drbg_t *drbg;
	rng_t *rng;

	a = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	b = lib->crypto->create_ke(lib->crypto, AIGIS_METHOD);
	ck_assert(a && b);
	ck_assert(!a->set_seed(a, chunk_empty, NULL));
	ck_assert(a->set_seed(a, chunk_empty, &fail));
	ck_assert(!a->get_public_key(a, &pk));
	ck_assert(!a->get_shared_secret(a, &secret));
	/* Replacing a failed RNG before any key is generated allows a retry. */
	rng = rng_tester_create(chunk_create(entropy, sizeof(entropy)));
	drbg = lib->crypto->create_drbg(lib->crypto, DRBG_CTR_AES256, 256,
								  rng, chunk_empty);
	ck_assert(drbg);
	ck_assert(a->set_seed(a, chunk_empty, drbg));
	drbg->destroy(drbg);
	ck_assert(a->get_public_key(a, &pk));
	ck_assert(!a->set_seed(a, chunk_empty, &fail));
	ck_assert(b->set_seed(b, chunk_empty, &fail));
	ck_assert(!b->set_public_key(b, pk));
	ck_assert(!b->get_shared_secret(b, &secret));
	/* No ciphertext should have been cached after encapsulation failed. */
	ck_assert(!b->get_public_key(b, &ct));
	chunk_free(&pk);
	a->destroy(a);
	b->destroy(b);
}
END_TEST
#endif

Suite *pqmagic_kem_suite_create()
{
	Suite *s = suite_create("pqmagic_kem");
	TCase *tc = tcase_create("Aigis-enc mode 2 SM3");
	tcase_add_loop_test(tc, test_aigis_roundtrip, 0, 8);
	tcase_add_test(tc, test_aigis_lengths);
	tcase_add_test(tc, test_aigis_implicit_rejection);
#ifdef TESTABLE_KE
	tcase_add_test(tc, test_aigis_rng_failure);
#endif
	suite_add_tcase(s, tc);
	return s;
}
