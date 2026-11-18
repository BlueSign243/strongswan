/* Public test-only seeds. Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <library.h>
#include <pqmagic_api.h>
#include <plugins/pqmagic/pqmagic_aigis_sig.h>
#include <plugins/pqmagic/pqmagic_sig_params.h>
#include "../../src/libstrongswan/tests/data/aigis_sig_vectors.h"

static int fail_after = -1;
void *__real_malloc(size_t n);
void *__wrap_malloc(size_t n)
{
	if (fail_after == 0) { return NULL; }
	if (fail_after > 0) { fail_after--; }
	return __real_malloc(n);
}
#define V(a) chunk_create((void*)(a), sizeof(a))
static chunk_t pk, sk;

static void *concurrent(void *arg)
{
	int i;
	for (i = 0; i < 16; i++)
	{
		chunk_t sig;
		assert(pqmagic_aigis_sig_sign(sk, V(test_message), chunk_empty, &sig));
		assert(chunk_equals(sig, V(test_aigis_sig)));
		assert(pqmagic_aigis_sig_verify(pk, V(test_message), chunk_empty, sig));
		chunk_clear(&sig);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	uint8_t seed[32], context[256] = {}, ordinary[2445];
	chunk_t sig, copy, p, s;
	size_t len;
	int i;
	pthread_t threads[4];
	bool variant = pqmagic_aigis_sig_check_variant();
	if (argc > 1)
	{
		assert(!variant);
		puts("SHAKE rejected by signature KAT");
		return 0;
	}
	assert(variant);
	for (i = 0; i < sizeof(seed); i++) { seed[i] = i; }
	assert(pqmagic_aigis_sig_expand_seed(V(seed), &pk, &sk));
	assert(chunk_equals(pk, V(test_aigis_pk)));
	assert(pqmagic_aigis_sig_expand_seed(V(seed), &p, &s));
	assert(chunk_equals(pk, p) && chunk_equals(sk, s));
	chunk_free(&p); chunk_clear(&s);
	for (i = 0; i < 2; i++)
	{
		chunk_t ctx = chunk_create(context, i ? 255 : 0);
		assert(pqmagic_aigis_sig_sign(sk, V(test_message), ctx, &sig));
		assert(!pqmagic_aigis_sig2_std_signature(ordinary, &len, test_message,
			sizeof(test_message), ctx.ptr, ctx.len, sk.ptr));
		assert(len == sig.len && memeq(ordinary, sig.ptr, len));
		assert(!pqmagic_aigis_sig2_std_verify(sig.ptr, sig.len, test_message,
			sizeof(test_message), ctx.ptr, ctx.len, pk.ptr));
		assert(pqmagic_aigis_sig_verify(pk, V(test_message), ctx, sig));
		chunk_clear(&sig);
	}
	assert(!pqmagic_aigis_sig_sign(sk, chunk_empty, V(context), &sig));
	assert(!sig.ptr && !sig.len);
	assert(!pqmagic_aigis_sig_sign(sk, chunk_create(NULL, 1), chunk_empty, &sig));
	assert(!pqmagic_aigis_sig_sign(sk, chunk_create(seed, SIZE_MAX), chunk_empty, &sig));
	assert(!pqmagic_aigis_sig_sign(sk, chunk_empty, chunk_create(NULL, 1), &sig));
	assert(!pqmagic_aigis_sig_sign(chunk_create(NULL,3376), chunk_empty, chunk_empty, &sig));
	assert(pqmagic_aigis_sig_sign(sk, chunk_empty, chunk_empty, &sig));
	assert(pqmagic_aigis_sig_verify(pk, chunk_empty, chunk_empty, sig));
	assert(!pqmagic_aigis_sig_verify(pk, chunk_empty, chunk_empty, chunk_create(sig.ptr,2444)));
	assert(!pqmagic_aigis_sig_verify(chunk_create(NULL,1312), chunk_empty, chunk_empty, sig));
	copy = chunk_clone(pk); copy.ptr[0] ^= 1;
	assert(!pqmagic_aigis_sig_verify(copy, chunk_empty, chunk_empty, sig));
	chunk_free(&copy); chunk_clear(&sig);
	for (i = 0; i < 2; i++)
	{
		fail_after = i;
		assert(!pqmagic_aigis_sig_expand_seed(V(seed), &p, &s));
		assert(!p.ptr && !p.len && !s.ptr && !s.len);
		fail_after = -1;
		fail_after = i;
		assert(!pqmagic_aigis_sig_sign(sk, chunk_empty, chunk_empty, &sig));
		assert(!sig.ptr && !sig.len);
		fail_after = -1;
	}
	for (i = 0; i < 4; i++) { assert(!pthread_create(&threads[i], NULL, concurrent, NULL)); }
	for (i = 0; i < 4; i++) { assert(!pthread_join(threads[i], NULL)); }
	chunk_free(&pk); chunk_clear(&sk);
	puts("Aigis primitive KAT/context/length/NULL/overflow/allocation/concurrency: passed");
	return 0;
}
