/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#include "test_suite.h"
#include <credentials/keys/private_key.h>
#include <credentials/keys/signature_params.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <pthread.h>
#include "../data/aigis_sig_vectors.h"

static key_type_t key_type(bool composite)
{
	key_type_t type = KEY_ANY;
	ck_assert_msg(enum_from_name(key_type_names, composite ?
		"COMPOSITE_AIGIS_SIG2_ED25519" : "AIGIS_SIG2_SM3", &type),
		"Aigis signature key type not registered");
	return type;
}
static signature_scheme_t sig_scheme(bool composite)
{
	signature_scheme_t scheme = SIGN_UNKNOWN;
	ck_assert(enum_from_name(signature_scheme_names, composite ?
		"COMPOSITE_AIGIS_SIG2_ED25519_SHA512" : "AIGIS_SIG2_SM3", &scheme));
	return scheme;
}
#define V(x) chunk_create((void*)(x), sizeof(x))

START_TEST(test_signature_vectors)
{
	bool composite = _i;
	key_type_t type = key_type(composite);
	signature_scheme_t scheme = sig_scheme(composite);
	private_key_t *key;
	public_key_t *pub, *loaded;
	chunk_t sig, der, fp, fp2;
	chunk_t priv = composite ? V(test_composite_pkcs8) : V(test_aigis_pkcs8);
	chunk_t spki = composite ? V(test_composite_spki) : V(test_aigis_spki);
	chunk_t expected = composite ? V(test_composite_sig) : V(test_aigis_sig);

	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
		BUILD_BLOB_ASN1_DER, priv, BUILD_END);
	ck_assert_msg(key, "Aigis private key provider missing");
	pub = key->get_public_key(key);
	ck_assert(pub);
	ck_assert_int_eq(pub->get_keysize(pub), 256);
	ck_assert(key->sign(key, scheme, NULL, V(test_message), &sig));
	ck_assert(chunk_equals(sig, expected));
	ck_assert(pub->verify(pub, scheme, NULL, V(test_message), sig));
	sig.ptr[0] ^= 1;
	ck_assert(!pub->verify(pub, scheme, NULL, V(test_message), sig));
	sig.ptr[0] ^= 1;
	sig.ptr[sig.len-1] ^= 1;
	ck_assert(!pub->verify(pub, scheme, NULL, V(test_message), sig));
	sig.ptr[sig.len-1] ^= 1;
	ck_assert(!pub->verify(pub, scheme, NULL, chunk_from_str("wrong message"), sig));
	ck_assert(!pub->verify(pub, scheme, NULL, V(test_message), chunk_skip(sig, 1)));
	ck_assert(!pub->verify(pub, scheme, (void*)1, V(test_message), sig));
	ck_assert(!pub->verify(pub, SIGN_ED25519, NULL, V(test_message), sig));
	chunk_clear(&sig);
	ck_assert(!key->sign(key, scheme, (void*)1, V(test_message), &sig));
	ck_assert(!sig.len && !sig.ptr);
	ck_assert(pub->get_encoding(pub, PUBKEY_SPKI_ASN1_DER, &der));
	ck_assert(chunk_equals(der, spki));
	loaded = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
		BUILD_BLOB_ASN1_DER, der, BUILD_END);
	ck_assert(loaded && pub->equals(pub, loaded));
	ck_assert(key->belongs_to(key, loaded));
	ck_assert(pub->get_fingerprint(pub, KEYID_PUBKEY_SHA1, &fp));
	ck_assert(loaded->get_fingerprint(loaded, KEYID_PUBKEY_SHA1, &fp2));
	ck_assert(chunk_equals(fp, fp2));
	chunk_free(&der);
	loaded->destroy(loaded);
	ck_assert(key->get_encoding(key, PRIVKEY_ASN1_DER, &der));
	ck_assert(chunk_equals(der, priv));
	chunk_clear(&der);
	pub->destroy(pub);
	key->destroy(key);
}
END_TEST

START_TEST(test_keygen_roundtrip)
{
	bool composite = _i;
	key_type_t type = key_type(composite);
	private_key_t *key, *loaded;
	public_key_t *pub;
	chunk_t der, sig;
	signature_scheme_t scheme = sig_scheme(composite);

	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
		BUILD_KEY_SIZE, 257, BUILD_END);
	ck_assert(!key);
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
		BUILD_KEY_SIZE, 256, BUILD_END);
	ck_assert(key);
	ck_assert(key->get_encoding(key, PRIVKEY_PEM, &der));
	loaded = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
		BUILD_BLOB_PEM, der, BUILD_END);
	ck_assert(loaded);
	chunk_clear(&der);
	pub = loaded->get_public_key(loaded);
	ck_assert(key->belongs_to(key, pub));
	ck_assert(key->sign(key, scheme, NULL, chunk_empty, &sig));
	ck_assert(pub->verify(pub, scheme, NULL, chunk_empty, sig));
	chunk_clear(&sig);
	pub->destroy(pub);
	loaded->destroy(loaded);
	key->destroy(key);
}
END_TEST

START_TEST(test_strict_der)
{
	chunk_t priv = _i ? V(test_composite_pkcs8) : V(test_aigis_pkcs8);
	chunk_t spki = _i ? V(test_composite_spki) : V(test_aigis_spki);
	chunk_t bad;
	private_key_t *key;
	public_key_t *pub;
	int i;
	key_type(_i);
	for (i = 0; i < priv.len; i++)
	{
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
			BUILD_BLOB_ASN1_DER, chunk_create(priv.ptr, i), BUILD_END);
		ck_assert(!key);
	}
	bad = chunk_cat("cc", priv, chunk_from_chars(0));
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
		BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!key);
	chunk_clear(&bad);
	bad = chunk_cat("cc", spki, chunk_from_chars(0));
	pub = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
		BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!pub);
	chunk_free(&bad);
}
END_TEST

START_TEST(test_der_profile_rejections)
{
	key_type_t other = key_type(!_i);
	chunk_t priv = _i ? V(test_composite_pkcs8) : V(test_aigis_pkcs8);
	chunk_t spki = _i ? V(test_composite_spki) : V(test_aigis_spki);
	chunk_t raw = _i ? V(test_composite_pk) : V(test_aigis_pk);
	chunk_t seed = chunk_skip(priv, priv.len - (_i ? 64 : 32));
	int oid = signature_scheme_to_oid(sig_scheme(_i));
	chunk_t bad, alg;
	private_key_t *key;
	public_key_t *pub;
	signature_params_t params = {}, fixed = { .scheme = sig_scheme(_i) };

	alg = asn1_algorithmIdentifier_params(oid, asn1_simple_object(ASN1_NULL, chunk_empty));
	ck_assert(!signature_params_parse(alg, 0, &params));
	bad = asn1_wrap(ASN1_SEQUENCE, "cm", alg, asn1_bitstring("c", raw));
	pub = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY, BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!pub); chunk_free(&bad);
	bad = asn1_wrap(ASN1_SEQUENCE, "ccm", ASN1_INTEGER_0, alg, asn1_simple_object(ASN1_OCTET_STRING, seed));
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!key); chunk_clear(&bad); chunk_free(&alg);
	bad = chunk_clone(spki); bad.ptr[bad.len-raw.len-1] = 1;
	pub = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY, BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!pub); chunk_free(&bad);
	/* Nonminimal length encoding of short PKCS8 outer SEQUENCE. */
	bad = chunk_cat("cc", chunk_from_chars(0x30,0x81), chunk_skip(priv,1));
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!key); chunk_clear(&bad);
	bad = asn1_wrap(ASN1_SEQUENCE, "cmm", chunk_from_chars(0x02,0x01,0x01),
		asn1_algorithmIdentifier(oid), asn1_simple_object(ASN1_OCTET_STRING, seed));
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!key); chunk_clear(&bad);
	bad = asn1_wrap(ASN1_SEQUENCE, "cmmc", ASN1_INTEGER_0, asn1_algorithmIdentifier(oid),
		asn1_simple_object(ASN1_OCTET_STRING, seed), chunk_from_chars(0xa0,0));
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, BUILD_BLOB_ASN1_DER, bad, BUILD_END);
	ck_assert(!key); chunk_clear(&bad);
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, other, BUILD_BLOB_ASN1_DER, priv, BUILD_END);
	ck_assert(!key);
	pub = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, other, BUILD_BLOB_ASN1_DER, spki, BUILD_END);
	ck_assert(!pub);
	fixed.params = (void*)1;
	ck_assert(!signature_params_build(&fixed, &bad)); ck_assert(!bad.len && !bad.ptr);
}
END_TEST

START_TEST(test_complete_fingerprints)
{
	private_key_t *key;
	public_key_t *pub, *changed;
	chunk_t raw = chunk_clone(V(test_composite_spki)), f1, f2;
	int i, type;
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, key_type(TRUE),
		BUILD_BLOB_ASN1_DER, V(test_composite_pkcs8), BUILD_END);
	ck_assert(key); pub = key->get_public_key(key);
	for (i = 0; i < 2; i++)
	{
		/* Both Aigis and Ed portions influence both complete-key fingerprints. */
		raw.ptr[raw.len-1344+(i ? 1312 : 0)] ^= 1;
		changed = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
			BUILD_BLOB_ASN1_DER, raw, BUILD_END);
		ck_assert(changed && !key->belongs_to(key, changed));
		for (type = 0; type < 2; type++)
		{
			ck_assert(pub->get_fingerprint(pub, type, &f1));
			ck_assert(changed->get_fingerprint(changed, type, &f2));
			ck_assert(!chunk_equals(f1,f2));
		}
		changed->destroy(changed);
		raw.ptr[raw.len-1344+(i ? 1312 : 0)] ^= 1;
	}
	chunk_free(&raw); pub->destroy(pub); key->destroy(key);
}
END_TEST

static rng_t *no_rng(crypto_factory_t *this, rng_quality_t quality) { return NULL; }
static bool no_entropy(rng_t *this, size_t len, uint8_t *out) { return FALSE; }
static void no_rng_destroy(rng_t *this) { }
static rng_t *failing_rng(crypto_factory_t *this, rng_quality_t quality)
{
	static rng_t rng = { .get_bytes = no_entropy, .destroy = no_rng_destroy };
	return &rng;
}
START_TEST(test_keygen_rng_failure)
{
	rng_t *(*saved)(crypto_factory_t*, rng_quality_t) = lib->crypto->create_rng;
	private_key_t *key;
	lib->crypto->create_rng = _i ? failing_rng : no_rng;
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, key_type(TRUE), BUILD_KEY_SIZE, 256, BUILD_END);
	lib->crypto->create_rng = saved;
	ck_assert(!key);
}
END_TEST

static private_key_t *threadkey;
static public_key_t *threadpub;
static void *sign_thread(void *arg)
{
	int i;
	for (i = 0; i < 8; i++)
	{
		chunk_t sig;
		if (!threadkey->sign(threadkey, sig_scheme(TRUE), NULL, V(test_message), &sig)) { return (void*)1; }
		if (!chunk_equals(sig, V(test_composite_sig)) || !threadpub->verify(threadpub, sig_scheme(TRUE), NULL, V(test_message), sig))
		{ chunk_clear(&sig); return (void*)1; }
		chunk_clear(&sig);
	}
	return NULL;
}
START_TEST(test_composite_concurrent)
{
	pthread_t threads[4];
	void *ret;
	int i;
	threadkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, key_type(TRUE), BUILD_BLOB_ASN1_DER, V(test_composite_pkcs8), BUILD_END);
	ck_assert(threadkey); threadpub = threadkey->get_public_key(threadkey);
	for (i = 0; i < 4; i++) { ck_assert_int_eq(pthread_create(&threads[i], NULL, sign_thread, NULL), 0); }
	for (i = 0; i < 4; i++) { ck_assert_int_eq(pthread_join(threads[i], &ret), 0); ck_assert(!ret); }
	threadpub->destroy(threadpub); threadkey->destroy(threadkey);
}
END_TEST

Suite *aigis_sig_suite_create()
{
	Suite *s = suite_create("aigis_sig");
	TCase *tc = tcase_create("Aigis KAT and keygen");
	tcase_add_loop_test(tc, test_signature_vectors, 0, 1);
	tcase_add_loop_test(tc, test_keygen_roundtrip, 0, 1);
	suite_add_tcase(s, tc); return s;
}
Suite *composite_aigis_sig_suite_create()
{
	Suite *s = suite_create("composite_aigis_sig");
	TCase *tc = tcase_create("composite KAT, both components, RNG and concurrency");
	tcase_add_loop_test(tc, test_signature_vectors, 1, 2);
	tcase_add_loop_test(tc, test_keygen_roundtrip, 1, 2);
	tcase_add_loop_test(tc, test_keygen_rng_failure, 0, 2);
	tcase_add_test(tc, test_composite_concurrent);
	suite_add_tcase(s, tc); return s;
}
Suite *pqmagic_credentials_suite_create()
{
	Suite *s = suite_create("pqmagic_credentials");
	TCase *tc = tcase_create("canonical DER and complete-key matching");
	tcase_add_loop_test(tc, test_strict_der, 0, 2);
	tcase_add_loop_test(tc, test_der_profile_rejections, 0, 2);
	tcase_add_test(tc, test_complete_fingerprints);
	suite_add_tcase(s, tc); return s;
}
