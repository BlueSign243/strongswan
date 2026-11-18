/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#include "pqmagic_composite_sig.h"
#include "pqmagic_aigis_sig.h"
#include "pqmagic_sig_encoding.h"
#include "pqmagic_sig_params.h"
#include <credentials/keys/signature_params.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>

/* Objects are immutable after construction. Fingerprints are computed once,
 * before publishing, so concurrent verification has no lazy-cache writes. */
typedef struct {
	public_key_t public;
	key_type_t type;
	chunk_t raw;
	uint8_t fp_raw[20], fp_spki[20];
	public_key_t *ed;
	refcount_t ref;
} public_sig_t;

typedef struct {
	private_key_t public;
	key_type_t type;
	chunk_t seed, sk;
	public_sig_t *pub;
	private_key_t *ed;
	refcount_t ref;
} private_sig_t;

static signature_scheme_t scheme_for(key_type_t type)
{
	return type == KEY_AIGIS_SIG2_SM3 ? SIGN_AIGIS_SIG2_SM3 :
		SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512;
}

static bool transcript(chunk_t message, chunk_t *out)
{
	static const uint8_t prefix[] = PQMAGIC_COMPOSITE_PREFIX;
	static const uint8_t suite[] = PQMAGIC_COMPOSITE_SUITE;
	uint8_t header[] = { 0, sizeof(suite)-1 }, context = 0, hash[64];
	hasher_t *hasher;
	bool success;

	*out = chunk_empty;
	if (message.len && !message.ptr) { return FALSE; }
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA512);
	if (!hasher) { return FALSE; }
	success = hasher->get_hash(hasher, message, hash);
	hasher->destroy(hasher);
	if (success)
	{
		*out = chunk_alloc(sizeof(prefix)-1 + sizeof(header) + sizeof(suite)-1 + 1 + sizeof(hash));
		success = !!out->ptr;
		if (success)
		{
			uint8_t *p = out->ptr;
			memcpy(p, prefix, sizeof(prefix)-1); p += sizeof(prefix)-1;
			memcpy(p, header, sizeof(header)); p += sizeof(header);
			memcpy(p, suite, sizeof(suite)-1); p += sizeof(suite)-1;
			*p++ = context; memcpy(p, hash, sizeof(hash));
		}
		else { *out = chunk_empty; }
	}
	memwipe(hash, sizeof(hash));
	return success;
}

METHOD(public_key_t, pub_type, key_type_t, public_sig_t *this) { return this->type; }
METHOD(public_key_t, pub_size, int, public_sig_t *this) { return 256; }
METHOD(public_key_t, pub_ref, public_key_t*, public_sig_t *this)
{
	ref_get(&this->ref); return &this->public;
}
METHOD(public_key_t, pub_destroy, void, public_sig_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF(this->ed);
		chunk_free(&this->raw);
		free(this);
	}
}
METHOD(public_key_t, pub_encoding, bool, public_sig_t *this,
	cred_encoding_type_t type, chunk_t *out)
{
	chunk_t der;
	bool success;

	*out = chunk_empty;
	if (type != PUBKEY_SPKI_ASN1_DER && type != PUBKEY_PEM) { return FALSE; }
	der = pqmagic_sig_encode(this->type, FALSE, this->raw);
	if (!der.ptr) { return FALSE; }
	if (type == PUBKEY_SPKI_ASN1_DER) { *out = der; return !!der.ptr; }
	success = lib->encoding->encode(lib->encoding, type, NULL, out,
		CRED_PART_SPKI_ASN1_DER, der, CRED_PART_END);
	chunk_free(&der);
	return success;
}
METHOD(public_key_t, pub_fp, bool, public_sig_t *this,
	cred_encoding_type_t type, chunk_t *fp)
{
	switch (type)
	{
		case KEYID_PUBKEY_SHA1: *fp = chunk_from_thing(this->fp_raw); return TRUE;
		case KEYID_PUBKEY_INFO_SHA1: *fp = chunk_from_thing(this->fp_spki); return TRUE;
		default: return FALSE;
	}
}
METHOD(public_key_t, pub_encrypt, bool, public_sig_t *this,
	encryption_scheme_t scheme, void *params, chunk_t plain, chunk_t *out)
{
	*out = chunk_empty; return FALSE;
}
METHOD(public_key_t, pub_verify, bool, public_sig_t *this,
	signature_scheme_t scheme, void *params, chunk_t data, chunk_t sig)
{
	chunk_t t;
	bool a, b;

	if (params || scheme != scheme_for(this->type)) { return FALSE; }
	if (this->type == KEY_AIGIS_SIG2_SM3)
	{
		return pqmagic_aigis_sig_verify(this->raw, data, chunk_empty, sig);
	}
	if (sig.len != PQMAGIC_COMPOSITE_SIG_BYTES || !sig.ptr || !transcript(data, &t))
	{
		return FALSE;
	}
	a = pqmagic_aigis_sig_verify(chunk_create(this->raw.ptr, PQMAGIC_SIG_PUBLIC_BYTES),
		t, chunk_from_str(PQMAGIC_COMPOSITE_CONTEXT), chunk_create(sig.ptr, PQMAGIC_SIG_BYTES));
	b = this->ed->verify(this->ed, SIGN_ED25519, NULL, t, chunk_skip(sig, PQMAGIC_SIG_BYTES));
	chunk_clear(&t);
	return a && b;
}

static public_sig_t *public_create(key_type_t type, chunk_t raw)
{
	public_sig_t *this;
	hasher_t *hasher;
	chunk_t der;

	this = malloc(sizeof(*this));
	if (!this) { return NULL; }
	*this = (public_sig_t){
		.public = {
			.get_type = _pub_type, .verify = _pub_verify, .encrypt = _pub_encrypt,
			.equals = public_key_equals, .get_keysize = _pub_size,
			.get_fingerprint = _pub_fp, .has_fingerprint = public_key_has_fingerprint,
			.get_encoding = _pub_encoding, .get_ref = _pub_ref, .destroy = _pub_destroy,
		},
		.type = type, .ref = 1,
	};
	this->raw = chunk_alloc(raw.len);
	if (!this->raw.ptr) { _pub_destroy(this); return NULL; }
	memcpy(this->raw.ptr, raw.ptr, raw.len);
	if (type == KEY_COMPOSITE_AIGIS_SIG2_ED25519)
	{
		this->ed = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ED25519,
			BUILD_EDDSA_PUB, chunk_skip(raw, PQMAGIC_SIG_PUBLIC_BYTES), BUILD_END);
		if (!this->ed) { _pub_destroy(this); return NULL; }
	}
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher) { _pub_destroy(this); return NULL; }
	der = pqmagic_sig_encode(type, FALSE, raw);
	if (!der.ptr || !hasher->get_hash(hasher, raw, this->fp_raw) ||
		!hasher->get_hash(hasher, der, this->fp_spki))
	{
		hasher->destroy(hasher); chunk_free(&der); _pub_destroy(this); return NULL;
	}
	hasher->destroy(hasher);
	chunk_free(&der);
	return this;
}

METHOD(private_key_t, priv_type, key_type_t, private_sig_t *this) { return this->type; }
METHOD(private_key_t, priv_size, int, private_sig_t *this) { return 256; }
METHOD(private_key_t, priv_public, public_key_t*, private_sig_t *this)
{
	return _pub_ref(this->pub);
}
METHOD(private_key_t, priv_ref, private_key_t*, private_sig_t *this)
{
	ref_get(&this->ref); return &this->public;
}
METHOD(private_key_t, priv_destroy, void, private_sig_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF(this->ed);
		if (this->pub) { _pub_destroy(this->pub); }
		chunk_clear(&this->seed);
		chunk_clear(&this->sk);
		free(this);
	}
}
METHOD(private_key_t, priv_fp, bool, private_sig_t *this,
	cred_encoding_type_t type, chunk_t *fp) { return _pub_fp(this->pub, type, fp); }
METHOD(private_key_t, priv_encoding, bool, private_sig_t *this,
	cred_encoding_type_t type, chunk_t *out)
{
	chunk_t der;
	bool success;

	*out = chunk_empty;
	if (type != PRIVKEY_ASN1_DER && type != PRIVKEY_PEM) { return FALSE; }
	der = pqmagic_sig_encode(this->type, TRUE, this->seed);
	if (!der.ptr) { return FALSE; }
	if (type == PRIVKEY_ASN1_DER) { *out = der; return !!der.ptr; }
	success = lib->encoding->encode(lib->encoding, type, NULL, out,
		CRED_PART_PKCS8_ASN1_DER, der, CRED_PART_END);
	chunk_clear(&der);
	return success;
}
METHOD(private_key_t, priv_decrypt, bool, private_sig_t *this,
	encryption_scheme_t scheme, void *params, chunk_t crypto, chunk_t *plain)
{
	*plain = chunk_empty; return FALSE;
}
METHOD(private_key_t, priv_schemes, enumerator_t*, private_sig_t *this)
{
	return signature_schemes_for_key(this->type, 256);
}
METHOD(private_key_t, priv_sign, bool, private_sig_t *this,
	signature_scheme_t scheme, void *params, chunk_t data, chunk_t *sig)
{
	chunk_t t, a = chunk_empty, b = chunk_empty;
	bool success;

	*sig = chunk_empty;
	if (params || scheme != scheme_for(this->type)) { return FALSE; }
	if (this->type == KEY_AIGIS_SIG2_SM3)
	{
		return pqmagic_aigis_sig_sign(this->sk, data, chunk_empty, sig);
	}
	if (!transcript(data, &t)) { return FALSE; }
	success = pqmagic_aigis_sig_sign(this->sk, t,
		chunk_from_str(PQMAGIC_COMPOSITE_CONTEXT), &a) &&
		this->ed->sign(this->ed, SIGN_ED25519, NULL, t, &b) && b.ptr && b.len == 64;
	if (success)
	{
		*sig = chunk_alloc(PQMAGIC_COMPOSITE_SIG_BYTES);
		success = !!sig->ptr;
		if (success) { memcpy(sig->ptr, a.ptr, a.len); memcpy(sig->ptr + a.len, b.ptr, b.len); }
		else { *sig = chunk_empty; }
	}
	chunk_clear(&a);
	chunk_clear(&b);
	chunk_clear(&t);
	return success;
}

static private_key_t *private_create(key_type_t type, chunk_t seed)
{
	private_sig_t *this;
	chunk_t pk = chunk_empty, epk, raw;
	uint8_t ed_der[48] = {
		0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20,
	};
	public_key_t *edpub;
	bool success;

	this = malloc(sizeof(*this));
	if (!this) { return NULL; }
	*this = (private_sig_t){
		.public = {
			.get_type = _priv_type, .supported_signature_schemes = _priv_schemes,
			.sign = _priv_sign, .decrypt = _priv_decrypt, .get_keysize = _priv_size,
			.get_public_key = _priv_public, .equals = private_key_equals,
			.belongs_to = private_key_belongs_to, .get_fingerprint = _priv_fp,
			.has_fingerprint = private_key_has_fingerprint, .get_encoding = _priv_encoding,
			.get_ref = _priv_ref, .destroy = _priv_destroy,
		},
		.type = type, .ref = 1,
	};
	this->seed = chunk_alloc(seed.len);
	if (!this->seed.ptr) { _priv_destroy(this); return NULL; }
	memcpy(this->seed.ptr, seed.ptr, seed.len);
	if (!pqmagic_aigis_sig_expand_seed(chunk_create(seed.ptr, 32), &pk, &this->sk))
	{
		_priv_destroy(this); return NULL;
	}
	if (type == KEY_COMPOSITE_AIGIS_SIG2_ED25519)
	{
		/* RFC8410 wraps the 32-byte Ed seed in an inner OCTET STRING. */
		memcpy(ed_der + 16, seed.ptr + 32, 32);
		this->ed = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
			BUILD_BLOB_ASN1_DER, chunk_from_thing(ed_der), BUILD_END);
		memwipe(ed_der, sizeof(ed_der));
		if (!this->ed) { chunk_free(&pk); _priv_destroy(this); return NULL; }
		edpub = this->ed->get_public_key(this->ed);
		if (!edpub) { chunk_free(&pk); _priv_destroy(this); return NULL; }
		success = edpub->get_encoding(edpub, PUBKEY_SPKI_ASN1_DER, &epk);
		edpub->destroy(edpub);
		if (!success || epk.len != 44)
		{
			chunk_free(&pk); if (success) { chunk_free(&epk); } _priv_destroy(this); return NULL;
		}
		/* Provider's canonical RFC8410 SPKI: final 32 bytes are raw public key. */
		raw = chunk_alloc(PQMAGIC_COMPOSITE_PUBLIC_BYTES);
		if (!raw.ptr) { chunk_free(&pk); chunk_free(&epk); _priv_destroy(this); return NULL; }
		memcpy(raw.ptr, pk.ptr, pk.len); memcpy(raw.ptr + pk.len, epk.ptr + epk.len - 32, 32);
		chunk_free(&epk);
		chunk_free(&pk);
		pk = raw;
	}
	this->pub = public_create(type, pk);
	chunk_free(&pk);
	if (!this->pub) { _priv_destroy(this); return NULL; }
	return &this->public;
}

private_key_t *pqmagic_sig_private_key_gen(key_type_t type, va_list args)
{
	builder_part_t part;
	u_int size = 256;
	uint8_t seed[64];
	rng_t *rng;
	private_key_t *key = NULL;
	size_t len = type == KEY_AIGIS_SIG2_SM3 ? 32 : 64;

	while ((part = va_arg(args, builder_part_t)) != BUILD_END)
	{
		if (part != BUILD_KEY_SIZE) { return NULL; }
		size = va_arg(args, u_int);
	}
	if (size && size != 256) { return NULL; }
	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng) { return NULL; }
	if (rng->get_bytes(rng, len, seed))
	{
		key = private_create(type, chunk_create(seed, len));
	}
	rng->destroy(rng);
	memwipe(seed, sizeof(seed));
	return key;
}

static bool load_blob(va_list args, chunk_t *blob)
{
	builder_part_t part;
	bool found = FALSE;
	*blob = chunk_empty;
	while ((part = va_arg(args, builder_part_t)) != BUILD_END)
	{
		if (part != BUILD_BLOB_ASN1_DER || found) { return FALSE; }
		*blob = va_arg(args, chunk_t);
		found = TRUE;
	}
	return found;
}
private_key_t *pqmagic_sig_private_key_load(key_type_t type, va_list args)
{
	chunk_t blob, raw;
	if (!load_blob(args, &blob) || !pqmagic_sig_decode(type, TRUE, blob, &raw)) { return NULL; }
	return private_create(type, raw);
}
public_key_t *pqmagic_sig_public_key_load(key_type_t type, va_list args)
{
	chunk_t blob, raw;
	public_sig_t *pub;
	if (!load_blob(args, &blob) || !pqmagic_sig_decode(type, FALSE, blob, &raw)) { return NULL; }
	pub = public_create(type, raw);
	return pub ? &pub->public : NULL;
}
private_key_t *pqmagic_composite_sig_private_key_gen(key_type_t type, va_list args)
{
	return type == KEY_COMPOSITE_AIGIS_SIG2_ED25519 ? pqmagic_sig_private_key_gen(type, args) : NULL;
}
private_key_t *pqmagic_composite_sig_private_key_load(key_type_t type, va_list args)
{
	return type == KEY_COMPOSITE_AIGIS_SIG2_ED25519 ? pqmagic_sig_private_key_load(type, args) : NULL;
}
public_key_t *pqmagic_composite_sig_public_key_load(key_type_t type, va_list args)
{
	return type == KEY_COMPOSITE_AIGIS_SIG2_ED25519 ? pqmagic_sig_public_key_load(type, args) : NULL;
}
