/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#include "pqmagic_sig_encoding.h"
#include "pqmagic_sig_params.h"
#include <asn1/asn1.h>
#include <asn1/oid.h>

int pqmagic_sig_oid(key_type_t type)
{
	return type == KEY_AIGIS_SIG2_SM3 ? OID_AIGIS_SIG2_SM3 :
		type == KEY_COMPOSITE_AIGIS_SIG2_ED25519 ?
		OID_AIGIS_SIG2_ED25519_SHA512 : OID_UNKNOWN;
}

/* Frozen UUID-derived OID content octets; canonical vectors cross-check this
 * representation against the oid.txt registry and docs/aigis-sig-profile.json. */
static const uint8_t aigis_oid[] = { 0x69,0xc8,0xa4,0xa7,0x86,0xcc,0xe7,0xda,0x81,0xeb,0x99,0x93,0x9c,0x88,0x8b,0x97,0xe6,0x97,0x75 };
static const uint8_t composite_oid[] = { 0x69,0x82,0x9c,0xfd,0xc2,0x86,0xd1,0x83,0xf2,0x8c,0xb1,0x92,0x97,0xe3,0xae,0xab,0xb1,0xb0,0x88,0x2a };

/* Only fixed v1 sizes, all below 65536; no generic BER parsing/allocation here. */
static size_t header(uint8_t *out, uint8_t tag, size_t len)
{
	out[0] = tag;
	if (len < 128) { out[1] = len; return 2; }
	out[1] = 0x82; out[2] = len >> 8; out[3] = len; return 4;
}

static size_t prefix(key_type_t type, bool secret, uint8_t out[64], size_t *rawlen)
{
	const uint8_t *oid;
	size_t oidlen, alglen, rawheader, bodylen, pos;
	if (type == KEY_AIGIS_SIG2_SM3)
	{ oid = aigis_oid; oidlen = sizeof(aigis_oid); *rawlen = secret ? 32 : 1312; }
	else if (type == KEY_COMPOSITE_AIGIS_SIG2_ED25519)
	{ oid = composite_oid; oidlen = sizeof(composite_oid); *rawlen = secret ? 64 : 1344; }
	else { return 0; }
	alglen = 4 + oidlen;
	rawheader = secret ? 2 : 4;
	bodylen = (secret ? 3 : 0) + alglen + rawheader + (secret ? 0 : 1) + *rawlen;
	pos = header(out, ASN1_SEQUENCE, bodylen);
	if (secret) { out[pos++] = ASN1_INTEGER; out[pos++] = 1; out[pos++] = 0; }
	out[pos++] = ASN1_SEQUENCE; out[pos++] = oidlen + 2;
	out[pos++] = ASN1_OID; out[pos++] = oidlen;
	memcpy(out + pos, oid, oidlen); pos += oidlen;
	pos += header(out + pos, secret ? ASN1_OCTET_STRING : ASN1_BIT_STRING, *rawlen + (secret ? 0 : 1));
	if (!secret) { out[pos++] = 0; }
	return pos;
}

chunk_t pqmagic_sig_encode(key_type_t type, bool secret, chunk_t raw)
{
	uint8_t pre[64];
	size_t len, n = prefix(type, secret, pre, &len);
	chunk_t der;
	if (!n || raw.len != len || !raw.ptr) { return chunk_empty; }
	der = chunk_alloc(n + len);
	if (!der.ptr) { return chunk_empty; }
	memcpy(der.ptr, pre, n); memcpy(der.ptr + n, raw.ptr, len);
	return der;
}

bool pqmagic_sig_decode(key_type_t type, bool secret, chunk_t der, chunk_t *raw)
{
	uint8_t pre[64];
	size_t len, n = prefix(type, secret, pre, &len);
	*raw = chunk_empty;
	if (!n || !der.ptr || der.len != n + len || !memeq(der.ptr, pre, n)) { return FALSE; }
	*raw = chunk_skip(der, n); return TRUE;
}
