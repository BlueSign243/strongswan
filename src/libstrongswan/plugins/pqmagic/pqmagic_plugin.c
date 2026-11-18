/*
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "pqmagic_plugin.h"
#include "pqmagic_kem.h"
#ifdef HAVE_PQMAGIC_SIGN
#include "pqmagic_aigis_sig.h"
#include "pqmagic_composite_sig.h"
#endif

typedef struct {
	plugin_t public;
	bool signatures;
} private_plugin_t;

METHOD(plugin_t, get_name, char*,
	private_plugin_t *this)
{
	return "pqmagic";
}

METHOD(plugin_t, get_features, int,
	private_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(KE, pqmagic_kem_create),
			PLUGIN_PROVIDE(KE, AIGIS_ENC_2_SM3),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
		/* Keep all signature features after the KEM group. */
#ifdef HAVE_PQMAGIC_SIGN
		PLUGIN_REGISTER(PRIVKEY, pqmagic_aigis_sig_private_key_load, FALSE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_AIGIS_SIG2_SM3),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
		PLUGIN_REGISTER(PRIVKEY_GEN, pqmagic_aigis_sig_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_AIGIS_SIG2_SM3),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
		PLUGIN_REGISTER(PUBKEY, pqmagic_aigis_sig_public_key_load, FALSE),
			PLUGIN_PROVIDE(PUBKEY, KEY_AIGIS_SIG2_SM3),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_AIGIS_SIG2_SM3),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_AIGIS_SIG2_SM3),
		PLUGIN_REGISTER(PRIVKEY, pqmagic_composite_sig_private_key_load, FALSE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_COMPOSITE_AIGIS_SIG2_ED25519),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(HASHER, HASH_SHA512),
				PLUGIN_DEPENDS(PUBKEY, KEY_ED25519),
				PLUGIN_DEPENDS(PRIVKEY, KEY_ED25519),
		PLUGIN_REGISTER(PRIVKEY_GEN, pqmagic_composite_sig_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_COMPOSITE_AIGIS_SIG2_ED25519),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
				PLUGIN_DEPENDS(HASHER, HASH_SHA512),
				PLUGIN_DEPENDS(PUBKEY, KEY_ED25519),
				PLUGIN_DEPENDS(PRIVKEY, KEY_ED25519),
		PLUGIN_REGISTER(PUBKEY, pqmagic_composite_sig_public_key_load, FALSE),
			PLUGIN_PROVIDE(PUBKEY, KEY_COMPOSITE_AIGIS_SIG2_ED25519),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(HASHER, HASH_SHA512),
				PLUGIN_DEPENDS(PUBKEY, KEY_ED25519),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512),
			PLUGIN_DEPENDS(HASHER, HASH_SHA512),
			PLUGIN_DEPENDS(PRIVKEY_SIGN, SIGN_ED25519),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512),
			PLUGIN_DEPENDS(HASHER, HASH_SHA512),
			PLUGIN_DEPENDS(PUBKEY_VERIFY, SIGN_ED25519),
#endif
	};
	*features = f;
	if (!this->signatures) { return 3; }
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_plugin_t *this)
{
	free(this);
}

PLUGIN_DEFINE(pqmagic)
{
	private_plugin_t *this;

	if (!pqmagic_kem_check_variant())
	{
		DBG1(DBG_LIB, "PQMagic Aigis-enc mode 2 SM3 self-test failed; "
			 "check the linked library's hash variant/version");
		return NULL;
	}
	INIT(this,
		.public = {
			.get_name = _get_name,
			.get_features = _get_features,
			.destroy = _destroy,
		},
	);
#ifdef HAVE_PQMAGIC_SIGN
	this->signatures = pqmagic_aigis_sig_check_variant();
	if (!this->signatures)
	{
		DBG1(DBG_LIB, "PQMagic Aigis-sig mode 2 SM3 self-test failed; signatures disabled");
	}
#endif
	return &this->public;
}
