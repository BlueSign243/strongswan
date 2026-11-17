/*
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "pqmagic_plugin.h"
#include "pqmagic_kem.h"

typedef struct {
	plugin_t public;
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
	};
	*features = f;
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
	return &this->public;
}
