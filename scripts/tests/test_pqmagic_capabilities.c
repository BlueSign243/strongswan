/* Test-only feature filtering proves real plugin dependency resolution. */
#include <assert.h>
#include <stdio.h>
#include <library.h>
#include <credentials/keys/private_key.h>
#include <plugins/plugin_feature.h>
static char *mode;
static plugin_feature_t filtered[16][1024];
static int slot;

int plugin_loader_feature_filter(plugin_t *plugin, plugin_feature_t **out)
{
	plugin_feature_t *original, *dest = filtered[slot++];
	int i, n = plugin->get_features(plugin, &original), count = 0;
	bool skip = FALSE;
	assert(slot <= 16 && n <= 1024);
	for (i = 0; i < n; i++)
	{
		plugin_feature_t *f = &original[i];
		if (f->kind == FEATURE_REGISTER || f->kind == FEATURE_CALLBACK) { skip = FALSE; }
		if (f->kind == FEATURE_PROVIDE)
		{
			skip = FALSE;
			if (streq(mode,"no-sha512") && f->type == FEATURE_HASHER && f->arg.hasher == HASH_SHA512) { skip = TRUE; }
			if (streq(mode,"no-ed"))
			{
				skip = (f->type == FEATURE_PRIVKEY && f->arg.privkey == KEY_ED25519) ||
					(f->type == FEATURE_PRIVKEY_GEN && f->arg.privkey_gen == KEY_ED25519) ||
					(f->type == FEATURE_PUBKEY && f->arg.pubkey == KEY_ED25519) ||
					(f->type == FEATURE_PRIVKEY_SIGN && f->arg.privkey_sign == SIGN_ED25519) ||
					(f->type == FEATURE_PUBKEY_VERIFY && f->arg.pubkey_verify == SIGN_ED25519);
			}
		}
		if (!skip) { dest[count++] = *f; }
	}
	*out = dest; return count;
}

int main(int argc, char **argv)
{
	private_key_t *key;
	key_exchange_t *a, *b;
	public_key_t *pub;
	chunk_t pk, ct, sa, sb, sig;
	bool full, single;
	assert(argc == 2); mode = argv[1]; full = streq(mode,"full"); single = !streq(mode,"bad-sig");
	assert(library_init(NULL,"cap-test"));
	plugin_loader_add_plugindirs(PLUGINDIR,"random openssl pkcs8 pem pqmagic");
	assert(lib->plugins->load(lib->plugins,"random openssl pkcs8 pem pqmagic"));
	assert(lib->plugins->has_feature(lib->plugins,(plugin_feature_t)PLUGIN_PROVIDE(PRIVKEY_GEN,KEY_COMPOSITE_AIGIS_SIG2_ED25519)) == full);
	assert(lib->plugins->has_feature(lib->plugins,(plugin_feature_t)PLUGIN_PROVIDE(PRIVKEY_SIGN,SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512)) == full);
	key = lib->creds->create(lib->creds,CRED_PRIVATE_KEY,KEY_COMPOSITE_AIGIS_SIG2_ED25519,BUILD_KEY_SIZE,256,BUILD_END);
	assert(!!key == full); DESTROY_IF(key);
	key = lib->creds->create(lib->creds,CRED_PRIVATE_KEY,KEY_AIGIS_SIG2_SM3,BUILD_KEY_SIZE,256,BUILD_END);
	assert(!!key == single);
	if (key)
	{
		pub = key->get_public_key(key);
		assert(key->sign(key,SIGN_AIGIS_SIG2_SM3,NULL,chunk_empty,&sig));
		assert(pub->verify(pub,SIGN_AIGIS_SIG2_SM3,NULL,chunk_empty,sig));
		chunk_clear(&sig); pub->destroy(pub); key->destroy(key);
	}
	/* Missing signature dependencies/self-test must leave the KEM operational. */
	a = lib->crypto->create_ke(lib->crypto,AIGIS_ENC_2_SM3);
	b = lib->crypto->create_ke(lib->crypto,AIGIS_ENC_2_SM3);
	assert(a && b && a->get_public_key(a,&pk) && b->set_public_key(b,pk));
	assert(b->get_public_key(b,&ct) && a->set_public_key(a,ct));
	assert(a->get_shared_secret(a,&sa) && b->get_shared_secret(b,&sb) && chunk_equals(sa,sb));
	chunk_free(&pk); chunk_free(&ct); chunk_clear(&sa); chunk_clear(&sb); a->destroy(a); b->destroy(b);
	library_deinit(); printf("Provider capabilities (%s) and KEM preservation: passed\n",mode);
}
