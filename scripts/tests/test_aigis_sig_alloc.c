/* Test-only fault injection for allocations owned by the new key/DER code. */
#include <assert.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <library.h>
#include <plugins/pqmagic/pqmagic_composite_sig.h>
#include <plugins/pqmagic/pqmagic_sig_encoding.h>
#include "../../src/libstrongswan/tests/data/aigis_sig_vectors.h"
static int fail_after = -1;
static struct { void *ptr; size_t len; } allocated[256];
void __real_free(void *p);
void __wrap_free(void *p)
{
	int i, j;
	for (i = 0; p && i < 256; i++)
	{
		if (allocated[i].ptr == p)
		{
			/* A seed still present at free is a plugin-owned secret leak.
			 * The exported DER is explicitly cleared by this test's caller. */
			for (j = 0; j + 32 <= allocated[i].len; j++)
			{
				uint8_t *q = (uint8_t*)p + j;
				int k;
				for (k = 0; k < 32 && q[k] == k; k++) { }
				assert(k != 32);
			}
			allocated[i].ptr = NULL; break;
		}
	}
	__real_free(p);
}
void *__real_malloc(size_t n);
void *__wrap_malloc(size_t n)
{
	if (fail_after == 0) { fail_after = -1; return NULL; }
	if (fail_after > 0) { fail_after--; }
	void *p = __real_malloc(n);
	int i;
	for (i = 0; p && i < 256; i++)
	{
		if (!allocated[i].ptr) { allocated[i].ptr = p; allocated[i].len = n; break; }
	}
	assert(i < 256); return p;
}
#define V(x) chunk_create((void*)(x), sizeof(x))
static private_key_t *load(key_type_t type, ...)
{
	private_key_t *key; va_list args;
	va_start(args, type); key = pqmagic_sig_private_key_load(type,args); va_end(args); return key;
}
int main(void)
{
	private_key_t *key, *attempt;
	public_key_t *pub;
	chunk_t der, sig;
	int i;
	assert(library_init(NULL,"alloc-test"));
	/* Ed25519/SHA512 need only the default provider; avoid the unrelated
	 * reloadable legacy-provider lifetime in this isolated LSan process. */
	lib->settings->set_bool(lib->settings,"alloc-test.plugins.openssl.load_legacy",FALSE);
	plugin_loader_add_plugindirs(PLUGINDIR, "random openssl pkcs8 pem");
	assert(lib->plugins->load(lib->plugins,"random openssl pkcs8 pem"));
	key = load(KEY_COMPOSITE_AIGIS_SIG2_ED25519, BUILD_BLOB_ASN1_DER, V(test_composite_pkcs8), BUILD_END);
	assert(key); pub = key->get_public_key(key);
	for (i = 0; i < 16; i++)
	{
		fail_after = i;
		attempt = load(KEY_COMPOSITE_AIGIS_SIG2_ED25519, BUILD_BLOB_ASN1_DER, V(test_composite_pkcs8), BUILD_END);
		fail_after = -1;
		DESTROY_IF(attempt);
	}
	for (i = 0; i < 5; i++)
	{
		bool ok;
		fail_after = i;
		ok = key->sign(key,SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512,NULL,V(test_message),&sig);
		fail_after = -1;
		if (ok) { assert(chunk_equals(sig,V(test_composite_sig))); chunk_clear(&sig); }
		else { assert(!sig.ptr && !sig.len); }
	}
	fail_after = 0;
	assert(!pub->verify(pub,SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512,NULL,V(test_message),V(test_composite_sig)));
	fail_after = -1;
	fail_after = 0;
	assert(!key->get_encoding(key,PRIVKEY_ASN1_DER,&der));
	assert(!der.ptr && !der.len); fail_after = -1;
	assert(key->get_encoding(key,PRIVKEY_ASN1_DER,&der));
	chunk_clear(&der);
	pub->destroy(pub); key->destroy(key); library_deinit();
	/* This standalone process never reinitializes OpenSSL. Run its process
	 * cleanup before LSan, unlike reloadable plugin unit-test lifetimes. */
	OPENSSL_cleanup();
	for (i = 0; i < 256; i++) { assert(!allocated[i].ptr); }
	puts("Key object/transcript/signature/DER allocation failure handling: passed");
}
