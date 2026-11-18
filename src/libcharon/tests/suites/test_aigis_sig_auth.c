/* Copyright (C) 2026. SPDX-License-Identifier: GPL-2.0-or-later */
#include "test_suite.h"
#include <time.h>
#include <daemon.h>
#include <sa/ikev2/authenticators/pubkey_authenticator.h>
#include <credentials/keys/signature_params.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/certificates/x509.h>
#include <tests/utils/exchange_test_helper.h>
#include <tests/utils/sa_asserts.h>
#include <tests/utils/mock_dh.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <sa/ikev2/keymat_v2.h>

START_TEST(test_auth_algorithm_boundary)
{
	signature_params_t params = { .scheme = SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512 }, *parsed;
	chunk_t alg, data, view;
	uint8_t len;
	key_type_t type;
	uint8_t signature[2509] = {};

	ck_assert(signature_params_build(&params, &alg));
	len = alg.len;
	data = chunk_cat("ccc", chunk_from_thing(len), alg, chunk_from_thing(signature));
	view = data;
	parsed = pubkey_authenticator_parse_auth_data(AUTH_DS, &type, &view);
	ck_assert_msg(parsed, "valid composite AUTH_DS must parse exact AlgorithmIdentifier");
	ck_assert_int_eq(parsed->scheme, params.scheme);
	ck_assert_int_eq(type, KEY_COMPOSITE_AIGIS_SIG2_ED25519);
	ck_assert_int_eq(view.len, 2509);
	signature_params_destroy(parsed);
	/* L=0, short DER, DER plus signature bytes, and out-of-range L. */
	data.ptr[0] = 0;
	view = data; ck_assert(!pubkey_authenticator_parse_auth_data(AUTH_DS, NULL, &view));
	data.ptr[0] = len-1;
	view = data; ck_assert(!pubkey_authenticator_parse_auth_data(AUTH_DS, NULL, &view));
	data.ptr[0] = len+1;
	view = data; ck_assert(!pubkey_authenticator_parse_auth_data(AUTH_DS, NULL, &view));
	data.ptr[0] = 255;
	view = chunk_create(data.ptr, len+1);
	ck_assert(!pubkey_authenticator_parse_auth_data(AUTH_DS, NULL, &view));
	data.ptr[0] = len;
	view = chunk_create(data.ptr, data.len-1);
	ck_assert(!pubkey_authenticator_parse_auth_data(AUTH_DS, NULL, &view));
	chunk_free(&data);
	chunk_free(&alg);
}
END_TEST

typedef struct {
	listener_t public;
	int mutate, auth_count;
} auth_listener_t;

static bool inspect_auth(listener_t *listener, ike_sa_t *ike_sa,
	message_t *message, bool incoming, bool plain)
{
	auth_listener_t *this = (auth_listener_t*)listener;
	if (incoming && plain && message->get_exchange_type(message) == IKE_SA_INIT && this->mutate == 5)
	{
		notify_payload_t *notify = message->get_notify(message, SIGNATURE_HASH_ALGORITHMS);
		chunk_t hashes;
		size_t i;
		ck_assert(notify); hashes = notify->get_notification_data(notify);
		for (i = 0; i+1 < hashes.len; i += 2) { hashes.ptr[i] = 0; hashes.ptr[i+1] = 2; }
	}
	if (incoming && plain && message->get_exchange_type(message) == IKE_SA_INIT && this->mutate == 9)
	{
		notify_payload_t *notify = message->get_notify(message, SIGNATURE_HASH_ALGORITHMS);
		enumerator_t *e = message->create_payload_enumerator(message);
		payload_t *payload;
		while (e->enumerate(e, &payload))
		{
			if (payload == (payload_t*)notify)
			{
				message->remove_payload_at(message, e); payload->destroy(payload); break;
			}
		}
		e->destroy(e);
	}
	if (incoming && plain && message->get_exchange_type(message) == IKE_AUTH)
	{
		auth_payload_t *auth = (auth_payload_t*)message->get_payload(message, PLV2_AUTH);
		if (auth)
		{
			chunk_t raw = auth->get_data(auth), sig = raw;
			signature_params_t *params;
			ck_assert_int_eq(auth->get_auth_method(auth), AUTH_DS);
			params = pubkey_authenticator_parse_auth_data(AUTH_DS, NULL, &sig);
			ck_assert(params);
			ck_assert_int_eq(params->scheme, SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512);
			ck_assert_int_eq(sig.len, 2509);
			signature_params_destroy(params);
			this->auth_count++;
			if (this->mutate == 1) { sig.ptr[0] ^= 1; }
			if (this->mutate == 2) { sig.ptr[sig.len-1] ^= 1; }
			if (this->mutate == 6) { raw.ptr[raw.ptr[0]] ^= 1; }
			if (this->mutate == 7) { auth->set_auth_method(auth, AUTH_RSA); }
			if (this->mutate == 8) { auth->set_data(auth, chunk_create(raw.ptr,raw.len-1)); }
			if (this->mutate == 3)
			{
				id_payload_t *id = (id_payload_t*)message->get_payload(message, PLV2_ID_INITIATOR);
				identification_t *wrong = identification_create_from_string("wrong.test");
				ck_assert(id);
				enumerator_t *enumerator = message->create_payload_enumerator(message);
				payload_t *payload;
				while (enumerator->enumerate(enumerator, &payload))
				{
					if (payload == (payload_t*)id)
					{
						message->remove_payload_at(message, enumerator);
						id->destroy(id);
						break;
					}
				}
				enumerator->destroy(enumerator);
				message->add_payload(message, (payload_t*)id_payload_create_from_identification(PLV2_ID_INITIATOR, wrong));
				wrong->destroy(wrong);
			}
		}
	}
	return TRUE;
}

static certificate_t *make_certificate(private_key_t *key, private_key_t *cakey,
	certificate_t *ca, char *name)
{
	public_key_t *pub = key->get_public_key(key);
	identification_t *subject = identification_create_from_string(ca ?
		(streq(name, "init") ? "CN=init" : "CN=resp") : "CN=Test CA");
	identification_t *san = identification_create_from_string(name);
	linked_list_t *sans = linked_list_create();
	certificate_t *cert;
	uint8_t serial = streq(name, "init") ? 1 : 2;
	signature_params_t scheme = { .scheme = cakey->get_type(cakey) == KEY_ED25519 ?
		SIGN_ED25519 : SIGN_COMPOSITE_AIGIS_SIG2_ED25519_SHA512 };

	sans->insert_last(sans, san);
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
		BUILD_SIGNING_KEY, cakey, BUILD_SIGNING_CERT, ca, BUILD_PUBLIC_KEY, pub,
		BUILD_SUBJECT, subject, BUILD_SUBJECT_ALTNAMES, sans,
		BUILD_X509_FLAG, ca ? 0 : X509_CA, BUILD_SERIAL, chunk_from_thing(serial),
		BUILD_NOT_BEFORE_TIME, time(NULL)-60, BUILD_NOT_AFTER_TIME, time(NULL)+3600,
		BUILD_SIGNATURE_SCHEME, &scheme, BUILD_END);
	pub->destroy(pub); subject->destroy(subject); san->destroy(san); sans->destroy(sans);
	ck_assert(cert);
	return cert;
}

static bool (*real_int_auth)(keymat_v2_t*, bool, chunk_t, chunk_t, chunk_t*);
static bool wrong_int_auth(keymat_v2_t *keymat, bool verify, chunk_t data, chunk_t prev, chunk_t *out)
{
	bool success = real_int_auth(keymat, verify, data, prev, out);
	if (success && verify && out->len) { out->ptr[0] ^= 1; }
	return success;
}

/* 0 M1 traditional issuer, 1 M2 composite chain; 2/3 corrupt each component,
 * 4 change ID, 5 reject classic chain under M2, 6 reject directly trusted leaf,
 * 7 reject an unrelated explicitly pinned CA. */
START_TEST(test_composite_ike_auth)
{
	mem_cred_t *creds = mem_cred_create();
	private_key_t *cakey, *keys[2];
	certificate_t *ca, *certs[2], *wrong = NULL;
	ike_sa_t *a, *b;
	ike_sa_id_t *ida, *idb;
	child_cfg_t *child;
	auth_listener_t listener = { .public.message = inspect_auth };
	char *m1 = "ike:aigissig2ed25519-sha512", *m2 = "aigissig2ed25519-sha512";
	bool strict = _i == 1 || (_i >= 5 && _i <= 7) || _i == 16;
	bool positive = _i <= 1 || _i == 15 || _i == 16;
	bool no_auth = _i == 9 || _i == 10 || _i == 11;
	exchange_test_sa_conf_t conf = {
		.initiator.ike = "aes256gcm16-prfsha384-ecp256-ke1_aigisenc2sm3",
		.responder.ike = "aes256gcm16-prfsha384-ecp256-ke1_aigisenc2sm3",
	};
	int i;

	lib->crypto->remove_ke(lib->crypto, (ke_constructor_t)mock_dh_create);
	lib->settings->set_bool(lib->settings, "%s.accept_private_algs", TRUE, lib->ns);
	cakey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
		_i == 0 || _i == 5 ? KEY_ED25519 : KEY_COMPOSITE_AIGIS_SIG2_ED25519,
		BUILD_KEY_SIZE, 256, BUILD_END);
	ck_assert(cakey);
	ca = make_certificate(cakey, cakey, NULL, "ca");
	if (_i != 6) { creds->add_cert(creds, TRUE, ca->get_ref(ca)); }
	for (i = 0; i < 2; i++)
	{
		keys[i] = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
			_i == 11 ? KEY_ED25519 : KEY_COMPOSITE_AIGIS_SIG2_ED25519, BUILD_KEY_SIZE, 256, BUILD_END);
		ck_assert(keys[i]);
		if (_i == 15)
		{
			public_key_t *pub = keys[i]->get_public_key(keys[i]);
			identification_t *id = identification_create_from_string(i ? "resp" : "init");
			certs[i] = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_TRUSTED_PUBKEY,
				BUILD_PUBLIC_KEY, pub, BUILD_SUBJECT, id, BUILD_END);
			pub->destroy(pub); id->destroy(id); ck_assert(certs[i]);
		}
		else { certs[i] = make_certificate(keys[i], cakey, ca, i ? "resp" : "init"); }
		creds->add_key(creds, keys[i]);
		creds->add_cert(creds, _i == 6 || _i == 15, certs[i]->get_ref(certs[i]));
	}
	if (_i == 7)
	{
		private_key_t *wk = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
			KEY_COMPOSITE_AIGIS_SIG2_ED25519, BUILD_KEY_SIZE, 256, BUILD_END);
		ck_assert(wk); wrong = make_certificate(wk, wk, NULL, "wrong"); wk->destroy(wk);
	}
	lib->credmgr->add_set(lib->credmgr, &creds->set);
	conf.initiator.auth = conf.responder.auth = strict ? m2 : m1;
	conf.initiator.cert = certs[0]; conf.responder.cert = certs[1];
	conf.initiator.ca = conf.responder.ca = (_i == 6 || _i == 15) ? NULL : wrong ?: ca;
	if (_i == 16) { conf.initiator.fragmentation = conf.responder.fragmentation = FRAGMENTATION_YES; }
	listener.mutate = _i >= 2 && _i <= 4 ? _i-1 : _i == 9 ? 5 : _i == 10 ? 9 : _i >= 12 && _i <= 14 ? _i-6 : 0;
	exchange_test_helper->add_listener(exchange_test_helper, &listener.public);
	child = exchange_test_helper->create_sa(exchange_test_helper, &a, &b, &conf);
	if (_i == 8)
	{
		keymat_v2_t *keymat = (keymat_v2_t*)a->get_keymat(a);
		real_int_auth = keymat->get_int_auth; keymat->get_int_auth = wrong_int_auth;
	}
	ida = a->get_id(a); idb = b->get_id(b);
	call_ikesa(a, initiate, child, NULL);
	idb->set_initiator_spi(idb, ida->get_initiator_spi(ida));
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	ida->set_responder_spi(ida, idb->get_responder_spi(idb));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	if (_i == 16)
	{
		message_t *first = exchange_test_helper->sender->dequeue(exchange_test_helper->sender), *duplicate;
		int packets = 1;
		ck_assert(first);
		duplicate = message_create_from_packet(first->get_packet(first));
		ck_assert_int_eq(duplicate->parse_header(duplicate), SUCCESS);
		exchange_test_helper->process_message(exchange_test_helper, b, first);
		/* Duplicate first encrypted fragment must not cause duplicate AUTH. */
		exchange_test_helper->process_message(exchange_test_helper, b, duplicate);
		while (!listener.auth_count && packets++ < 24)
		{ exchange_test_helper->process_message(exchange_test_helper, b, NULL); }
		ck_assert(packets > 1 && packets < 24);
		packets = 0;
		while (listener.auth_count < 2 && packets++ < 24)
		{ exchange_test_helper->process_message(exchange_test_helper, a, NULL); }
		ck_assert(packets > 1 && packets < 24);
	}
	else if (!no_auth) { exchange_test_helper->process_message(exchange_test_helper, b, NULL); }
	if (positive)
	{
		if (_i != 16) { exchange_test_helper->process_message(exchange_test_helper, a, NULL); }
		ck_assert_int_eq(listener.auth_count, 2);
		ck_assert_int_eq(a->get_state(a), IKE_ESTABLISHED);
		ck_assert_int_eq(b->get_state(b), IKE_ESTABLISHED);
		assert_child_sa_count(a, 1); assert_child_sa_count(b, 1);
	}
	else
	{
		ck_assert_int_eq(listener.auth_count, no_auth ? 0 : 1);
		ck_assert(b->get_state(b) != IKE_ESTABLISHED);
		assert_child_sa_count(b, 0);
	}
	call_ikesa(a, destroy); call_ikesa(b, destroy);
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	certs[0]->destroy(certs[0]); certs[1]->destroy(certs[1]);
	ca->destroy(ca); cakey->destroy(cakey); DESTROY_IF(wrong);
}
END_TEST

Suite *aigis_sig_auth_suite_create()
{
	Suite *s = suite_create("aigis_sig_auth");
	TCase *tc = tcase_create("RFC7427 strict boundary");
	tcase_add_test(tc, test_auth_algorithm_boundary);
	tcase_add_loop_test(tc, test_composite_ike_auth, 0, 11);
	tcase_add_loop_test(tc, test_composite_ike_auth, 11, 17);
	suite_add_tcase(s, tc);
	return s;
}
