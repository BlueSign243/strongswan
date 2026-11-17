/*
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "test_suite.h"
#include <daemon.h>
#include <tests/utils/exchange_test_helper.h>
#include <tests/utils/sa_asserts.h>
#include <tests/utils/mock_dh.h>
#include <encoding/payloads/ke_payload.h>

static bool corrupt_ciphertext(listener_t *listener, ike_sa_t *ike_sa,
							   message_t *message, bool incoming, bool plain)
{
	if (plain && incoming &&
		message->get_exchange_type(message) == IKE_INTERMEDIATE &&
		!message->get_request(message))
	{
		ke_payload_t *ke = (ke_payload_t*)message->get_payload(message,
															PLV2_KEY_EXCHANGE);
		chunk_t ct;

		ck_assert(ke);
		ck_assert_int_eq(ke->get_key_exchange_method(ke), AIGIS_ENC_2_SM3);
		ct = ke->get_key_exchange_data(ke);
		ck_assert_int_eq(ct.len, 992);
		ct.ptr[0] ^= 1;
		free(listener);
		return FALSE;
	}
	return TRUE;
}

/* Test that a same-length invalid ciphertext cannot produce an authenticated
 * SA. The fault is injected after decryption to exercise KEM rejection itself. */
START_TEST(test_aigis_invalid_ciphertext)
{
	exchange_test_sa_conf_t conf = {
		.initiator.ike = "aes256gcm16-prfsha384-ecp256-ke1_aigisenc2sm3",
		.responder.ike = "aes256gcm16-prfsha384-ecp256-ke1_aigisenc2sm3",
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child;
	listener_t *listener;

	lib->crypto->remove_ke(lib->crypto, (ke_constructor_t)mock_dh_create);
	lib->settings->set_bool(lib->settings, "%s.accept_private_algs", TRUE,
							lib->ns);
	child = exchange_test_helper->create_sa(exchange_test_helper, &a, &b, &conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);
	call_ikesa(a, initiate, child, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	/* Initiator sends a genuine Aigis public key. */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	INIT(listener, .message = corrupt_ciphertext);
	exchange_test_helper->add_listener(exchange_test_helper, listener);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	/* The IKE_AUTH request uses divergent keys and must fail verification. */
	ck_assert(SUCCESS !=
		exchange_test_helper->process_message(exchange_test_helper, b, NULL));
	ck_assert(a->get_state(a) != IKE_ESTABLISHED);
	ck_assert(b->get_state(b) != IKE_ESTABLISHED);
	assert_child_sa_count(a, 0);
	assert_child_sa_count(b, 0);
	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

Suite *aigis_suite_create()
{
	Suite *s = suite_create("aigis");
	TCase *tc = tcase_create("implicit rejection");
	tcase_add_test(tc, test_aigis_invalid_ciphertext);
	suite_add_tcase(s, tc);
	return s;
}
