/* Exercise the actual VICI load-conn callback without opening a socket. */
#include <assert.h>
#include <stdio.h>
#include <daemon.h>
#include <plugins/vici/vici_config.h>
#include <plugins/vici/vici_builder.h>
static vici_command_cb_t load_command;
static void *load_user;
static void manage(vici_dispatcher_t *this, char *name, vici_command_cb_t cb, void *user)
{
	if (streq(name,"load-conn")) { load_command = cb; load_user = user; }
}
static void check(char *local, char *remote, bool success)
{
	vici_dispatcher_t dispatcher = { .manage_command = manage };
	vici_config_t *config = vici_config_create(&dispatcher,NULL,NULL);
	vici_builder_t *builder = vici_builder_create();
	vici_message_t *request, *reply;
	builder->begin_section(builder,"aigis-vici-test");
	builder->add_kv(builder,"version","2");
	builder->begin_section(builder,"local"); builder->add_kv(builder,"auth","%s",local); builder->end_section(builder);
	builder->begin_section(builder,"remote"); builder->add_kv(builder,"auth","%s",remote); builder->end_section(builder);
	builder->end_section(builder);
	request = builder->finalize(builder);
	assert(load_command);
	reply = load_command(load_user,"load-conn",1,request);
	assert(reply);
	if (streq(reply->get_str(reply,"no","success"),"yes") != success)
	{
		fprintf(stderr,"Unexpected VICI load-conn result for %s / %s: %s\n",local,remote,
			reply->get_str(reply,"success","errmsg"));
		abort();
	}
	reply->destroy(reply); request->destroy(request); config->destroy(config);
}
int main(void)
{
	char *m1 = "ike:aigissig2ed25519-sha512", *m2 = "aigissig2ed25519-sha512";
	assert(library_init(NULL,"vici-profile-test"));
	assert(libcharon_init());
	plugin_loader_add_plugindirs(PLUGINDIR,"random openssl pqmagic");
	assert(lib->plugins->load(lib->plugins,"random openssl pqmagic"));
	check(m1,m1,TRUE); check(m2,m1,TRUE); check(m1,m2,FALSE);
	check("pubkey","pubkey",TRUE);
	check(m1,"ike:aigissig2ed25519-sha256",FALSE);
	check(m1,"ike:aigissig2ed25519-sha512-junk",FALSE);
	check(m1,"ike:AIGISSIG2ED25519-sha512",FALSE);
	libcharon_deinit(); library_deinit();
	puts("Actual VICI profile validation, M2 missing CA and local normalization: passed");
}
