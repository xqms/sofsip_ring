// Sofia-SIP simple phone ringer
// (C) 2010 Max Schwarz <Max@x-quadraht.de>

#include <assert.h>

#include <sofia-sip/su_alloc.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/msg_header.h>
#include <sofia-sip/sdp.h>
#include <stdlib.h>
#include <getopt.h>

su_home_t g_su_home;
su_root_t *g_su_root;
nua_t *g_nua;
nua_handle_t *g_register_handle;

// User information
const char *g_username = 0;
const char *g_password = 0;
const char *g_remote = 0;
const char *g_proxy = 0;

// Authentication
void sip_do_auth(nua_handle_t *nh, const char *scheme,
                 const char *realm, const char *user,
                 const char *password)
{
	char *tmpstr = 0;
	
	tmpstr = su_sprintf(&g_su_home, "%s:%s:%s:%s",
	                    scheme, realm, user, password);
	
	nua_authenticate(nh, NUTAG_AUTH(tmpstr), TAG_END());
	
	su_free(&g_su_home, tmpstr);
}

void sip_authenticate(nua_handle_t *nh, const sip_t *sip, tagi_t tags[])
{
	sip_www_authenticate_t const *wa = sip->sip_www_authenticate;
	sip_proxy_authenticate_t const *pa = sip->sip_proxy_authenticate;
	
	tl_gets(tags,
	        SIPTAG_WWW_AUTHENTICATE_REF(wa),
	        SIPTAG_PROXY_AUTHENTICATE_REF(pa),
	        TAG_NULL());
	
	const char *scheme;
	
	if(wa)
		sip_do_auth(nh, wa->au_scheme,
		            msg_params_find(wa->au_params, "realm="),
		            g_username, g_password);
	
	if(pa)
		sip_do_auth(nh, pa->au_scheme,
		            msg_params_find(pa->au_params, "realm="),
		            g_username, g_password);
}

// Unregistering
void sip_r_unregister(int status, char const *phrase, nua_handle_t *nh,
		const sip_t *sip, tagi_t tags[])
{
	printf("UNREGISTER: %d (%s)\n", status, phrase);
	
	if(status == 200)
	{
		printf("Unregistered successfully.\n");
		printf("Now quitting (this can take some time)\n");
		nua_shutdown(g_nua);
	}
}

// Calling

void sip_call(const char *address)
{
	nua_handle_t *handle;
	sip_to_t *to;
	sdp_session_t *l_sdp;
	sdp_parser_t *local_parser;
	const char *CAPS = "v=0\nm=audio 0 RTP/AVP 0\na=rtpmap:0 PCMU/8000";
	const char *pa_error = 0;
	const char *l_sdp_str;
	
	to = sip_to_make(&g_su_home, address);
	
	assert(to);
	
	handle = nua_handle(g_nua, NULL,
                            NUTAG_URL(to->a_url),
                            SIPTAG_TO(to),
                            TAG_NULL());
	
	local_parser = sdp_parse(&g_su_home, CAPS, strlen(CAPS), sdp_f_insane);
	pa_error = sdp_parsing_error(local_parser);
	assert(!pa_error);
	
	l_sdp = sdp_session(local_parser);
	if(l_sdp && l_sdp->sdp_media)
	{
		l_sdp->sdp_media->m_port = 16384;
	}
	
	sdp_printer_t *printer = sdp_print(&g_su_home, l_sdp, NULL, 0, sdp_f_config | sdp_f_insane);
	assert(!sdp_printing_error(printer));
	l_sdp_str = sdp_message(printer);
	
	
	nua_invite(handle,
	           SOATAG_USER_SDP_STR(l_sdp_str),
	           SOATAG_RTP_SORT(SOA_RTP_SORT_REMOTE),
	           SOATAG_RTP_SELECT(SOA_RTP_SELECT_ALL),
	           TAG_END());
	
	sdp_printer_free(printer);
	sdp_parser_free(local_parser);
}

void sip_r_call(int status, char const *phrase, nua_handle_t *nh,
                const sip_t *sip, tagi_t tags[])
{
	printf("INVITE: %d (%s)\n", status, phrase);
	
	switch(status)
	{
		case 401:
		case 407:
			sip_authenticate(nh, sip, tags);
			break;
		case 180:
		case 200:
			printf("Phone is ringing. Canceling call...\n");
			nua_cancel(nh, TAG_END());
			break;
		case 487:
			printf("Canceled. Unregistering...\n");
			nua_unregister(g_register_handle, TAG_END());
			break;
	}
}

// Shutdown
void sip_r_shutdown(int status, char const *phrase, nua_handle_t *nh,
		const sip_t *sip, tagi_t tags[])
{
	printf("SHUTDOWN: %d (%s)\n", status, phrase);
	
	if(status == 200)
		su_root_break(g_su_root);
}

// Registering
void sip_register()
{
	nua_handle_t *handle;
	sip_to_t *to;
	char aor[100];
	
	snprintf(aor, sizeof(aor), "sip:%s", g_username);
	
	to = sip_to_make(&g_su_home, aor);
	
	assert(to);
	
	handle = nua_handle(g_nua, NULL, SIPTAG_TO(to), TAG_NULL());
	
	nua_register(handle, NUTAG_M_FEATURES("expires=30"), TAG_NULL());
}

// Return of REGISTER
void sip_r_register(int status, char const *phrase, nua_t *nua, nua_handle_t *nh,
                    const sip_t *sip, tagi_t tags[])
{
	printf("REGISTER returned %d (%s)\n", status, phrase);
	
	if(status < 200)
		return;
	
	if(status == 401 || status == 407)
		sip_authenticate(nh, sip, tags);
	else if(status >= 300)
		assert(0);
	else if(status == 200)
	{
		printf("Successfully registered.\n");
		
		g_register_handle = nh;
		
		printf("Dialling...\n");
		sip_call(g_remote);
	}
}

void nua_callback(nua_event_t event, int status, char const *phrase, nua_t *nua,
                  nua_magic_t *magic, nua_handle_t *nh, nua_hmagic_t *hmagic,
                  sip_t const *sip, tagi_t tags[])
{
	switch(event)
	{
		case nua_r_register:
			sip_r_register(status, phrase, nua, nh, sip, tags);
			break;
		case nua_r_invite:
			sip_r_call(status, phrase, nh, sip, tags);
			break;
		case nua_r_unregister:
			sip_r_unregister(status, phrase, nh, sip, tags);
			break;
		case nua_r_shutdown:
			sip_r_shutdown(status, phrase, nh, sip, tags);
			break;
	}
}

void usage(FILE *dest, const char *appname)
{
	fprintf(dest, "Usage: %s --user <username> --proxy <proxy> --remote <remote> [options]\n"
	       "\n"
	       "Options:\n"
	       "  --password <password>  Use specified password. If this option is not given,\n"
	       "                         the password is asked from stdin\n"
	       "\n"
	       "%s is a small tool using the Sofia-SIP library (http://sofia-sip.sourceforge.net/).\n"
	       "It rings the specified SIP remote and hangs up immediately. It can be used to\n"
	       "notify someone by ringing their mobile phone once.\n",
	         appname, appname);
}

int main(int argc, char **argv)
{
	char aor[100];
	int c;
	int digit_optind = 0;
	
	// Init su OS abstraction layer
	su_init();
	su_home_init(&g_su_home);
	
	// Parse options
	while(1)
	{
		static struct option long_options[] = {
			{"user", required_argument, NULL, 'u'},
			{"proxy", required_argument, NULL, 'p'},
			{"password", required_argument, NULL, 's'},
			{"remote", required_argument, NULL, 'r'},
			{"help", no_argument, NULL, 'h'},
			{0, 0, 0, 0}
		};
		
		c = getopt_long(argc, argv, "u:p:s:r:h", long_options, NULL);
		
		if(c == -1)
			break;
		
		switch(c)
		{
			case 'h':
				usage(stdout, argv[0]);
				return 0;
			case 'u':
				g_username = optarg;
				break;
			case 'p':
				g_proxy = optarg;
				break;
			case 'r':
				g_remote = optarg;
				break;
			case 's':
				g_password = optarg;
				break;
			default:
				fprintf(stderr, "Unknown argument '%s'\n", argv[optind]);
				usage(stderr, argv[0]);
				return -1;
		}
	}
	
	if(!g_remote || !g_proxy || !g_username)
	{
		fprintf(stderr, "--remote, --proxy and --user arguments are mandatory!\n");
		return -1;
	}
	
	if(!g_password)
	{
		g_password = getpass("Password: ");
	}
	
	// Create su event loop
	g_su_root = su_root_create(&g_su_home);
	
	snprintf(aor, sizeof(aor), "sip:%s", g_username);
	
	g_nua = nua_create(g_su_root,
			   &nua_callback, NULL,
			   SIPTAG_FROM_STR(aor),
			   NUTAG_PROXY(g_proxy),
			   SOATAG_AF(SOA_AF_IP4_IP6),
			   TAG_NULL()
			   );
	
	sip_register();
	
	su_root_run(g_su_root);
	
	return 0;
}
