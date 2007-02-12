/*
 *  smtphook.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 2004
 *  Perl support extended by Daniel Kiper <dkiper@netspace.com.pl>.
 */

/*
 * This is a way to allow (if configured, and enabled) calling
 * of external perl scripts to handle various tasks that are
 * not trivially hardwireable into C code, but what people
 * might want to change themselves.
 *
 */

#include "hostenv.h"

char *perlhookpath; /* for cfgread() use in every case.. */

#ifdef DO_PERL_EMBED

/* The DB includes are needed for included internal policy-state
   declarations. Not for the perl hooks per se. */

#include "sleepycatdb.h"

#ifdef HAVE_NDBM
#define datum Ndatum
#include <ndbm.h>
#undef datum
#endif
#ifdef HAVE_GDBM
#define datum Gdatum
#include <gdbm.h>
#undef datum
#endif

#define _POLICYTEST_INTERNAL_
#include "smtpserver.h"

#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;
static void xs_init (pTHX);

EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

EXTERN_C void
xs_init(pTHX)
{
	char *file = __FILE__;
	dXSUB_SYS;

	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}


/* Called at master server start to load in necessary stuff,
   and said stuff is NOT allowed to make e.g. network socket
   connections, or open databases, or ... anything permanent
   creating new file descriptors that will live beyond fork()
   on arriving connection.
*/

int ZSMTP_hook_init()
{
	const char *smtpperl5opt;
	char *argv[] = {"", perlhookpath};
	int argc = sizeof(argv) / sizeof(char *), exitstatus;

#ifdef HAVE_PUTENV
	if ((smtpperl5opt = getzenv("SMTPPERL5OPT")) != NULL)
		if (putenv((char *)smtpperl5opt - 9) == -1)
			type(NULL , 0, NULL, "Can not set PERL5OPT environment variable !");
#endif

	PERL_SYS_INIT3(&argc, &argv, NULL);

	if ((my_perl = perl_alloc()) == NULL) {
		type(NULL , 0, NULL, "Can not allocate memory for perl !");
		return 0;
	}

	perl_construct(my_perl);

	exitstatus = perl_parse(my_perl, xs_init, argc, argv, NULL);

#if PERL_REVISION >= 5 && PERL_VERSION >= 7 && PERL_SUBVERSION >= 2
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

	if (!exitstatus) {
	  perl_run(my_perl);
	  return 1; /*  OK! */

	} else {
	  type(NULL, 0, NULL,
	       "Failed to parse perlhook script: '%s'", perlhookpath);

	  PL_perl_destruct_level = 0;
	  perl_destruct(my_perl);
	  perl_free(my_perl);
	  PERL_SYS_TERM();
	  my_perl = NULL;
	}
	return 0;
}

void ZSMTP_hook_atexit()
{
	if (my_perl == NULL)
		return;

	PL_perl_destruct_level = 0;
	perl_destruct(my_perl);
	perl_free(my_perl);
	PERL_SYS_TERM();
	my_perl = NULL;
}

void ZSMTP_hook_set_ipaddress(rhostaddr, rport, rhostname, lhostaddr, lport, lhostname)
	const char *rhostaddr;
	int rport;
	const char *rhostname;
	const char *lhostaddr;
	int lport;
	const char *lhostname;
{
	dSP;

	/* Testing this is TOO LATE!
	   This must not be called at all !

	   if (my_perl == NULL)
	      return;

	*/

	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	if (rhostaddr != NULL && strlen(rhostaddr) > 0)
		XPUSHs(sv_2mortal(newSVpv(rhostaddr, 0)));
	else
		XPUSHs(&PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(rport)));
	if (rhostname != NULL && strlen(rhostname) > 0)
		XPUSHs(sv_2mortal(newSVpv(rhostname, 0)));
	else
		XPUSHs(&PL_sv_undef);
	if (lhostaddr != NULL && strlen(lhostaddr) > 0)
		XPUSHs(sv_2mortal(newSVpv(lhostaddr, 0)));
	else
		XPUSHs(&PL_sv_undef);
	XPUSHs(sv_2mortal(newSViv(lport)));
	if (lhostname != NULL && strlen(lhostname) > 0)
		XPUSHs(sv_2mortal(newSVpv(lhostname, 0)));
	else
		XPUSHs(&PL_sv_undef);
	PUTBACK;
	call_pv("ZSMTP::hook::set_ipaddress", G_DISCARD | G_EVAL);
	FREETMPS;
	LEAVE;
}

void ZSMTP_hook_set_user(user, kind)
     const char *user, *kind;
{
	dSP;

	if (my_perl == NULL)
		return;

	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	if (user != NULL && strlen(user) > 0)
		XPUSHs(sv_2mortal(newSVpv(user, 0)));
	else
		XPUSHs(&PL_sv_undef);
	if (kind != NULL && strlen(kind) > 0)
		XPUSHs(sv_2mortal(newSVpv(kind, 0)));
	else
		XPUSHs(&PL_sv_undef);
	PUTBACK;
	call_pv("ZSMTP::hook::set_user", G_DISCARD | G_EVAL);
	FREETMPS;
	LEAVE;
}

int ZSMTP_hook_univ(hook, state, str, len, retp)
	const char *hook;
     struct policystate *state;
     const unsigned char *str;
     const int len;
     int *retp;
{
	int count;
	SV *ZSMTP_hook_hdr, *message, *rc, *result;
	dSP;

	if (my_perl == NULL)
		return 0;

	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	if (str != NULL && len > 0)
		XPUSHs(sv_2mortal(newSVpvn(str, len)));
	else
		XPUSHs(&PL_sv_undef);
	PUTBACK;
	count = call_pv(hook, G_ARRAY | G_EVAL);
	SPAGAIN;

	if (count != 4) {
	PUTBACK;
	FREETMPS;
	LEAVE;
		type(NULL, 0, NULL, "%s perl call returned %d results, not 4!", hook, count);
		return 0;
	}

	ZSMTP_hook_hdr = POPs;
	message = POPs;
	result = POPs;
	rc = POPs;

	if (!SvIOK(rc) || !SvIVX(rc)) {
		PUTBACK;
		FREETMPS;
		LEAVE;
		return 0;
	}

	if (SvPOK(ZSMTP_hook_hdr)) {
		if (state->ZSMTP_hook_hdr != NULL)
			free(state->ZSMTP_hook_hdr);
		state->ZSMTP_hook_hdr = strdup(SvPVX(ZSMTP_hook_hdr));
	}

	if (SvIVX(rc) < 0) {
		PUTBACK;
		FREETMPS;
		LEAVE;
		return 0;
	}

	if (retp != NULL)
		*retp = SvIOK(result) ? SvIVX(result) : 0;

	if (SvPOK(message)) {
		if (state->message != NULL)
			free(state->message);
		state->message = strdup(SvPVX(message));
	}

	PUTBACK;
	FREETMPS;
	LEAVE;
	return 1;
}

#endif
