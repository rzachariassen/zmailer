/*
 *  smtphook.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 2004
 *
 */

/*
 * This is a way to allow (if configured, and enabled) calling
 * of external perl scripts to handle various tasks that are
 * not trivially hardwireable into C code, but what people
 * might want to change themselves.
 *
 */

/* TODO:
 *  - Testing (1st write-thru is done; 2004-Jul-13)
 *  - Profiling (should this be in a subserver of its own ?)
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

static PerlInterpreter *my_perl; /* = NULL */
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
   connections, or open databases, or ... */

int ZSMTP_hook_init(argc, argv, env, filename)
     const int argc;
     char **argv;
     const char **env;
     const char *filename;
{
	int exitstatus = 0;
	char * embedding[2];
	const char *zconf = getzenv("ZCONFIG");
	const char **envp, **pp;
	int i;


	/* Modify environment data so that ZCONFIG will
	   be first env variable to be given to the perl
	   environment! */

	if (zconf) zconf -= 8;

	for (i = 0, pp=env; *pp; ++i, ++pp) ;

	envp = malloc((sizeof(char *) * (i+3)));
	if (!envp) return -1; /* OOPS! */

	envp[0] = zconf;
	for (i = 1, pp=env; *pp; ++i, ++pp)
	  envp[i] = *pp;
	envp[i] = NULL;

	/* Now setup perl environment */

	PERL_SYS_INIT3(&argc, &argv, &envp);

	my_perl = perl_alloc();
	if (!my_perl) {
	  /* FIXME: FIXME: error processing */
	}
	perl_construct(my_perl);

	embedding[0] = "";
	embedding[1] = (char*)filename;

	exitstatus = perl_parse( my_perl, xs_init, 2, embedding, NULL);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	if (!exitstatus) {

	  perl_run(my_perl);

	} else {

	  type(NULL,0,NULL,"Failed to parse perlhook script: '%s'",
	       filename);

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
	if (!my_perl) return;

	PL_perl_destruct_level = 0;
	perl_destruct(my_perl);
	perl_free(my_perl);
	PERL_SYS_TERM();
	my_perl = NULL;
}


/* Funcions used in actual processing of things */

/* return value !0: formed an opinnion */
int ZSMTP_hook_set_ipaddress(ipaddrstr, retp)
     const char *ipaddrstr;
     int *retp;
{
	dSP;
	int count;
	int rc = 0;

	if (!my_perl) return 0;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP) ;
	XPUSHs(sv_2mortal(newSVpv(ipaddrstr,0)));
	PUTBACK ;

	count = call_pv("ZSMTP::hook::set_ipaddress",G_ARRAY|G_EVAL);

	SPAGAIN;

	if (count != 2) {
	  type(NULL,0,NULL,"ZSMTP::hook::set_ipaddress() perl call returned %d results, not 2!", count);
	} else {
	  /* Result vector is:
	       (0,  ii)  -> no opinnion, no returned value
	       (!0, ii)  -> opinnion, value 'ii' returns via *retp
	  */
	  int result = POPi;
	  rc         = POPi;

	  if (rc) {
	    if (retp)
	      *retp = result;
	  }
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return rc;
}

/* return value !0: formed an opinnion */
int ZSMTP_hook_set_user(user, kind, retp)
     const char *user, *kind;
     int *retp;
{
	dSP;
	int count;
	int rc = 0;

	if (!my_perl) return 0;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP) ;
	XPUSHs(sv_2mortal(newSVpv(user,0)));
	XPUSHs(sv_2mortal(newSVpv(kind,0)));
	PUTBACK ;

	count = call_pv("ZSMTP::hook::set_user",G_ARRAY|G_EVAL);

	SPAGAIN;

	if (count != 2) {
	  type(NULL,0,NULL,"ZSMTP::hook::set_user() perl call returned %d results, not 2!", count);
	} else {
	  /* Result vector is:
	       (0,  ii)  -> no opinnion, no returned value
	       (!0, ii)  -> opinnion, value 'ii' returns via *retp
	  */
	  int result = POPi;
	  rc         = POPi;

	  if (rc) {
	    if (retp)
	      *retp = result;
	  }
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return rc;
}

/* return value !0: formed an opinnion */
int ZSMTP_hook_mailfrom(state, str, len, retp)
     struct policystate *state;
     const char *str;
     const int len;
     int *retp;
{
	dSP;
	int count;
	int rc = 0;

	if (!my_perl) return 0;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP) ;
	XPUSHs(sv_2mortal(newSVpvn(str,len)));
	PUTBACK ;

	count = call_pv("ZSMTP::hook::mailfrom",G_ARRAY|G_EVAL);

	SPAGAIN;

	if (count != 2) {
	  type(NULL,0,NULL,"ZSMTP::hook::mailfrom() perl call returned %d results, not 2!", count);
	} else {
	  /* Result vector is:
	       (0,  ii)  -> no opinnion, no returned value
	       (!0, ii)  -> opinnion, value 'ii' returns via *retp
	  */
	  int result = POPi;
	  rc         = POPi;

	  if (rc) {
	    if (retp)
	      *retp = result;
	  }
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return rc;
}

/* return value !0: formed an opinnion */
int ZSMTP_hook_rcptto(state, str, len, retp)
     struct policystate *state;
     const char *str;
     const int len;
     int *retp;
{
	dSP;
	int count;
	int rc = 0;

	if (!my_perl) return 0;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP) ;
	XPUSHs(sv_2mortal(newSVpvn(str,len)));
	PUTBACK ;

	count = call_pv("ZSMTP::hook::rcptto",G_ARRAY|G_EVAL);

	SPAGAIN;

	if (count != 2) {
	  type(NULL,0,NULL,"ZSMTP::hook::rcptto() perl call returned %d results, not 2!", count);
	} else {
	  /* Result vector is:
	       (0,  ii)  -> no opinnion, no returned value
	       (!0, ii)  -> opinnion, value 'ii' returns via *retp
	  */
	  int result = POPi;
	  rc         = POPi;

	  if (rc) {
	    if (retp)
	      *retp = result;
	  }
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return rc;
}
#endif
