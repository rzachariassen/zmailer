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
 *    Everything + ...
 *     + internal state management - without global variable ??
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
	embedding[1] = filename;

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
	STRLEN n_a;

	if (!my_perl) return 0;

	return 0;
}

/* return value !0: formed an opinnion */
int ZSMTP_hook_setuser(user, kind, retp)
     const char *user, *kind;
     int *retp;
{
	STRLEN n_a;

	if (!my_perl) return 0;

	return 0;
}

/* return value !0: formed an opinnion */
int ZSMTP_hook_mailfrom(state, str, len, retp)
     struct policystate *state;
     const char *str;
     const int len;
     int *retp;
{
	STRLEN n_a;

	if (!my_perl) return 0;

	return 0;
}

/* return value !0: formed an opinnion */
int ZSMTP_hook_rcptto(state, str, len, retp)
     struct policystate *state;
     const char *str;
     const int len;
     int *retp;
{
	STRLEN n_a;

	if (!my_perl) return 0;

	return 0;
}


#endif
