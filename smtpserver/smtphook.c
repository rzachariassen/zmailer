/*
 *  smtphook.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 1997-2004
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

int ZSMTP_hook_init(argc, argv, env, filename)
     const int argc;
     const char **argv;
     const char **env;
     const char *filename;
{
	int exitstatus = 0;
	char *embedding[2];
	STRLEN n_a;

	PERL_SYS_INIT3(&argc, &argv, &env);

	my_perl = perl_alloc();
	if (!my_perl) {
	  /* FIXME: FIXME: error processing */
	}
	perl_construct(my_perl);

	embedding[0] = "";
	embedding[1] = filename;

	exitstatus = perl_parse( my_perl, NULL, 2, embedding, NULL);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

}


/* return value 0: accepted! */
int ZSMTP_hook_authuser_mailfrom(state, str, len)
     struct policystate *state;
     const char *str;
     const int len;
{
  return 0;
}


#endif
