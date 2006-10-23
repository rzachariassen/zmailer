/*
 *  THIS CODE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  User authentication through an external program. The program (or script)
 *  should read a username from command line and a password from standard
 *  input. Exit status 0 means successful authentication.  The message
 *  directed to standard output or standard error is logged via syslogd
 *  (facility=auth, priority=info).  The authentication mechanism can be
 *  dangerous when used without care!
 *
 *  <Artur.Urbanowicz@man.lublin.pl>, 1999
 */

#define _GNU_SOURCE /* Very short hand define to please compilation
                       at glibc 2.1.* -- _XOPEN_SOURCE_EXTENDED + BSD + ... */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "smtpserver.h"

#define NOTOK   (-1)
#define OK      0
#define NBITS   ((sizeof (int)) * 8)

int pipeauthchild_pid = -1;
int pipeauthchild_status = 0;


static int run __(( FILE **rfp, FILE **wfp,
		    const char *path, char *const argv[], char *const envp[]));

static int run(rfp, wfp, path, argv, envp)
     FILE **rfp, **wfp;
     const char *path;
     char *const argv[];
     char *const envp[];
{
    int pdi[2], pdo[2], i, pid;

    fflush( stdout );
    fflush( stderr );

    if( pipe( pdi ) == NOTOK ) return NOTOK;
    if( pipe( pdo ) == NOTOK ) {
        (void)close( pdi[0] );
        (void)close( pdi[1] );
        return NOTOK;
    }

    pid = fork();
    switch (pid) {
    case -1: /* Various failures */
        MIBMtaEntry->ss.ForkFailures ++;
        close( pdo[0] );
        close( pdo[1] );
        close( pdi[0] );
        close( pdi[1] );
        *rfp = *wfp = NULL;
        break;

    case 0: /* Child */
	/* Builtin presumption of: stdin==0, stdout==1, stderr==2 ... */
        if( pdo[0] != fileno(stdin)  ) (void) dup2( pdo[0], fileno(stdin)  );
        if( pdi[1] != fileno(stdout) ) (void) dup2( pdi[1], fileno(stdout) );
        if( pdi[1] != fileno(stderr) ) (void) dup2( pdi[1], fileno(stderr) );
        for( i=fileno(stderr)+1; i<NBITS; i++ ) (void)close( i );
        execve( path, argv, envp );
        _exit( NOTOK );
        break;

    default: /* Parent */

        pipeauthchild_pid = pid;

        close( pdi[1] );
        close( pdo[0] );
        if( ( *rfp = fdopen( pdi[0],"r" ) ) == NULL ||
            ( *wfp = fdopen( pdo[1],"w" ) ) == NULL    ) {
            close( pdi[0] );
            close( pdo[1] );
            return NOTOK;
        }
    }
    return pid;
}


static int pipeauth __((char *, char *, size_t, char *, char *));
static int
pipeauth(cmd, msg, msgsize, uname, password)
     char *cmd;
     char *msg;
     size_t msgsize;
     char *uname;
     char *password;
{
    FILE *rfp, *wfp;
    int pid;
    char *argv[4]; int argc = 0;
    char *envp[9]; int envc = 0;
    char buf[2048]; char *cp;
    const char *s;
    int status = -1;

    cp = buf;
    *cp = 0;
    sprintf( cp, "%.200s", cmd );
    argv[argc++] = cp;
    cp += strlen(cp) + 1;
    argv[argc++] = uname;
    argv[argc++] = NULL;

    envp[envc++] = "SHELL=/bin/sh";
    envp[envc++] = "IFS= \t\n";
    envp[envc] = getenv("TZ");
    if (envp[envc] != NULL) /* Pass on the TZ environment .. */
      ++envc;

    s = getzenv("PATH");
    if (!s) {
        envp[envc++] = "PATH=/usr/bin:/bin:/usr/ucb";
    } else {
        sprintf( cp, "PATH=%.999s", s );
        envp[envc++] = cp;
        cp += strlen(cp) + 1;
    }

    s = getzenv("ZCONFIG");
    if (!s) s = ZMAILER_ENV_FILE;

    cp += strlen(cp) + 1;
    sprintf( cp, "ZCONFIG=%.200s", s );
    envp[envc++] = cp;
    envp[envc] = NULL;
    
    wfp = rfp = NULL;
    pid = run( &rfp, &wfp, argv[0], argv, envp );
    if (pid > 1) {
        fprintf( wfp, "%s\n", password );
	fflush(wfp);
        fclose( wfp );
	wfp = NULL; /* Mark the pointer null too, so we won't
		       double-close this futher below.
		       "Darryl L. Miles" <darryl@netbauds.net> */
	/* Following weird thing is because we have top-level
	   child-death reaper code at the main part of this
	   program... */
	do {
	    int rc = wait( &status );
	    if (rc < 0 && errno == EINTR) continue;
	    if (rc < 0) break;
	    if (rc != pid) continue; /* Eh... should not.. */
	    pipeauthchild_status = status;
	    break;
	} while(1);

        if ( msg ) {
            msg[ msgsize-1 ] = 0;
            fgets( msg, msgsize, rfp );
        }
    }
    if (wfp) fclose(wfp);
    if (rfp) fclose(rfp);

    return pipeauthchild_status;
}


char *pipezpwmatch __((char *cmd, char *uname, char *password, long *uidp));
char *pipezpwmatch( cmd, uname, password, uidp )
     char *cmd, *uname, *password;
     long *uidp;
{
  char msg[256] = "";
  int status;

  status = pipeauth( cmd, msg, sizeof(msg), uname, password );
  if (status)
    *uidp = -1;
#ifdef LOG_AUTHPRIV
  syslog( LOG_AUTHPRIV|LOG_INFO, "%s: %s", uname, msg );
#else
  syslog( LOG_AUTH|LOG_INFO, "%s: %s", uname, msg );
#endif
  return status ? "Authentication failed" : NULL;
}
