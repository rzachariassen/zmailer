/*
 *  contentpolicy.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 1998, 2000
 *
 *  This is the ugly one, we run SENSOR program on each
 *  accepted message -- if the sensor decrees the program
 *  unacceptable, we return policy-analysis result per
 *  analyzed file to the caller of this program.
 *
 *  The protocol in between the smtpserver, and the content
 *  policy analysis program is a simple one:
 *     to contentpolicy:   relfilepath \n  (relative to current dir)
 *     from contentpolicy: %i [%i ]comment text \n
 */

#include "smtpserver.h"

extern int debug;

char *contentfilter = NULL;

int contentpolicypid      = -1;
FILE *cpol_tofp   = NULL;
FILE *cpol_fromfp = NULL;

static int init_content_policy()
{
  int piperd[2], pipewr[2]; /* per parent */

  pipe(piperd);
  pipe(pipewr);

  if (cpol_tofp)   fclose(cpol_tofp);
  if (cpol_fromfp) fclose(cpol_fromfp);

  cpol_tofp = cpol_fromfp = NULL;

  contentpolicypid = fork();

  if (contentpolicypid == 0) { /* CHILD */
    close(piperd[0]);
    close(pipewr[1]);

    dup2(piperd[1], 1);
    dup2(piperd[1], 2);
    dup2(pipewr[0], 0);

    close(piperd[1]);
    close(pipewr[0]);

    execl(contentfilter, contentfilter, NULL);
    _exit(255); /* EXEC failure! */
  }

  if (contentpolicypid < 0) {
    /* ERROR! :-( */
    return 0;
  }

  /* Parent */

  cpol_tofp   = fdopen(pipewr[1], "w");
  cpol_fromfp = fdopen(piperd[0], "r");

  close(pipewr[0]);
  close(piperd[1]);

  return 1; /* Successfull start! (?) */
}


int
contentpolicy(rel, state, fname)
struct policytest *rel;
struct policystate *state;
const char *fname;
{
  char responsebuf[8192];
  int c, i, rc;
  char *s;

  if (state->always_reject)
    return -1;
  if (state->sender_reject)
    return -2;
  if (state->always_freeze)
    return 1;
  if (state->sender_freeze)
    return 1;
  if (state->always_accept)
    return 0;

  if (state->message != NULL)
    free(state->message);
  state->message = NULL;

  if (! contentfilter)
    return 0; /* Until we have implementation */

  if (contentpolicypid < 0)
    if (!init_content_policy())
      return 0; /* DUH! */

  /* Ok, we seem to have content-filter program configured... */

  fprintf(cpol_tofp, "%s\n", fname);
  fflush(cpol_tofp);

 pick_reply:;

  c = i = 0;
  for (;;) {
    if (ferror(cpol_fromfp) || feof(cpol_fromfp)) break;
    c = fgetc(cpol_fromfp);
    if (c == '\n') break;
    if (i < sizeof(responsebuf)-1)
      responsebuf[i++] = c;
  }
  responsebuf[i] = 0;
  while (c != '\n') {
    if (ferror(cpol_fromfp) || feof(cpol_fromfp)) break;
    c = fgetc(cpol_fromfp);
  }

  type(NULL,0,NULL, "policyprogram said: %s", responsebuf);

  /* on non-zero return, do set  state->message  on free()able storage ! */

  /* Pick at first the heading numeric value. */

  i = sscanf(responsebuf, "%d", &rc);

  if (i == 1) {
    /* Scan until first space - or EOL */
    for (i = 0; i < sizeof(responsebuf) && responsebuf[i] != 0; ++i)
      if (responsebuf[i] == ' ') break;
    /* Scan over spaces */
    while (i < sizeof(responsebuf) && responsebuf[i] == ' ') ++i;
  } else {

    /* Hmm.. Bad!  Lets close the  cpol_tofp  and see what happens..
       Will we ever get working reply ? */

    if (cpol_tofp) {
      fclose(cpol_tofp);
      cpol_tofp = NULL;
      goto pick_reply;
    }

    /* No working reply, ah well, push it into the freezer */

    i = 0;
    rc = -1;
  }

  if (!cpol_tofp) {
    fclose(cpol_fromfp);
    cpol_fromfp = NULL;
    kill(SIGKILL, contentpolicypid);
    contentpolicypid = -1;
  }

  state->message = strdup(responsebuf + i);

  return rc;
}
