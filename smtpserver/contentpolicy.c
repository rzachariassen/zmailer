/*
 *  contentpolicy.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 1998, 2000, 2002-2003
 *
 *  This is the ugly one, we run SENSOR program on each
 *  accepted message -- if the sensor decrees the program
 *  unacceptable, we return policy-analysis result per
 *  analyzed file to the caller of this program.
 *
 *  The protocol in between the smtpserver, and the content
 *  policy analysis program is a simple one:
 *   0) Caller starts the policy program
 *   1) When the policy program is ready to answer to questions,
 *      it writes "#hungry\n" to its STDOUT.
 *   2) This caller wrapper detects the state, and feeds it
 *      a job-spec:   relfilepath \n
 *   3) The policy-program will then respond with a line
 *      matching format:
 *           %i %i.%i.%i comment text \n
 *   4) the interface collects that, and presents onwards.
 *  Loop restart from phase 1), UNLESS the policy program
 *  has yielded e.g. EOF, in which case the loop terminates.
 *
 *  If no answer is received (merely two consequtive #hungry
 *  states, or non-conformant answers), a "ok" is returned,
 *  and the situation is logged.
 *
 *  
 *
 *
 */

#include "smtpserver.h"

extern int debug;

char *contentfilter; /* set at cfgread.c */

/* Local data */

int contentpolicypid      = -1;

static FILE *cpol_tofp;
static FILE *cpol_fromfp;
static int contentphase;

/* Phases:
   0: started, expecting "#hungry"
   1: seen "#hungry", ready for a job!
   2: sent a task, expecting answer
*/


static int init_content_policy()
{
  int piperd[2], pipewr[2]; /* per parent */

  pipe(piperd);
  pipe(pipewr);

  if (cpol_tofp)   fclose(cpol_tofp);
  if (cpol_fromfp) fclose(cpol_fromfp);

  cpol_tofp = cpol_fromfp = NULL;
  contentphase = 0;

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

static int
pickresponse(buf, bufsize, fp)
     char *buf;
     int bufsize;
     FILE *fp;
{
    int c, i;

    c = i = 0;
    --bufsize;

    if (feof(fp) || ferror(fp)) return -1;
  
    for (;;) {
      if (ferror(fp) || feof(fp)) break;

      c = fgetc(fp);
      if (c == EOF)  break;
      if (c == '\n') break;

      if (i < bufsize)
	buf[i++] = c;
    }
    buf[i] = 0;

    while (c != '\n') {
      if (ferror(fp) || feof(fp)) break;
      c = fgetc(fp);
    }

    return i;
}



int
contentpolicy(rel, state, fname)
struct policytest *rel;
struct policystate *state;
const char *fname;
{
  char responsebuf[8192];
  int i, rc, neg, val;
  int seenhungry = 0;
  
  if (state->always_reject)
    return -1;
  if (state->sender_reject)
    return -2;
  if (state->always_freeze)
    return 1;
  if (state->sender_freeze)
    return 1;
  /* If no 'filter *' defined, use old behaviour */
  if (state->always_accept && (state->content_filter < 0))
    return 0;
  /* 'filter', but not 'filter +' ! */
  if (state->content_filter == 0)
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

  type(NULL,0,NULL, "ContentPolicy program running with pid %d; input='%s'\n",
       contentpolicypid, fname);

 pick_reply:;


  i = pickresponse(responsebuf, sizeof(responsebuf), cpol_fromfp);
  type(NULL,0,NULL, "policyprogram said: rc=%d  '%s'", i, responsebuf);
  if (i <= 0) return 0; /* Urgh.. */

  if (strcmp(responsebuf, "#hungry") == 0) {
    ++seenhungry;
    if (seenhungry == 1 && cpol_tofp) {
      fprintf(cpol_tofp, "%s\n", fname);
      fflush(cpol_tofp);
      goto pick_reply;
    }
    /* Seen SECOND #hungry !!!
       Abort the connection by closing the command socket..
       Collect all replies, and log them.  */

    if (cpol_tofp) fclose(cpol_tofp);
    cpol_tofp = NULL;
    sleep(1);
    if (contentpolicypid > 1) kill(SIGKILL, contentpolicypid);

    for (;;) {
      i = pickresponse(responsebuf, sizeof(responsebuf), cpol_fromfp);
      if (i <= 0) break;
      type(NULL,0,NULL, "policyprogram said: %s", responsebuf);
    }
    /* Finally yield zero.. */
    return 0;
  }

  if (*responsebuf == '#' || *responsebuf == '\n') /* debug stuff ?? */
    /* Debug-stuff... */
    goto pick_reply;



  i = 0;
  val = neg = 0;
  if (responsebuf[i] == '-') {
    ++i;
    neg = 1;
  }
  while ('0' <= responsebuf[i] && responsebuf[i] <= '9') {
    val *= 10;
    val += (responsebuf[i] - '0');
    ++i;
  }
  if (neg) val = -val;

  if (!(i >= neg) || responsebuf[i] != ' ') {

    if (!seenhungry) goto pick_reply;

    return 0; /* Bad result -> tool borken.. */
  }

  rc = val;

  /* on non-void return, do set  state->message  on free()able storage ! */

  /* Pick at first the heading numeric value. */

  /* Scan until first space - or EOL */
  for (; i < sizeof(responsebuf) && responsebuf[i] != 0; ++i) {
    if (responsebuf[i] == ' ') break;
  }
  /* Scan over spaces */
  while (i < sizeof(responsebuf) && responsebuf[i] == ' ') ++i;


  if (!cpol_tofp) {
    fclose(cpol_fromfp);
    cpol_fromfp = NULL;
    if (contentpolicypid > 1)
      kill(SIGKILL, contentpolicypid);
    contentpolicypid = -1;
  }

  state->message = strdup(responsebuf + i);

  return rc;
}
