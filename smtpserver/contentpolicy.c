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
 *  states, or non-conformant answers), an "ok" is returned,
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
int debug_content_filter;

static FILE *cpol_tofp;
static FILE *cpol_fromfp;

static int init_content_policy_prog()
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
    MIBMtaEntry->ss.ContentPolicyForkFailures ++;
    return 0;
  }

  /* Parent */

  cpol_tofp   = fdopen(pipewr[1], "w");
  cpol_fromfp = fdopen(piperd[0], "r");

  close(pipewr[0]);
  close(piperd[1]);

  return 1; /* Successfull start! (?) */
}

static int init_content_policy_sock()
{
  int msgsock;
  struct sockaddr_un server;

  memset((char*)&server,0,sizeof(server));
  server.sun_family = AF_UNIX;
  strncpy(server.sun_path,contentfilter,sizeof(server.sun_path)-1);
  server.sun_path[sizeof(server.sun_path)-1]='\0';
  if ((msgsock=socket(AF_UNIX,SOCK_STREAM,0)) < 0) {
    type(NULL,0,NULL, "contentfilter socket(%s) error %d (%s)",
			contentfilter,errno,strerror(errno));
    return(0);
  }
  if (connect(msgsock,(struct sockaddr *)&server,
      sizeof(server)-sizeof(server.sun_path)+strlen(server.sun_path)+1) < 0) {
    type(NULL,0,NULL, "contentfilter connect(%s) error %d (%s)",
			contentfilter,errno,strerror(errno));
    return 0;
  }
  contentpolicypid = 0;
  cpol_tofp   = fdopen(msgsock, "w");
  cpol_fromfp = fdopen(msgsock, "r");
  return 1;
}

static int init_content_policy()
{
  struct stat stbuf;

  if (stat(contentfilter, &stbuf)) {
    type(NULL,0,NULL, "contentfilter stat(%s) error %d",contentfilter,errno);
    return 0;
  }
  if (S_ISREG(stbuf.st_mode))
    return init_content_policy_prog();
  else
    return init_content_policy_sock();
}


int
contentpolicy(rel, state, fname)
struct policytest *rel;
struct policystate *state;
const char *fname;
{
  int i, rc, neg, val;
  int seenhungry = 0;
  char *s;
  
  if (state->always_reject) {
    if (debug_content_filter)
      type(NULL,0,NULL, "ContentPolicy not run; AlwaysReject");
    return -1;
  }
  if (state->sender_reject) {
    if (debug_content_filter)
      type(NULL,0,NULL, "ContentPolicy not run; SenderReject");
    return -2;
  }
  if (state->always_freeze) {
    if (debug_content_filter)
      type(NULL,0,NULL, "ContentPolicy not run; AlwaysFreeze");
    return 1;
  }
  if (state->sender_freeze) {
    if (debug_content_filter)
      type(NULL,0,NULL, "ContentPolicy not run; SenderFreeze");
    return 2;
  }
  /* If no 'filter *' defined, use old behaviour */
  if (state->always_accept && (state->content_filter < 0)) {
    if (debug_content_filter)
      type(NULL,0,NULL, "ContentPolicy not run; AlwaysAccept w/o FILTER+");
    return 0;
  }
  /* 'filter', but not 'filter +' ! */
  if (state->content_filter == 0) {
    if (debug_content_filter)
      type(NULL,0,NULL, "ContentPolicy not run; AlwaysAccept w FILTER but not '+'");
    return 0;
  }

  if (state->message != NULL)
    free(state->message);
  state->message = NULL;

  if (! contentfilter) {
    if (debug_content_filter)
      type(NULL,0,NULL, "ContentPolicy not run; not configured");
    return 0; /* Until we have implementation */
  }

  /* Ok, we seem to have content-filter program configured... */

  s = contentfilter_proc( & state->ctf_state, fname );
  if (!s) {
    return 0; /* FAILED to do any analysis! */
  }

  i = 0;
  val = neg = 0;
  if (s[i] == '-') {
    ++i;
    neg = 1;
  }
  while ('0' <= s[i] && s[i] <= '9') {
    val *= 10;
    val += (s[i] - '0');
    ++i;
  }
  if (neg) val = -val;

  if (!(i >= neg) || s[i] != ' ') {

    return 0; /* Bad result -> tool borken.. */
  }

  rc = val;

  /* on non-void return, do set  state->message  on free()able storage ! */

  /* Pick at first the heading numeric value. */

  /* Scan until first space - or EOL */
  for (; s[i] != 0; ++i) {
    if (s[i] == ' ') break;
  }

  /* Scan over spaces */
  while (s[i] == ' ') ++i;

  state->message = strdup(s + i);

  return rc;
}

void killcfilter(SS, cpid)
SmtpState *SS;
int cpid;
{
    if (cpid > 0) {
	if (cpol_tofp == NULL)
	    fclose(cpol_tofp);
        cpol_tofp   = NULL;
	if (cpol_fromfp == NULL)
            fclose(cpol_fromfp);
	cpol_fromfp = NULL;
	sleep(1); /* for normal filter shutdown */
	kill(cpid, SIGKILL);
    }
}

