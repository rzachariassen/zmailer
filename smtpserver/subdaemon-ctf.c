/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2004.
 */

/*
 * Protocol from client to server is of TEXT LINES that end with '\n'
 * and are without '\r'... (that are meaningless inside the system.)
 *
 * The fd-passing system sends one byte of random junk, and a bunch
 * of ancilliary data (the fd.)
 */


#include "smtpserver.h"

static int subdaemon_handler_ctf_init  __((void**));
static int subdaemon_handler_ctf_input __((void *, struct peerdata *));
static int subdaemon_handler_ctf_preselect  __((void*, fd_set *, fd_set *, int *));
static int subdaemon_handler_ctf_postselect __((void*, fd_set *, fd_set *));

struct subdaemon_handler subdaemon_handler_contentfilter = {
	subdaemon_handler_ctf_init,
	subdaemon_handler_ctf_input,
	subdaemon_handler_ctf_preselect,
	subdaemon_handler_ctf_postselect,
};


/* ============================================================ */

struct ctf_state {
  char responsebuf[8192];
  FILE *cpol_tofp;
  FILE *cpol_fromfp;
  int phase;
  int pid;
};


static int
ctf_pickresponse(buf, bufsize, fp)
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


static int
subdaemon_handler_ctf_init ( statep )
     void **statep;
{
	struct ctf_state *state = *statep;

	if (*statep == NULL) {

	  int piperd[2], pipewr[2]; /* per parent */

	  *statep = state = malloc(sizeof(*state));
	  memset(state, 0, sizeof(*state));


	  pipe(piperd);
	  pipe(pipewr);

	  state->pid = fork();

	  if (state->pid == 0) { /* CHILD */
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

	  if (state->pid < 0) {
	    /* ERROR! :-( */
	    MIBMtaEntry->ss.ContentPolicyForkFailures ++;
	    type(NULL,0,NULL, "ContentPolicy not run; failed to start ?!");
	    return -1;
	  }

	  /* Parent */

	  state->cpol_tofp   = fdopen(pipewr[1], "w");
	  state->cpol_fromfp = fdopen(piperd[0], "r");

	  close(pipewr[0]);
	  close(piperd[1]);
	}
	return 0;
}


static int
subdaemon_handler_ctf_preselect (state, rdset, wrset, topfd)
     void *state;
     fd_set *rdset, *wrset;
     int *topfd;
{
	int i;

	return -1;
}

static int
subdaemon_handler_ctf_postselect (state, rdset, wrset)
     void *state;
     fd_set *rdset, *wrset;
{
	int i;

	return -1;
}


static int
subdaemon_handler_ctf_input (statep, peerdata)
     void *statep;
     struct peerdata *peerdata;
{
	int i, val, neg, rc;
	int seenhungry = 0;
	struct ctf_state *state = statep;


	peerdata->inpbuf[peerdata->inlen -1] = 0;

	if (debug_content_filter)
	  type(NULL,0,NULL, "ContentPolicy program running with pid %d; input='%s'",
	       state->pid, peerdata->inpbuf);

 pick_reply:;

	
	rc = ctf_pickresponse(state->responsebuf, sizeof(state->responsebuf),
			     state->cpol_fromfp);
	if (debug_content_filter)
	  type(NULL,0,NULL, "policyprogram said: rc=%d  '%s'",
	       i, state->responsebuf);

	if (i <= 0) return 0; /* Urgh.. */

	if (strcmp(state->responsebuf, "#hungry") == 0) {
	  ++seenhungry;
	  if (seenhungry == 1 && state->cpol_tofp) {
	    fwrite(peerdata->inpbuf, peerdata->inlen -1, 1, state->cpol_tofp);
	    fputc('\n',state->cpol_tofp);


	    fflush(state->cpol_tofp);
	    goto pick_reply;
	  }
	  /* Seen SECOND #hungry !!!
	     Abort the connection by closing the command socket..
	     Collect all replies, and log them.  */
	  
	  if (state->cpol_tofp) fclose(state->cpol_tofp);
	  state->cpol_tofp = NULL;
	  sleep(1);
	  if (state->pid > 1) kill(SIGKILL, state->pid);
	  
	  for (;;) {
	    i = ctf_pickresponse(state->responsebuf, sizeof(state->responsebuf),
				 state->cpol_fromfp);
	    if (i <= 0) break;
	    if (debug_content_filter)
	      type(NULL,0,NULL, "policyprogram said: %s", state->responsebuf);
	  }
	  /* Finally yield zero.. */
	  return 0;
	}
	
	if (state->responsebuf[0] == '#' ||
	    state->responsebuf[0] == '\n') /* debug stuff ?? */
	  /* Debug-stuff... */
	  goto pick_reply;



	i = 0;
	val = neg = 0;
	if (state->responsebuf[i] == '-') {
	  ++i;
	  neg = 1;
	}
	while ('0' <= state->responsebuf[i] && state->responsebuf[i] <= '9') {
	  val *= 10;
	  val += (state->responsebuf[i] - '0');
	  ++i;
	}
	if (neg) val = -val;
	
	if (!(i >= neg) || state->responsebuf[i] != ' ') {
	  
	  if (!seenhungry) goto pick_reply;
	  
	  return -1; /* Bad result -> tool borken.. */
	}
	
	/* on non-void return, do set  state->message 
	   on free()able storage ! */

	
	if (!state->cpol_tofp) {
	  fclose(state->cpol_fromfp);
	  state->cpol_fromfp = NULL;
	  if (state->pid > 1)
	    kill(SIGKILL, state->pid);
	  state->pid = -1;
	}

	peerdata->outlen = rc + 1;
	memcpy( peerdata->outbuf, state->responsebuf, rc );
	peerdata->outbuf[rc] = '\n';
	
	return 0; /* all fine */
}
