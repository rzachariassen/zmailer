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

int debug_content_filter;

int
contentpolicy(rel, state, fname)
struct policytest *rel;
struct policystate *state;
const char *fname;
{
	int i, rc, neg, val;
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
	    type(NULL,0,NULL,"ContentPolicy not run; AlwaysAccept w/o FILTER+");
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

void killcfilter(SS)
SmtpState *SS;
{
	struct policystate *ps = & SS->policystate;

	smtpcontentfilter_kill( ps->ctf_state );
}

