/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-1997.
 */

/*
 * ZMailer SMTP server.
 */

#include "smtpserver.h"

/* as in: SKIPWHILE(isascii,cp) */
#define SKIPWHILE(X,Y)  while (*Y != '\0' && isascii(*Y) && X(*Y)) { ++Y; }

static void cfparam __((char *));
static void cfparam(str)
char *str;
{
    char *name, *param1, *param2;

    name = strchr(str, '\n');	/* The trailing newline chopper ... */
    if (name)
	*name = 0;

    SKIPWHILE(!isspace, str);
    SKIPWHILE(isspace, str);
    name = str;
    SKIPWHILE(!isspace, str);
    if (*str != 0)
	*str++ = 0;

    if (cistrcmp(name, "help") == 0) {
	int i = 0, helpmax = HELPMAX;
	while (helplines[i] != NULL && i < helpmax)
	    ++i;
	param2 = strchr(str, '\n');
	if (param2)
	    *param2 = 0;
	helplines[i] = strdup(str);
	helplines[i + 1] = NULL;	/* This will always stay within the array... */
	return;
    }

    SKIPWHILE(isspace, str);
    param1 = str;

    SKIPWHILE(!isspace, str);
    if (*str != 0)
	*str++ = 0;
    SKIPWHILE(isspace, str);
    param2 = str;
    SKIPWHILE(!isspace, str);
    if (*str != 0)
	*str++ = 0;

    if (cistrcmp(name, "maxsize") == 0) {
	sscanf(param1, "%ld", &maxsize);
	return;
    }
    if (cistrcmp(name, "max-error-recipients") == 0) {
	sscanf(param1, "%d", &MaxErrorRecipients);
	return;
    }
    if (cistrcmp(name, "same-ip-source-parallel-max") == 0) {
	sscanf(param1, "%d", &MaxSameIpSource);
	return;
    }
    if (cistrcmp(name, "MaxSameIpSource") == 0) {
	sscanf(param1, "%d", &MaxSameIpSource);
	return;
    }
    if (cistrcmp(name, "ListenQueueSize") == 0) {
	sscanf(param1, "%d", &ListenQueueSize);
	return;
    }
    if (cistrcmp(name, "accept-percent-kludge") == 0) {
	percent_accept = 1;
	return;
    }
    if (cistrcmp(name, "reject-percent-kludge") == 0) {
	percent_accept = -1;
	return;
    }
    if (cistrcmp(name, "allowsourceroute") == 0) {
      allow_source_route = 1;
      return;
    }
    /* Following have two parameters:  DBTYPE and DBPATH */
    if (cistrcmp(name, "policydb") == 0) {
	policydefine(&policydb, param1, param2);
	return;
    }
    if (cistrcmp(name, "tcprcvbuffersize") == 0) {
	sscanf(param1, "%d", &TcpRcvBufferSize);
	return;
    }
    if (cistrcmp(name, "tcpxmitbuffersize") == 0) {
	sscanf(param1, "%d", &TcpXmitBufferSize);
	return;
    }
    if (cistrcmp(name, "debugcmd") == 0) {
      debugcmdok = 1;
      return;
    }
    if (cistrcmp(name, "expncmd") == 0) {
      expncmdok = 1;
      return;
    }
    if (cistrcmp(name, "vrfycmd") == 0) {
      vrfycmdok = 1;
      return;
    }
}

struct smtpconf *
 readcffile(name)
const char *name;
{
    FILE *fp;
    struct smtpconf scf, *head, *tail = NULL;
    char c, *cp, buf[1024], *s, *s0;

    if ((fp = fopen(name, "r")) == NULL)
	return NULL;
    head = NULL;
    buf[sizeof(buf) - 1] = 0;
    while (fgets(buf, sizeof buf, fp) != NULL) {
	c = buf[0];
	if (c == '#' || (isascii(c) && isspace(c)))
	    continue;
	if (buf[sizeof(buf) - 1] != 0 &&
	    buf[sizeof(buf) - 1] != '\n') {
	    int cc;
	    while ((cc = getc(fp)) != '\n' &&
		   cc != EOF);	/* Scan until end-of-line */
	}
	buf[sizeof(buf) - 1] = 0;	/* Trunc, just in case.. */

	if (strncmp(buf, "PARAM", 5) == 0) {
	    cfparam(buf);
	    continue;
	}
	scf.flags = "";
	scf.next = NULL;
	cp = buf;
	SKIPWHILE(!isspace, cp);
	c = *cp;
	*cp = '\0';
	s0 = s = strdup(buf);
	for (s = s0; *s; ++s)
	    if (isascii(*s & 0xFF) && isupper(*s & 0xFF))
		*s = tolower(*s & 0xFF);
	scf.pattern = s0;
	scf.maxloadavg = 999;
	if (c != '\0') {
	    ++cp;
	    SKIPWHILE(isspace, cp);
	    if (*cp && isascii(*cp) && isdigit(*cp)) {
		/* Sanity-check -- 2 is VERY LOW */
		if ((scf.maxloadavg = atoi(cp)) < 2)
		    scf.maxloadavg = 2;
		SKIPWHILE(isdigit, cp);
		SKIPWHILE(isspace, cp);
	    }
	    scf.flags = strdup(cp);
	    if ((cp = strchr(scf.flags, '\n')) != NULL)
		*cp = '\0';
	}
	if (head == NULL) {
	    head = tail = (struct smtpconf *) emalloc(sizeof scf);
	    *head = scf;
	} else {
	    tail->next = (struct smtpconf *) emalloc(sizeof scf);
	    *(tail->next) = scf;
	    tail = tail->next;
	}
    }
    fclose(fp);
    return head;
}

struct smtpconf *
 findcf(h)
const char *h;
{
    struct smtpconf *scfp;
    register char *cp, *s;
    int c;

#ifndef	USE_ALLOCA
    cp = emalloc(strlen(h) + 1);
#else
    cp = alloca(strlen(h) + 1);
#endif
    for (s = cp; *h != '\0'; ++h) {
	c = (*h) & 0xFF;
	if (isascii(c) && isalpha(c) && isupper(c))
	    *s++ = tolower(c);
	else
	    *s++ = c;
    }
    *s = '\0';
    for (scfp = cfhead; scfp != NULL; scfp = scfp->next) {
	if (strmatch(scfp->pattern, cp)) {
#ifndef USE_ALLOCA
	    free(cp);
#endif
	    return scfp;
	}
    }
#ifndef USE_ALLOCA
    free(cp);
#endif
    return NULL;
}
