/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*  Rmail --  handle remote mail received via UUCP */

#include <stdio.h>
#include "hostenv.h"
#include <ctype.h>
#include "mail.h"

#include "malloc.h"
#include "libc.h"
#include "libz.h"
#include <sysexits.h>

#define	REMOTE_FROM	"remote from "	/* standard magic phrase */

#define	MAXHOPS		500	/* maximum number of >From lines */

const char *somewhere = "uunet"; /* default remote host (for uunet et al) */

/*
 *  This program considers:
 *
 *	From address3  <date3>
 *	>From address2  <date2> remote from host2
 *	>From address1  <date1> remote from host1
 *
 *  as being equivalent to:
 *
 *	From host2!host1!address1
 *	Date: <date3>
 *	Received: by host2 ... ; <date2>
 *	Received: by host1 ... ; <date1>
 *
 *  and does the required conversion before feeding an incoming message
 *  into ZMailer. The "Date:" and "Received: by host1 ..." headers, would
 *  normally be counterproductive, and therefore are left out.
 *
 *  The only limits in this program are available memory and MAXHOPS.
 */

#define PRINTABLE(a,b)	((a != NULL && *a != '\0') ? a : b)

struct from_ {
	const char	*address;
	const char	*date;
	const char	*remotehost;
};


extern char *optarg;
extern int optind;
extern char *getenv();
#ifndef strchr
extern char *strchr();
#endif

int D_alloc = 0;	/* Memory usage debugging */

const char *progname;
extern struct from_ *copyfrom_ __((struct from_ *));
extern struct from_ *breakdown __((char *fromline, int len));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int n, flmax, i, debug, c, errflg;
	char buf[BUFSIZ];
	const char *cp;
	struct from_ *sc, *fl[MAXHOPS];
	FILE *mfp;

	progname = argv[0];
	debug = 0;
	errflg = 0;
	if (getenv("REMOTE") != NULL)
		somewhere = getenv("REMOTE");
	while ((c = getopt(argc, argv, "dh:V")) != EOF) {
		switch (c) {
		case 'd':
			debug = !debug;
			break;
		case 'h':
			somewhere = optarg;
			break;
		case 'V':
			prversion("rmail");
			exit(EX_OK);
			break;
		default:
			++errflg;
			break;
		}
	}
	if (errflg || optind >= argc) {
		fprintf(stderr,"Usage: %s [-d -h default_host] address ...\n",
			       progname);
		exit(EX_USAGE);
	}
	initline(0L);
	flmax = 0;
	while ((n = getline(stdin)) > 0) {
		if (((*linebuf == '>' && (++linebuf, --n)) || 1)
		    && strncmp("From ", linebuf, 5) == 0) {
			if (debug) {
				printf("Found From_ line: '");
				fwrite(linebuf, 1, n-1, stdout);
				printf("'\n");
			}
			if ((sc = breakdown(linebuf, n-1)) == NULL)
				exit(EX_SOFTWARE);	/* message printed below */
			if (flmax >= MAXHOPS) {
				fprintf(stderr,"%s: too many hops\n",progname);
				exit(EX_SOFTWARE);
			}
			fl[flmax++] = copyfrom_(sc);
		} else
			break;
	}

	if (n <= 0) {	/* what's the point? */
		fprintf(stderr, "%s: empty message\n", progname);
		exit(EX_DATAERR);
	}

	if (debug) {
		for (i = 0; i < flmax; ++i) {
			sc = fl[i];
			printf("addr = %s, date = '%s', rhost = %s\n",
			       PRINTABLE(sc->address, "?"),
			       PRINTABLE(sc->date, "?"),
			       PRINTABLE(sc->remotehost, "?"));
		}
	} else
		runastrusteduser();

	mfp = (debug ? stdout : mail_open(MSG_RFC822));
	if (mfp == NULL) {
		fprintf(stderr, "%s: cannot send mail, try later\n", progname);
		exit(EX_TEMPFAIL);
	}

	fprintf(mfp, "external\n");
	while (optind < argc) {
		/* FIRST 'todsn', THEN 'to' -header! */
		char *s;
		fprintf(mfp, "todsn ORCPT=rfc822;");
		s = argv[optind];
		while (*s) {
		  int c = (*s) & 0xFF;
		  if ('!' <= c && c <= '~' && c != '+' && c != '=')
		    putc(c,mfp);
		  else
		    fprintf(mfp,"+%02X",c);
		  ++s;
		}
		fprintf(mfp,"\n");
		fprintf(mfp, "to %s\n", argv[optind++]);
	}

	fprintf(mfp, "with UUCP\n");

	if ((cp = getenv("UU_MACHINE")) != NULL)	/* set by HDB uuxqt */
		fprintf(mfp, "rcvdfrom %s\n", somewhere = cp);
	else if ((cp = getenv("REMOTE")) != NULL)	/* set by A/UX ?? */
		fprintf(mfp, "rcvdfrom %s\n", somewhere = cp);
	else if (fl[0]->remotehost == NULL)
		fprintf(mfp, "rcvdfrom %s\n", somewhere);

	fprintf(mfp, "from ");
	if (flmax < 1) {
		/*
		 * Someone might be trying to fake us out. Not
		 * much we can do, this is a valiant attempt.
		 */
		fprintf(mfp, "uucp\n");
		fprintf(mfp,"env-end\n");
	} else {
		cp = fl[flmax-1]->address;
		if (cp != NULL && strchr(cp, '@') != NULL) {
			for (i = flmax; i < flmax; ++i) {
			  fprintf(mfp, "@%s%s%c",
				  PRINTABLE(fl[i]->remotehost, somewhere),
				  ((i == 0 && fl[i]->remotehost != NULL
				    && strchr(fl[i]->remotehost, '.') == NULL)
				   ? ".uucp" : ""),
				  ((i == flmax-1) ? ':' : ','));
			}
		} else {
			for (i = 0; i < flmax; ++i) {
			  fprintf(mfp, "%s!",
				  PRINTABLE(fl[i]->remotehost, somewhere));
			}
		}

		cp = fl[--i]->address;
		if (cp == NULL) {	/* egad! */
			fprintf(stderr,"%s: malformed From_ line\n", progname);
			if (!debug) mail_abort(mfp);
			exit(EX_DATAERR);
		}
		fprintf(mfp, "%s\n", cp);
		fprintf(mfp,"env-end\n");
		for (i = 0; i < flmax - 1; ++i)
			if (fl[i]->remotehost != NULL && fl[i]->date != NULL)
				fprintf(mfp, "Received: by %s%s ; %s\n",
					fl[i]->remotehost, 
					((strchr(fl[i]->remotehost,'.')
					  == NULL) ? ".uucp" : ""),
					fl[i]->date);
	}

	fwrite((char *)linebuf, 1, n, mfp);

	n = linegetrest();
	if (n > 0)
		fwrite((char *)linebuf, 1, n, mfp);
	while ((n = fread(buf, 1, sizeof buf, stdin)) > 0)
		fwrite(buf, 1, n, mfp);
	if (!debug && mail_close(mfp) == EOF) {
		fprintf(stderr,"%s: error while creating message, try later\n",
			       progname);
		mail_abort(mfp);
		exit(EX_TEMPFAIL);
	}
	return EX_OK;
}

/*
 *  Returns a struct containing pointers to the various fields of a From_ line.
 */

struct from_ *
breakdown(fromline, len)
	char	*fromline;
	int	len;
{
	register char *cp, *overrun;
	char *scp;
	int quoted;
	static struct from_ f;

	if (strncmp(fromline, "From ", sizeof "From " - 1) != 0) {
		fprintf(stderr,"%s: panic: code inconsistency\n", progname);
		return NULL;
	}
	f.address = f.date = f.remotehost = (char *)NULL;

	overrun = fromline + len;
	cp = fromline + (sizeof "From");
	while (isascii(*cp) && cp < overrun && isspace(*cp))
		++cp;
	f.address = cp;

	quoted = 0;
	while (isascii(*cp) && cp < overrun && (quoted || !isspace(*cp))) {
		if (*cp == '\\' && cp < overrun-1)
			++cp;
		else if (*cp == '"')
			quoted = !quoted;
		++cp;
	}
	*cp++ = '\0';

	while (isascii(*cp) && cp < overrun && isspace(*cp))
		++cp;
	if(cp >= overrun)
		return &f;
	f.date = cp;
	while (isascii(*cp) && cp < overrun && *cp != '\n') {
		if ((overrun - cp > sizeof REMOTE_FROM - 1) && *cp == 'r'
		    && strncmp(cp, REMOTE_FROM, sizeof REMOTE_FROM - 1) == 0) {
			scp = cp + sizeof REMOTE_FROM - 1;
			--cp;
			while (isascii(*cp) && cp < overrun && isspace(*cp))
				--cp;
			*++cp = '\0';
			cp = scp;
			while (isascii(*cp) && cp < overrun && isspace(*cp))
				++cp;
			f.remotehost = cp;
			while (isascii(*cp) && cp < overrun && !isspace(*cp))
				++cp;
			*cp = '\0';
			return &f;
		}
		++cp;
	}
	--cp;
	while (isspace(*cp) && cp > f.date)
		--cp;
	*++cp = '\0';
	return &f;
}

struct from_ *
copyfrom_(fp)
	struct from_ *fp;
{
	struct from_ *nfp;

	nfp = (struct from_ *)emalloc(sizeof (struct from_));
	if ((nfp->address = fp->address) != NULL) {
	  char *wcp = emalloc((unsigned int) strlen(fp->address)+1);
	  strcpy(wcp, fp->address);
	  nfp->address = wcp;
	}
	if ((nfp->date = fp->date) != NULL) {
	  char *wcpd = emalloc((unsigned int) strlen(fp->date)+1);
	  strcpy(wcpd, fp->date);
	  nfp->date = wcpd;
	}
	if ((nfp->remotehost = fp->remotehost) != NULL) {
	  char *wcp = emalloc((unsigned int) strlen(fp->remotehost)+1);
	  strcpy(wcp, fp->remotehost);
	  nfp->remotehost = wcp;
	}
	return nfp;
}

#if 0
char *
tmalloc(n)
	unsigned int n;
{
	extern char *emalloc();

	return emalloc(n);
}
#endif
