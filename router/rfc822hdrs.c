/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * This file implements most of an RFC822/976 scanner/parser.
 */

#include "mailer.h"
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "io.h"
#include "prototypes.h"

#ifndef _IOFBF
#define _IOFBF  0
#endif  /* !_IOFBF */


struct headerinfo nullhdr = { 0, nilHeaderSemantics, nilUserType, normal };
int D_rfc822 = 0; /* Debug traceing */

extern int do_hdr_warning; /* If set, headers with errors in them are
			      printed "as is" -- h_line */

/*
 * Apply RFC822 scanner and parser to the list of Line tokens passed as args.
 *
 * The return value in the appropriate form for the type of header line.
 * This function is the primary interface to the scanner/parser routines here.
 */

union misc
hdr_scanparse(e, h, commentflag, no_line_crossing)
	struct envelope *e;
	struct header *h;
	int commentflag, no_line_crossing;
{
	register token822 *t;
	long		 len;
	const char	*cp, *ocp;
	char		 c1, c2;
	union misc	 retval;
	token822	*tlist, **prev_tp, *scan_t, *nt;
	struct headerinfo *hd;

	/* If we don't recognize the header, we can't parse it */
	if ((hd = h->h_descriptor) == NULL || hd->hdr_name == NULL
	    || hd->semantics == nilHeaderSemantics) {
		retval.t = h->h_lines;
		return retval;
	}
	/*
	 * The list of special characters in RFC822 isn't always enough
	 * to properly interpret certain header fields, for example date
	 * strings in strange formats, or %-@ addresses. Here we determine
	 * which extra characters should be considered specials, so we can
	 * inform the scanner of it.
	 */
	switch (hd->semantics) {
	case DateTime:
		c1 = '/'; c2 = '-'; break;
	case Received:
		/* I wish we didn't have to do it for the whole line */
		/* There's a definite BUG possibility here -- what if one
		 * sees 'from mitre-bedford.arpa', how will it be treated?
		 * The -bedford.arpa part might get lost, thats what!
		 */
		c1 = '/'; c2 = '-'; break;
#ifdef	RFC976
	case Address: case Addresses: case AddressList:
	case RouteAddressInAngles: case RouteAddress:
	case Mailbox: case Mailboxes: case MailboxList: case AMailboxList:
		c1 = '!'; c2 = '%'; break;	/* violates RFC822! */
#endif	/* RFC976 */
	default:
		c1 = '\0'; c2 = '\0'; break;
	}
	tlist = NULL;
	prev_tp = &tlist;
	for (t = h->h_lines; t != NULL; t = t->t_next) {
		if (t->t_type != Line)	/* sanity check */
			continue;
		/*
		 * Scan the entire line at a time, instead of having the
		 * parser call the scanner when a token is needed. This avoids
		 * nontrivial function-call overhead, but does decrease
		 * flexibility slightly.
		 */
		cp = t->t_pname;
		len = TOKENLEN(t);
		while (len > 0) {
			ocp = cp;
			nt = t;
			scan_t = scan822(&cp, len, c1, c2, commentflag, &nt);
			if (nt != t && !no_line_crossing) {
				/* compound token across line */

				while (t != nt)
					t = t->t_next;
				/* len should be 0 */
				len = t->t_pname + TOKENLEN(t) - cp;
			} else
				len -= cp - ocp;
			/* Append the scanner tokens to the list of tokens */
			*prev_tp = scan_t;
			while (scan_t != NULL) {
				/*
				 * Doing it in a loop allows the scanner to
				 * return a token list instead of one token.
				 */
				prev_tp = &(scan_t->t_next);
				scan_t = scan_t->t_next;
			}
		}
	}
	*prev_tp = NULL;

	/* parse it */
	if (hd->semantics == nilHeaderSemantics)
		retval.t = tlist;
	else
		retval = parse822(hd->semantics,
				  &tlist, &(e->e_localtime),
				  D_rfc822 ? stderr : NULL);
	return retval;
}

/*
 *  If s points to a known header field name,
 *  return the description associated with that field.
 */

struct header *
makeHeader(hdb, s, len)
	struct sptree *hdb;
	register const char	*s;
	int	len;
{
	struct headerinfo	*hlp;
	struct header	*h;
	char c;
	const char *p = s;
	int testlen = len;

	h = (struct header *)tmalloc(sizeof (struct header));
	h->h_pname = strnsave(s, len);

	/* Using strlen() may go beyond the original buffer,
	   as is the case with partial reading of the email
	   headers to a limited size buffer.. */
	while (*p != 0 && --testlen >= 0) ++p;

	if (testlen > 0 || *p != 0) {
		c = *(s+len);
		*(char *)(s+len) = '\0';
		hlp = find_header(hdb, s);
		*(char *)(s+len) = c;
	} else
		hlp = find_header(hdb, s);

	if (hlp == NULL)
		hlp = &nullhdr;
	h->h_contents.a = NULL;
	h->h_descriptor = hlp;
	h->h_stamp = newHeader;
	h->h_next = NULL;
	return h;
}

struct headerinfo *
senderDesc()
{
	static struct headerinfo *sd = NULL;

	if (sd != NULL)
		return sd;
	for (sd = &envelope_hdrs[0]; sd->hdr_name != NULL; ++sd)
		if (sd->class == eFrom)
			break;
	return sd;
}

void
set_pname(e, h, s)
	struct envelope *e;
	struct header *h;
	const char *s;
{
	struct headerinfo *sd;
	char buf[BUFSIZ];

	if (e->e_resent) {
		strcpy(buf, "Resent-");
		strncpy(buf+7, s, sizeof(buf)-8);
		buf[sizeof(buf)-1] = 0;
		s = strsave(buf);
	}
	if (!CISTREQ(h->h_descriptor->hdr_name, s)) {
		sd = (struct headerinfo *)tmalloc(sizeof (struct headerinfo));
		*sd = *(h->h_descriptor);
		sd->hdr_name = s;
		h->h_descriptor = sd;
	}
	h->h_pname = s;
}

/*
 * Copy the preferred value for the message sender to a new header struct.
 */

struct header *
copySender(e)
	struct envelope *e;
{
	register struct header	*h;
	register char		**cpp;
	const char		*cp;
	struct header		*best;
	int			minval;
	
	best = NULL;
	minval = 10000;
	for (h = e->e_headers; h != NULL; h = h->h_next) {
		if (h->h_descriptor->user_type != Sender
		    || h->h_stamp == BadHeader
		    || (e->e_resent != 0 && h->h_descriptor->class != Resent))
			continue;
		cp = h->h_descriptor->hdr_name + e->e_resent;
		for (cpp = prio_list; *cpp != NULL; ++cpp) {
			/* printf("comparing '%s' and '%s'\n", *cpp, cp); */
			if (**cpp == *cp && strcmp(*cpp, cp) == 0
			    && (cpp - prio_list) < minval) {
				best = h;
				minval = cpp - prio_list;
			}
		}
	}
	if (best == NULL)
		return NULL;
	h = (struct header *)tmalloc(sizeof (struct header));
	*h = *best;
	h->h_pname = e->e_resent ? "Resent-From" : "From";
	h->h_descriptor = senderDesc();
	h->h_next = NULL;
	h->h_lines = NULL;
	/* should check that we don't have a MailboxList or AddressList here */
	return h;
}

/*
 * Copy recipient headers to fill out the envelope information.
 */

struct header *
copyRecipient(h)
	register struct header	*h;
{
	register struct header	*nh;
	static struct headerinfo	*recipientDesc;

	if (recipientDesc == NULL) {
		for (recipientDesc = &envelope_hdrs[0];
		     recipientDesc->hdr_name != NULL; ++recipientDesc) {
			if (recipientDesc->class == eTo)
				break;
		}
	}
	nh = (struct header *)tmalloc(sizeof (struct header));
	*nh = *h;
	nh->h_pname = "to";
	nh->h_descriptor = recipientDesc;
	/* we know nh->h_next is going to be overwritten immediately */
	return nh;
}

/*
 * Construct a header line containing a message id.
 */

struct header *
mkMessageId(e, unixtime)
	struct envelope *e;
	time_t unixtime;
{
	register struct header *h;
	static struct headerinfo *msgidDesc;
	static int genseq = 0;
	char buf[200];	/* XX: tsk tsk */
	struct tm *ts;
	
	if (msgidDesc == NULL) {
		for (msgidDesc = &mandatory_hdrs[0];
		     msgidDesc->hdr_name != NULL; ++msgidDesc) {
			if (msgidDesc->semantics == MessageID)
				break;
		}
	}
	h = (struct header *)tmalloc(sizeof (struct header));
	h->h_pname = e->e_resent ? "Resent-Message-Id" : "Message-Id";
	h->h_descriptor = msgidDesc;
	h->h_stamp = newHeader;
	h->h_next = 0;
#if 0
	{
	  char *cp, *s, *p, tzbuf[20];
	  cp = rfc822tz(&unixtime, &ts, 1);
	  for (s = cp, p = tzbuf; *s != '\0'; ++s) {
	    if (isascii(*s) && isupper(*s))
	      *p++ = tolower(*s);
	    else if (*s == '(' || *s == ')')
	      continue; /* Skip them.. */
	    else if (isascii(*s) && isspace(*s))
	      *p++ = '_';
	    else
	      *p++ = *s;
	  }
	  *p = '\0';
	  cp = tzbuf;
	  sprintf(buf, "<%02d%s%d.%02d%02d%02d%.20s.%.20s+%d@%.90s>",
		  ts->tm_year % 100, monthname[ts->tm_mon], ts->tm_mday,
		  ts->tm_hour, ts->tm_min, ts->tm_sec,
		  cp, e->e_file, ++genseq, myhostname);
	}
#else /* New way to do this .. more compressed one.. */
	ts = gmtime(&unixtime);
	sprintf(buf, "<%04d%02d%02d%02d%02d%02dZ%.20s+%d@%.90s>",
		ts->tm_year + 1900, ts->tm_mon + 1, ts->tm_mday,
		ts->tm_hour,        ts->tm_min,     ts->tm_sec,
		e->e_file,          ++genseq,       myhostname);
#endif
	h->h_lines = makeToken(buf, strlen(buf));
	h->h_lines->t_type = Line;
	h->h_contents = hdr_scanparse(e, h, 0, 0);
	/* OPTIMIZE: save this in a hashtable somewhere */
	return h;
}

struct header *
mkToHeader(e, buf)
	struct envelope *e;
	const char *buf;
{
	register struct header *h;
	static struct headerinfo *toDesc;
	
	if (toDesc == NULL) {
		for (toDesc = &mandatory_hdrs[0];
		     toDesc->hdr_name != NULL; ++toDesc) {
			if (toDesc->semantics == AddressList)
				break;
		}
	}
	h = (struct header *)tmalloc(sizeof (struct header));
	h->h_pname = e->e_resent ? "Resent-To" : "To";
	h->h_descriptor = toDesc;
	h->h_stamp = newHeader;
	h->h_next = 0;
	h->h_lines = makeToken(buf, strlen(buf));
	h->h_lines->t_type = Line;
	h->h_contents = hdr_scanparse(e, h, 0, 0);
	/* OPTIMIZE: save this in a hashtable somewhere */
	return h;
}

/*
 * Construct an RFC822 date header.
 */

struct header *
mkDate(isresent, unixtime)
	int isresent;
	time_t unixtime;
{
	register struct header	*h;
	char *cp, *s;
	static struct headerinfo *dateDesc;
	
	/* There is really only one kind of dateDesc.. */
	if (dateDesc == NULL) {
		dateDesc = find_header(spt_headers,
				       isresent ? "resent-date" : "date");
		if (dateDesc == NULL)
			return NULL;
	}
	h = (struct header *)tmalloc(sizeof (struct header));
	h->h_pname = isresent ? "Resent-Date" : "Date";
	h->h_descriptor = dateDesc;
	h->h_stamp = newHeader;
	h->h_next = 0;
	h->h_contents.d = unixtime;
	cp = rfc822date(&(h->h_contents.d));
	s = cp + strlen(cp) -1;
	if (*cp != 0 && *s == '\n') *s = 0;
	h->h_lines = makeToken(cp, strlen(cp));
	h->h_lines->t_type = Line;
	/* OPTIMIZE: save this in a hashtable somewhere */
	return h;
}

/*
 * Print an entire header entry onto fp, possibly multiple lines.
 */

int	hdr_width = 78;

void
hdr_print(h, fp)
	struct header *h;
	FILE *fp;
{
	int col, cl, addrlen, newline;
	token822 *t;
	struct address *ap;
	struct addr *pp;
	HeaderSemantics sem;

	if (h == NULL)
		return;

	sem = h->h_descriptor->semantics;

	if (h->h_stamp == BadHeader)
	  sem = nilHeaderSemantics;

	col = 1 + strlen(h->h_pname);

	switch (sem) {
	case Address:
	case Addresses:
	case AddressList:
	case DomainName:
	case Mailbox:
	case Mailboxes:
	case MailboxList:
	case AMailboxList:
	case MessageID:
	case RouteAddressInAngles:
	case RouteAddress:
	case UserAtDomain:
	case DateTime:
		/* Use this ONLY if no original lines are available! */
		if (h->h_contents.d > 0L && h->h_lines == NULL) {
		  if (wanttabs) {
		    fprintf(fp, "%s:%c", h->h_pname, col >= 7 ? ' ' : '\t');
		    col += col >= 7 ? 1 : 8 - col%8;
		  } else {
		    fprintf(fp, "%s: ", h->h_pname);  /* spoilsport! */
		    ++col;
		  }
		  break;
		} else {

		  /* Pre-existing header; print the header name, and
		     whitespace characters of the pre-existing header. */

		  fprintf(fp, "%s:", h->h_pname);
		  for (t = h->h_lines; t != NULL; t = t->t_next) {
		    const char *p = t->t_pname;
		    while (*p == ' ' || *p == '\t' ||
			   *p == '\n' || *p == '\r') {
		      putc(*p, fp);
		      if (*p == ' ' || *p == '\t')
			++col;
		      else
			col = 0;
		      ++p;
		    }
		    if (*p != 0)
		      break;
		  }
		}
		break;
	default:
		fprintf(fp, "%s:", h->h_pname);
		break;
	}
	switch (sem) {
	case Received:
		if (h->h_lines != NULL) {
			/* Write out the original lines if possible */
			for (t = h->h_lines; t != NULL; t = t->t_next) {
				fwrite(t->t_pname, sizeof (char),
				       (int)(TOKENLEN(t)), fp);
				putc('\n', fp);
			}
			break;
		}
		putc(' ',fp);
		++col;
		if ((ap = h->h_contents.r->r_from) != NULL) {
			fprintf(fp, "from ");
			col += 5;
			col += printAddress(fp, ap->a_tokens, 0);
		}
		if ((ap = h->h_contents.r->r_by) != NULL) {
			cl = printAddress(fp, ap->a_tokens, col+6);
			if (cl > 76) {
			  fprintf(fp, "\n\t");
			  col = 8;
			} else
			  putc(' ',fp), ++col;
			fprintf(fp, "by ");
			col += 3;
			col += printAddress(fp, ap->a_tokens, 0);
		}
		if ((t = h->h_contents.r->r_via) != NULL) {
			cl = fprintToken(fp, t, col+4);
			if (cl > 76) {
			  fprintf(fp, "\n\t");
			  col = 8;
			} else
			  putc(' ',fp), ++col;
			fprintf(fp, "via ");
			col += 4;
			col += fprintToken(fp, t, 0);
		}
		for (t = h->h_contents.r->r_with; t != NULL; t = t->t_next) {
			cl = fprintToken(fp, t, col+4);
			if (cl > 76) {
			  fprintf(fp, "\n\t");
			  col = 8;
			} else
			  putc(' ',fp), ++col;
			fprintf(fp, "with ");
			col += 5;
			col += fprintToken(fp, t, 0);
		}
		if ((ap = h->h_contents.r->r_id) != NULL) {
			cl = printAddress(fp, ap->a_tokens, col+6);
			if (cl > 76) {
			  fprintf(fp, "\n\t");
			  col = 8;
			} else
			  putc(' ',fp), ++col;
			fprintf(fp, "id <");
			col += 5;
			col += printAddress(fp, ap->a_tokens, 0);
			putc('>', fp);
		}
		if ((ap = h->h_contents.r->r_for) != NULL) {
			cl = printAddress(fp, ap->a_tokens, col+5);
			if (cl > 76) {
			  fprintf(fp, "\n\t");
			  col = 8;
			} else
			  putc(' ',fp), ++col;
			fprintf(fp, "for ");
			col += 4;
			col += printAddress(fp, ap->a_tokens, 0);
		}
		putc(';', fp);
		++col;
		if ((col + 32) > 78) {
		  fprintf(fp, "\n\t");
		  col = 8;
		} else
		  putc(' ', fp);
		{
		  char *cp, *s;
		  cp = rfc822date(&(h->h_contents.r->r_time));
		  s = cp + strlen(cp) -1;
		  if (*cp != 0 && *s == '\n') *s = 0;
		  fputs(cp, fp);
		  putc('\n', fp);
		}
		break;
	case nilHeaderSemantics:
		for (t = h->h_lines; t != NULL; t = t->t_next) {
			fwrite(t->t_pname, sizeof (char),
			       (int)TOKENLEN(t), fp);
			putc('\n', fp);
		}
		break;
	case Address:
	case Addresses:
	case AddressList:
	case DomainName:
	case Mailbox:
	case Mailboxes:
	case MailboxList:
	case AMailboxList:
	case MessageID:
	case RouteAddressInAngles:
	case RouteAddress:
	case UserAtDomain:
		newline = 1;
		for (ap = h->h_contents.a; ap != NULL; ap = ap->a_next) {
			addrlen = printAddress(fp, ap->a_tokens, col);
			for (pp = ap->a_tokens; pp != NULL; pp = pp->p_next)
				if (pp->p_type == anAddress)
					break;
			/* pp == NULL means mail group phrase */
			if (ap->a_next != NULL)
				++addrlen;
			if (newline || addrlen < hdr_width) {
				if (newline)
					newline = 0;
				else
					++col, putc(' ', fp);
				if (addrlen - col + 8 > hdr_width) {
					col = printLAddress(fp,
							    ap->a_tokens, col);
				} else {
				/* we don't bother calculating col exactly */
					col = addrlen;
					printAddress(fp,
							    ap->a_tokens, 0);
				}
			} else if (addrlen - col +8 > hdr_width/* columns */) {
				++col, putc(' ', fp);
				col = printLAddress(fp, ap->a_tokens, col);
			} else {
				putc('\n', fp);
				putc('\t', fp);
				col = 8 + addrlen - col;
				printAddress(fp, ap->a_tokens, 0);
			}
			if (pp != NULL && ap->a_next != NULL)
				++col, putc(',', fp);
		}
		putc('\n', fp);
		break;
	case DateTime:
		/* Use this ONLY if no original lines are available! */
		if (h->h_contents.d > 0L && h->h_lines == NULL) {
			char *cp, *s;
			cp = rfc822date(&(h->h_contents.d));
			s = cp + strlen(cp) -1;
			if (*cp != 0 && *s == '\n') *s = 0;
			fputs(cp, fp);
			putc('\n', fp);
			break;
		} /* else we have the original line ... */
		for (t = h->h_lines; t != NULL; t = t->t_next) {
			const char *cp = t->t_pname;
			/* Skip over the leading white-space */
			while (*cp == ' '||*cp == '\t') ++cp;
			fputs(cp, fp);
			putc('\n', fp);
		}
		break;
	default:
		for (t = h->h_lines; t != NULL; t = t->t_next) {
			fwrite(t->t_pname, sizeof (char),
			       (int)(TOKENLEN(t)), fp);
			putc('\n', fp);
		}
		break;
	}
}

/* is there a header-value ? */

int
hdr_nilp(h)
	register struct header *h;
{
	if (h == NULL)
		return 1;

	if (h->h_stamp != BadHeader) {

	switch (h->h_descriptor->semantics) {
	case DateTime:
		return h->h_contents.d == 0;
	case Received:
		return h->h_contents.r == NULL;
	case Address:
	case Addresses:
	case AddressList:
	case DomainName:
	case Mailbox:
	case Mailboxes:
	case MailboxList:
	case AMailboxList:
	case MessageID:
	case RouteAddressInAngles:
	case RouteAddress:
	case UserAtDomain:
		return h->h_contents.a == NULL;
	default:
		break;
	}

	}

	return h->h_lines == NULL;
}

void
pureAddress(fp, pp)
	FILE *fp;
	register struct addr *pp;
{
	register token822 *t;

	for (; pp != NULL ; pp = pp->p_next) {
		if (pp->p_type != anAddress)
			continue;
		for (t = pp->p_tokens ; t != NULL ; t = t->t_next)
			fprintToken(fp, t, 0);
	}
}

int
pureAddressBuf(buf, len, pp)
	char *buf;
	int len;
	register struct addr *pp;
{
	int tlen;

	for (; pp != NULL ; pp = pp->p_next) {
		if (pp->p_type != anAddress)
			continue;
		tlen = printToken(buf, buf+len, pp->p_tokens, NULL, 0);
		buf += tlen;
		len -= tlen;
	}
	return len;
}

/*
 * Print the address pointed to by pp onto fp. If the onlylength flag
 * is set, no printing is done, but the number of characters that would
 * have been printed is returned instead.
 */

int
printAddress(fp, pp, onlylength)
	FILE *fp;
	register struct addr *pp;
	int onlylength;
{
	int inAddress, len = 0;
	token822 *t;
	struct addr *lastp, *tpp;

	inAddress = 0;
	for (lastp = NULL, tpp = pp; tpp != NULL; tpp = tpp->p_next)
		if (tpp->p_type == anAddress)
			lastp = tpp;
	for (; pp != NULL; pp = pp->p_next) {
		if (pp->p_type == aComment || pp->p_type == anError) {
			if (onlylength) ++onlylength;
			else putc('(', fp);
			++len;
		} else if (pp->p_type == anAddress)
			inAddress = 1;
		for (t = pp->p_tokens; t != NULL; t = t->t_next) {
			switch (pp->p_type) {
			case aPhrase:
			case aComment:
			case aGroup:
			case aWord:
				if (t != pp->p_tokens) {
					if (onlylength) ++onlylength;
					else putc(' ', fp);
					++len;
				}
				/* fall through */
			case anAddress:
			case aDomain:
			case anError:
			case reSync:
				if (onlylength)
				  onlylength = fprintToken(fp, t, onlylength);
				else
				  len += fprintToken(fp, t, 0);
				if (pp->p_type == reSync && t->t_next != NULL
				    && (t->t_next->t_type == t->t_type
					|| *(t->t_next->t_pname) == '<')) {
				  if (onlylength)
				    ++onlylength;
				  else
				    putc(' ', fp);
				  ++len;
				}
				break;
			case aSpecial:
				if (t != pp->p_tokens && *(t->t_pname) == '<'){
				  if (onlylength)
				    ++onlylength;
				  else
				    putc(' ', fp);
				  ++len;
				}
				if (onlylength)
				  ++onlylength;
				else
				  putc((*t->t_pname), fp);
				++len;
				break;
			}
		}
		if (pp->p_type == aComment || pp->p_type == anError) {
			if (onlylength)
			  ++onlylength;
			else
			  putc(')', fp);
			++len;
		} else if (lastp == pp)
			inAddress = 0;
		if (!inAddress && pp->p_next != NULL
		    && !(pp->p_next->p_type == anAddress
			 && pp->p_type == aSpecial
			 && *pp->p_tokens->t_pname == '<')
		    && !(pp->p_next->p_type == aSpecial
			 && pp->p_type == anAddress
			 && *pp->p_next->p_tokens->t_pname == '>')
		    && !(pp->p_next->p_type == aSpecial
			 && *pp->p_next->p_tokens->t_pname == ':')
		    && pp->p_next->p_type != anError) {
			if (onlylength) ++onlylength;
			else putc(' ', fp);
			++len;
		}
	}
	return (onlylength ? onlylength : len);
}

int
printLAddress(fp, pp, col)
	FILE *fp;
	register struct addr *pp;
	int col;
{
	int inAddress;
	token822 *t;
	struct addr *lastp, *tpp;

	inAddress = 0;
	for (lastp = NULL, tpp = pp; tpp != NULL; tpp = tpp->p_next)
		if (tpp->p_type == anAddress)
			lastp = tpp;
	for (; pp != NULL; pp = pp->p_next) {
		if (pp->p_type == aComment || pp->p_type == anError) {
			++col, putc('(', fp);
		} else if (pp->p_type == anAddress)
			inAddress = 1;
		for (t = pp->p_tokens; t != NULL; t = t->t_next) {
			switch (pp->p_type) {
			case aPhrase:
			case aComment:
			case aGroup:
			case aWord:
				if (t != pp->p_tokens) {
					++col, putc(' ', fp);
				}
				/* fall through */
			case anAddress:
			case aDomain:
			case anError:
			case reSync:
				if (pp->p_type == aComment) {
					col = fprintFold(fp, t, col);
				} else {
					col = fprintToken(fp, t, col);
					fprintToken(fp, t, 0);
				}
				if (pp->p_type == reSync && t->t_next != NULL
				    && (t->t_next->t_type == t->t_type
					|| *(t->t_next->t_pname) == '<')) {
					++col, putc(' ', fp);
				}
				break;
			case aSpecial:
				if (t != pp->p_tokens && *(t->t_pname) == '<')
					++col, putc(' ', fp);
				++col, putc((*t->t_pname), fp);
				break;
			}
			if (t->t_next != NULL
			    && TOKENLEN(t->t_next) > 1
			    && ((col + fprintToken(fp, t->t_next, 1)-1)
				>= hdr_width)) {
				     putc('\n', fp);
				     putc('\t', fp);
				     col = 8;
			}
		}
		if (pp->p_type == aComment || pp->p_type == anError) {
			++col, putc(')', fp);
		} else if (lastp == pp)
			inAddress = 0;
		if (!inAddress && pp->p_next != NULL
		    && !(pp->p_next->p_type == anAddress
			 && pp->p_type == aSpecial
			 && *pp->p_tokens->t_pname == '<')
		    && !(pp->p_next->p_type == aSpecial
			 && pp->p_type == anAddress
			 && *pp->p_next->p_tokens->t_pname == '>')
		    && !(pp->p_next->p_type == aSpecial
			 && *pp->p_next->p_tokens->t_pname == ':')
		    && pp->p_next->p_type != anError) {
			++col, putc(' ', fp);
		}
	}
	return col;
}

/*
 * More or less the same as printAddress (they must be kept in sync!!),
 * but returns a string instead of printing it somewhere. The two routines
 * should really be merged, when one can do stdio to a string.
 */

char *
saveAddress(pp)
	register struct addr *pp;
{
	int len, totallen, inAddress;
	char *cp, *buf;
	token822 *t;
	struct addr *lastp, *tpp;

	totallen = printAddress((FILE *)NULL, pp, 1);
	cp = buf = tmalloc((u_int)(totallen+1));
	inAddress = 0;
	for (lastp = NULL, tpp = pp; tpp != NULL; tpp = tpp->p_next)
		if (tpp->p_type == anAddress)
			lastp = tpp;
	for (; pp != NULL; pp = pp->p_next) {
		if (pp->p_type == aComment || pp->p_type == anError)
			*cp++ = '(';
		else if (pp->p_type == anAddress)
			inAddress = 1;
		for (t = pp->p_tokens; t != NULL; t = t->t_next) {
			len = TOKENLEN(t);
			switch (pp->p_type) {
			case aPhrase:
			case aComment:
			case aGroup:
			case aWord:
				if (t != pp->p_tokens)
					*cp++ = ' ';
				/* fall through */
			case anAddress:
			case aDomain:
			case anError:
			case reSync:
				if (t->t_type == DomainLiteral)
					*cp++ = '[';
				else if (t->t_type == String)
					*cp++ = '"';
				memcpy(cp, t->t_pname, len);
				cp += len;
				if (t->t_type == DomainLiteral)
					*cp++ = ']';
				else if (t->t_type == String)
					*cp++ = '"';
				if (pp->p_type == reSync && t->t_next != NULL
				    && (t->t_next->t_type == t->t_type
					|| *(t->t_next->t_pname) == '<'))
					*cp++ = ' ';
				break;
			case aSpecial:
				if (t != pp->p_tokens && *(t->t_pname) == '<')
					*cp++ = ' ';
				*cp++ = *t->t_pname;
				break;
			}
		}
		if (pp->p_type == aComment || pp->p_type == anError)
			*cp++ = ')';
		else if (lastp == pp)
			inAddress = 0;
		if (!inAddress && pp->p_next != NULL
		    && !(pp->p_next->p_type == anAddress
			 && pp->p_type == aSpecial
			 && *pp->p_tokens->t_pname == '<')
		    && !(pp->p_next->p_type == aSpecial
			 && pp->p_type == anAddress
			 && *pp->p_next->p_tokens->t_pname == '>')
		    && !(pp->p_next->p_type == aSpecial
			 && *pp->p_next->p_tokens->t_pname == ':')
		    && pp->p_next->p_type != anError)
			*cp++ = ' ';
	}
	*cp = '\0';
	return buf;
}

/*
 * This function does the real work of hdr_errprint().  It is here
 * because it needs to be kept in sync with the functions above.
 */

struct errmsgpos { int pos; token822 *tokens; };

void
errprint(fp, pp, hdrlen)
	FILE *fp;
	register struct addr *pp;
	int hdrlen;
{
	int inAddress, n, i, j, len;
	token822 *t;
	struct addr *lastp, *tpp;

	static struct errmsgpos * errmsg = NULL;
	static int errmsgposspace = 0;

	inAddress = 0;
	for (lastp = NULL, tpp = pp; tpp != NULL; tpp = tpp->p_next)
		if (tpp->p_type == anAddress)
			lastp = tpp;
	putc('\t', fp);
	len = 1;
	n = 0;
	for (; pp != NULL; pp = pp->p_next) {
		if (pp->p_type == aComment)
			putc('(', fp), ++len;
		else if (pp->p_type == anAddress)
			inAddress = 1;
		else if (pp->p_type == anError) {
			if (n >= errmsgposspace) {
			  /* Must expand the space */
			  if (errmsgposspace == 0) {
			    errmsgposspace = 100;
			    errmsg = (void*) emalloc(sizeof(*errmsg) *
							errmsgposspace);
			  } else {
			    errmsgposspace <<= 1;
			    errmsg = (void*) erealloc(errmsg,
						      sizeof(*errmsg) *
						      errmsgposspace);
			  }
			}
			errmsg[n].pos = len - 1;
			errmsg[n++].tokens = pp->p_tokens;
			continue;
		}
		for (t = pp->p_tokens; t != NULL; t = t->t_next) {
			switch (pp->p_type) {
			case aPhrase:
			case aComment:
			case aGroup:
			case aWord:
				if (t != pp->p_tokens)
					putc(' ', fp), ++len;
				/* fall through */
			case anAddress:
			case aDomain:
			case reSync:
				len = fprintToken(fp, t, len);
				fprintToken(fp, t, 0);
				if (pp->p_type == reSync && t->t_next != NULL
				    && (t->t_next->t_type == t->t_type
					|| *(t->t_next->t_pname) == '<'))
					putc(' ', fp), ++len;
				break;
			case aSpecial:
				if (t != pp->p_tokens && *(t->t_pname) == '<')
					putc(' ', fp), ++len;
				putc((*t->t_pname), fp), ++len;
				break;
			case anError:
				break;
			}
		}
		if (pp->p_type == aComment) {
			putc(')', fp), ++len;
		} else if (lastp == pp)
			inAddress = 0;
		if (!inAddress && pp->p_next != NULL
			       && pp->p_next->p_type != anError
		    && !(pp->p_next->p_type == anAddress
			 && pp->p_type == aSpecial
			 && *pp->p_tokens->t_pname == '<')
		    && !(pp->p_next->p_type == aSpecial
			 && pp->p_type == anAddress
			 && *pp->p_next->p_tokens->t_pname == '>')
		    && !(pp->p_next->p_type == aSpecial
			 && *pp->p_next->p_tokens->t_pname == ':')) {
			putc(' ', fp), ++len;
		}
	}
	putc('\n', fp);
	for (i = 0; i < (hdrlen+1)/8 ; ++i)
		putc('\t', fp);
	putc('\t', fp);
	for (i = 0, len = 0; i < n;) {
		for (; (len+1)/8 < errmsg[i].pos/8; len = ((len/8)+1)*8)
			putc('\t', fp);
		for (; len < errmsg[i].pos; ++len)
			putc(' ', fp);
		while (i < n && len == errmsg[i].pos)
			putc('^', fp), ++i;
		++len;
	}
	--n;
	fprintf(fp, "-%s", errmsg[n].tokens->t_pname);
	for (t = errmsg[n].tokens->t_next; t != NULL; t = t->t_next)
		fprintf(fp, ", %s", t->t_pname);
	putc('\n', fp);
	for (j = 0; j < n; ++j) {
		for (i = 0; i < (hdrlen+1)/8 ; ++i)
			putc('\t', fp);
		putc('\t', fp);
		for (i = 0, len = 0; i < n-j;) {
			for (; (len+1)/8 < errmsg[i].pos/8; len = ((len/8)+1)*8)
				putc('\t', fp);
			for (; len < errmsg[i].pos; ++len)
				putc(' ', fp);
			while (i < n-j && len == errmsg[i].pos) {
				if (i == n-j-1) {
					if (j == 0)
						putc(' ', fp), ++i;
					putc('\\', fp), ++i;
				} else
					putc('|', fp), ++i;
			}
			++len;
		}
		fprintf(fp, "-%s", errmsg[n-j-1].tokens->t_pname);
		for (t = errmsg[n-j-1].tokens->t_next; t != NULL; t = t->t_next)
			fprintf(fp, ", %s", t->t_pname);
		putc('\n', fp);
	}
}

HeaderStamp
hdr_type(h)
	struct header *h;
{
	register struct address *ap;

	switch (h->h_descriptor->semantics) {
	case DateTime:
	case Received:
	case nilHeaderSemantics:
		break;
	default:
		for (ap = h->h_contents.a; ap != NULL; ap = ap->a_next)
			if (ap->a_stamp == BadAddress)
				return BadHeader;
	}
	return newHeader;
}

/*
 * Construct a warning header loosely following RFC886.
 *
 * The erroneous header *must* be parsed to address form,
 * i.e. h->h_contents.a is the correct union member.
 */

struct header *
hdr_warning(h)
	struct header *h;
{
	struct address *ap, *pwap, *hwap, **papp;
	struct header *wh;
	int len;
	char *cp;

	if (h->h_stamp != BadHeader)
		return h;
	/*
	 * Splice out the bad addresses, put them in a separate header.
	 */
	pwap = hwap = NULL;
	papp = &h->h_contents.a;
	for (ap = h->h_contents.a; ap != NULL;) {
		if (ap->a_stamp == BadAddress) {	/* splice it out */
			if (pwap != NULL)
				pwap->a_next = ap;
			pwap = ap;
			if (hwap == NULL)
				hwap = ap;
			ap = ap->a_next;
			pwap->a_next = NULL;
		} else {		/* leave it where it is */
			*papp = ap;
			papp = &ap->a_next;
			ap = ap->a_next;
		}
	}
	*papp = NULL;
	if (hwap == NULL)
		return h;
	/*
	 * Now hwap contains list of addresses that need warnings,
	 * and the header itself has got all those bad addresses spliced out.
	 * If the header doesn't have any addresses left, it is replaced
	 * by the new synthesized Mailer-Warning header. Otherwise the
	 * new warning header is linked into the message header right after
	 * this header.
	 */
	wh = (struct header *)tmalloc(sizeof (struct header));
	wh->h_next = h->h_next;
	h->h_next = wh;
	wh->h_pname = "Illegal-Object";
	wh->h_descriptor = &nullhdr;
	wh->h_stamp = newHeader;
	wh->h_contents.a = NULL;
	cp = tmalloc(strlen(h->h_pname) + strlen(myhostname) + 50);
	if (h->h_descriptor->user_type == nilUserType) {
		sprintf(cp,
			       " Syntax error in %s: value%s found on %s:",
			       h->h_pname, hwap->a_next == NULL ? "" : "s",
			       myhostname);
	} else {
		sprintf(cp,
			       " Syntax error in %s: address%s found on %s:",
			       h->h_pname, hwap->a_next == NULL ? "" : "es",
			       myhostname);
	}

	wh->h_lines = makeToken(cp, strlen(cp));

	sb_external(FILENO(stdout));
	printf("\t%s:", h->h_pname);
	errprint(stdout, hwap->a_tokens, strlen(h->h_pname)+8);
	cp = sb_retrieve(FILENO(stdout));
	len = strlen(cp);
	if (*(cp + len - 1) == '\n')
		--len;
	wh->h_lines->t_next = makeToken(cp, len);
	if (h->h_contents.a == NULL)
		return wh;
	return h;
}

/*
 * Print a useful error message to fp, describing the erroneous addresses
 * in the header, using nice diagrams etc. etc.  Non-cryptic output desired.
 */

void
hdr_errprint(e, h, fp, msg)
	struct envelope *e;
	struct header *h;
	FILE *fp;
	const char *msg;
{
	int i;
	struct address *ap;

	if (h->h_stamp != BadHeader)
		return;
	
	for (i = 0, ap = h->h_contents.a; ap != NULL; ap = ap->a_next)
		i += (ap->a_stamp == BadAddress);

	fprintf(fp, "Error%s in \"%s\" %s address%s:\n",
		    i > 1 ? "s" : "", h->h_pname, msg, i > 1 ? "es" : "");
	for (ap = h->h_contents.a; ap != NULL; ap = ap->a_next)
		if (ap->a_stamp == BadAddress && ap->a_tokens != NULL) {
			putc('\n', fp);
			errprint(fp, ap->a_tokens, 0);
		}
	putc('\n', fp);
	if (erraddrlog != NULL) {
		FILE *ealfp;

		if ((ealfp = fopen(erraddrlog, "a")) != NULL) {
			struct siobuf *osiop = siofds[FILENO(ealfp)];
			char vbuf[BUFSIZ];

			setvbuf(ealfp, vbuf, _IOFBF, sizeof vbuf);
			siofds[FILENO(ealfp)] = NULL;
			if (e != NULL)
				fprintf(ealfp, "%s: %s\n",
				       e->e_file, rfc822date(&(e->e_nowtime)));
			fprintf(ealfp, "Error%s in \"%s\" %s address%s:\n",
				    i > 1 ? "s" : "", h->h_pname, msg,
				    i > 1 ? "es" : "");
			for (ap = h->h_contents.a; ap != NULL; ap = ap->a_next)
				if (ap->a_stamp == BadAddress
						&& ap->a_tokens != NULL) {
					putc('\n', ealfp);
					errprint(ealfp, ap->a_tokens, 0);
				}
			putc('\n', ealfp);
			fclose(ealfp);
			siofds[FILENO(ealfp)] = osiop;
		}
	}
}

