/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Token manipulation functions.
 */

#include "hostenv.h"
#include "mailer.h"
#include "../libsh/io.h"
#include <ctype.h>
#include "libz.h"

token822 *
makeToken(s, n)
	const char	*s;
	register u_int	n;
{
	register token822	*t;

	t = (token822 *)tmalloc(sizeof (token822));
	t->t_pname = strnsave(s, n);
	t->t_len = 0;
	t->t_type = Empty;
	t->t_next = 0;
	return t;
}

token822 *
copyToken(t)
	register token822 *t;
{
	register token822 *ct;
	int tlen;
	
	if (stickymem != MEM_TEMP) {
		tlen = TOKENLEN(t);
	} else {
		tlen = t->t_len;
	}

	if (tlen > 50000) {
		/* Eh ?!  Got 50k chars of (header) token ?  Umm...
		   (indeed we have seen such monster; a 205 kB of SINGLE
		   "To:" header with 8700+ addresses on it.) */
		tlen = 50000; /* We use AT MOST 50k from start! */
	}

	ct = (token822 *)tmalloc(sizeof (token822));
	if (stickymem != MEM_TEMP)
	  ct->t_pname = strnsave((const char *)t->t_pname, tlen);
	else
	  ct->t_pname = t->t_pname;
	ct->t_len = tlen;

	ct->t_type = t->t_type;
	ct->t_next = t->t_next;
	return ct;
}

const char *
formatToken(t)
	register token822 *t;
{
	const char *name;
	int len;
	static char buf[256];

	switch (t->t_type) {
	case String:	name = "string"; break;
	case Atom:	name = "atom"; break;
	case Special:	name = "special"; break;
	case DomainLiteral:	name = "domainLiteral"; break;
	case Line:	name = "line"; break;
	case Space:	name = "space"; break;
	case Word:	name = "word"; break;
	case Comment:	name = "comment"; break;
	case Empty:	name = "empty"; break;
	case Error:	name = "error"; break;
	default:	name = "unknown"; break;
	}
	buf[0] = '\'';
	len = TOKENLEN(t);
	if ((len + 4 + strlen(name)) >= sizeof(buf))
	  len = sizeof(buf) - strlen(name) - 4;
	memcpy(buf+1, (char *)(t->t_pname), len);
	sprintf(buf + len + 1, "'(%s)", name);
	return buf;
}

const char *
formatAddr(d)
	AddrComponent d;
{
	switch (d) {
	case aPhrase:	return "aPhrase";
	case aComment:	return "aComment";
	case aSpecial:	return "aSpecial";
	case aGroup:	return "aGroup";
	case anAddress:	return "anAddress";
	case aDomain:	return "aDomain";
	case aWord:	return "aWord";
	case anError:	return "anError";
	case reSync:	return "reSync";
	/*case aSpace:	return "aSpace";*/
	}
	return "unknown";
}

int
printToken(buf, eob, t, tend, quotespecials)
	char *buf, *eob;
	register token822 *t, *tend;
	int quotespecials;
{
	register char *cp;
	register const char *s;
	register int len;

	--eob;		/* make space for terminating NUL */
	for (cp = buf; t != NULL && t != tend && cp < eob; t = t->t_next) {
		if (t->t_type == DomainLiteral)
			*cp++ = '[';
		else if (t->t_type == String)
			*cp++ = '"';
		else if (quotespecials && t->t_type == Special)
			*cp++ = '\\';
		for (s = t->t_pname, len = TOKENLEN(t); len > 0; --len)
			*cp++ = *s++;
		if (t->t_type == DomainLiteral)
			*cp++ = ']';
		else if (t->t_type == String)
			*cp++ = '"';
	}
	*cp = '\0';
	return cp - buf;
}

int
printdToken(bufp, buflenp, t, tend, quotespecials)
	char **bufp;
	register token822 *t, *tend;
	int quotespecials, *buflenp;
{
	register char *cp, *buf = *bufp;
	register const char *s;
	register int len, buflen = *buflenp;

	for (cp = buf; t != NULL && t != tend; t = t->t_next) {
		/* If it won't fit in, extent the space */
		while (((cp - buf) + 3 + TOKENLEN(t)) > buflen) {
		  /* Must extend */
		  buflen <<= 1; /* Multiply by two ! */
		  len = (cp - buf);
		  buf = erealloc(buf,buflen);
		  cp = buf+len;
		}
		if (t->t_type == DomainLiteral)
			*cp++ = '[';
		else if (t->t_type == String)
			*cp++ = '"';
		else if (quotespecials && t->t_type == Special)
			*cp++ = '\\';
		for (s = t->t_pname, len = TOKENLEN(t); len > 0; --len)
			*cp++ = *s++;
		if (t->t_type == DomainLiteral)
			*cp++ = ']';
		else if (t->t_type == String)
			*cp++ = '"';
	}
	*cp = '\0';
	*bufp    = buf;
	*buflenp = buflen;
	return cp - buf;
}

/* return output cursor column if 'fp' is non-null,
 * else return the number of output chars. */

int
fprintToken(fp, t, onlylength)
	FILE *fp;
	token822 *t;
	int onlylength;
{
	int len, col = onlylength;

	len = TOKENLEN(t);
	if (t->t_type == DomainLiteral) {
		if (fp) putc('[', fp);
		else ++onlylength;
		++col;
	} else if (t->t_type == String) {
		if (fp) putc('"', fp);
		else ++onlylength;
		++col;
	} else if (t->t_type == Error) {
		if (fp) putc('?', fp);
		else ++onlylength;
		++col;
	}
	if (fp) {
		const char *s = (const char *)t->t_pname;
		int i;
		fwrite(s, sizeof (char), len, fp);
		for (i = 0; i < len; ++i) {
		  if (s[i] == '\t')
		    col += 8 - (col % 8);
		  else if (s[i] == '\n')
		    col = 0;
		  else
		    ++col;
		}
	} else {
		onlylength += len;
	}
	if (t->t_type == DomainLiteral) {
		if (fp) putc(']', fp);
		else ++onlylength;
		++col;
	} else if (t->t_type == String) {
		if (fp) putc('"', fp);
		else ++onlylength;
		++col;
	} else if (t->t_type == Error) {
		if (fp) putc('?', fp);
		else ++onlylength;
		++col;
	}
	return (fp ? col : onlylength);
}

#define LINELEN	80

/* return output cursor column if 'fp' is non-null,
 * else return the number of output chars. */

int
fprintFold(fp, t, col, foldcol)
	FILE *fp;
	token822 *t;
	int col, foldcol;
{
	int len;
	const char *cp, *ncp;

	len = TOKENLEN(t);
	if (fp) {
	  if (t->t_type == DomainLiteral)
	    putc('[', fp);
	  else if (t->t_type == String)
	    putc('"', fp);
	  else if (t->t_type == Error)
	    putc('?', fp);
	}
	++col;

	cp = t->t_pname;
	do {
		/* find a breakpoint */
		if (col < LINELEN && len > (LINELEN-col)) {
		  /* there is a breakpoint */
		  for (ncp = cp + (LINELEN-col); ncp > cp; --ncp) {
		    if (isascii((*ncp)&0xFF) && (isspace((*ncp)&0xFF)
						 || *ncp == ','))
		      break;
		  }
		  if (ncp == cp) {
		    for (ncp = cp + (LINELEN-col); ncp < cp + len; ++ncp)
		      if (isascii((*ncp)&0xFF) && (isspace((*ncp)&0xFF)
						   || *ncp == ','))
			break;
		  }
		  /* found breakpoint */
		} else
		  ncp = cp + len;
		while (cp < ncp && len > 0) {
		  int c = (*cp) & 0xFF;
		  if (isascii(c) && isspace(c)) {
		    ++col, putc(' ', fp);
		    while (cp < ncp && len > 0) {
		      c = (*cp) & 0xFF;
		      if (!(isascii(c) && isspace(c)))
			break;
		      --len;
		      ++cp;
		    }
		  } else {
		    ++col;
		    putc(*cp, fp);
		    --len;
		    ++cp;
		  }
		}
		if (len > 0) {
		  /* gobble LWSP at beginning of line */
		  while (len > 0 && isascii((*cp)&0xFF) && isspace((*cp)&0xFF))
		    --len, ++cp;
		  putc('\n', fp);
		  for (col = 0; col + 8 <= foldcol; col += 8)
		    putc('\t', fp);
		  for (;col < foldcol; ++col)
		    putc(' ', fp);
		  if (col < 1)
		    putc(' ', fp), ++col;
		}
	} while (len > 0);

	if (fp) {
	  if (t->t_type == DomainLiteral)
	    putc(']', fp);
	  else if (t->t_type == String)
	    putc('"', fp);
	  else if (t->t_type == Error)
	    putc('?', fp);
	}
	++col;
	return col;
}

void
freeTokens(t, memtype)
	token822 *t;
	int memtype;
{
	token822 *nt;

	if (memtype != MEM_MALLOC)
		return;
	while (t != NULL) {
		if (t->t_len > 600000)
			abort(); /* The copyToken() builds at most 50k
				    sized tokens, this is 600k, and thus
				    it MUST be failure! */
		nt = t->t_next;
		free((char *)t->t_pname);
		free((char *)t);
		t = nt;
	}
}
