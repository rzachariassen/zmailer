/*
 * Common tricks to check and downgrade headers from MIME 8BIT to
 * MIME QUOTED-PRINTABLE
 */

/*
 * To really understand how headers (and their converted versions)
 * are processed you do need to draw a diagram.
 * Basically:
 *    rp->desc->headers[]    is index to ALL of the headers, and
 *    rp->desc->headerscvt[] is index to ALL of the CONVERTED headers.
 * Elements on these arrays are  "char *strings[]" which are the
 * actual headers.
 * There are multiple-kind headers depending upon how they have been
 * rewritten, and those do tack together for each recipients (rp->)
 * There
 *    rp->newmsgheader    is a pointer to an element on  rp->desc->headers[]
 *    rp->newmsgheadercvt is respectively an elt on  rp->desc->headerscvt[]
 *
 * The routine-collection   mimeheaders.c  creates converted headers,
 * if the receiving system needs them. Converted header data is created
 * only once per  rewrite-rule group, so there should not be messages which
 * report  "Received: ... convert XXXX convert XXXX convert XXXX; ..."
 * for as many times as there there are recipients for the message.
 * [mea@utu.fi] - 25-Jul-94
 */

#include "hostenv.h"
#include <stdio.h>
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>

#include "malloc.h"
#include "libz.h"
#include "ta.h"

extern char *strdup();
#ifndef strchr
extern char *strchr();
#endif
extern void *emalloc();
extern void *erealloc();
extern char *getzenv();

#ifndef	__
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif

static int mime_received_convert __((struct rcpt *rp, char *convertstr));

/* extern FILE *verboselog; */

#define istokenchar(x) (isalnum(x) || x == '-' || x == '_' || x == '$' || \
			x == '#'   || x == '%' || x == '+')

/* strqcpy() -- store the string into buffer with quotes if it
   		is not entirely of alphanums+'-'+'_'.. */

static int strqcpy __((char *buf, int buflen, char *str));

static int
strqcpy(buf,buflen,str)
	char *buf, *str;
	int buflen;
{
	char *s = str;
	char *p = buf;
	int cnt = buflen;
	int needquotes = 0;

	/* Copy while scanning -- redo if need quotes.. */
	while (*s) {
	  char c = *s;
	  if (!((c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		c == '-' || c == '_')) {
	    needquotes = 1;
	    break;
	  }
	  if (cnt) {
	    *p++ = c;
	    --cnt;
	  }
	  ++s;
	}
	if (cnt && !needquotes) {
	  *p = 0;
	  return (buflen - cnt);
	}
	/* Ok, need quotes.. */
	p = buf;
	cnt = buflen -3;
	s = str;
	*p++ = '"';
	while (*s) {
	  if (*s == '"' || *s == '\\')
	    *p++ = '\\', --cnt;
	  if (cnt>0)
	    *p++ = *s, --cnt;
	  ++s;
	}
	if (cnt<0) cnt = 0;

	*p++ = '"';
	*p   = 0;
	return (buflen - cnt);
}


int cvtspace_copy(rp)
struct rcpt *rp;
{
	int hdrcnt = 0;
	char **probe = *(rp->newmsgheader);
	char **newcvt;

	/* Count how many lines */
	while (*probe) {
	  ++probe;
	  ++hdrcnt;
	}

	/* Allocate, and copy ! */

	newcvt = (char **)emalloc(sizeof(char *)*(hdrcnt+1));
	if (newcvt != NULL) {

	  char **ss = newcvt;
	  probe = *(rp->newmsgheader);

	  while (*probe) { /* Copy over */
	    int len = strlen(*probe)+1;
	    *ss = (char *)emalloc(len);
	    /* emalloc() exits at the 'out of memory' condition */
	    memcpy(*ss,*probe,len);
	    ++hdrcnt;
	    ++probe;
	    ++ss;
	  }
	  *ss = NULL;

	  *(rp->newmsgheadercvt) = newcvt;

	} else
	  return 0;	/* Out of memory ? */

	return 1;
}

#ifdef HAVE_STDARG_H
#ifdef __STDC__
int
append_header(struct rcpt *rp, const char *fmt, ...)
#else /* Not ANSI-C */
int
append_header(rp, fmt)
	struct rcpt *rp;
	const char *fmt;
#endif
#else
int
append_header(va_alist)
	va_dcl
#endif
{
	va_list pvar;
	char linebuf[2000]; /* XX: SHOULD be enough..  damn vsprintf()..*/
	int linelen;
	int linecnt;
	char ***hdrpp, **hdrp2;

#ifdef HAVE_STDARG_H
	va_start(pvar,fmt);
#else
	struct rcpt *rp;
	char *fmt;

	va_start(pvar);
	rp  = va_arg(pvar, struct rcpt*);
	fmt = va_arg(pvar, char *);
#endif
	linebuf[0] = 0;

#ifdef HAVE_VSNPRINTF
	vsnprintf(linebuf, sizeof(linebuf)-1, fmt, pvar);
#else
	vsprintf(linebuf, fmt, pvar);
#endif
	va_end(pvar);

	linelen = strlen(linebuf);
	if (linelen > sizeof(linebuf)) {
	  exit(240); /* BUG TIME! */
	}

/*
	if (*(rp->newmsgheadercvt) == NULL)
	  if (cvtspace_copy(rp) == 0)
	    return -1;
*/
	hdrpp   = rp->newmsgheadercvt;
	if (*hdrpp == NULL) /* Not copied ? */
	  hdrpp = rp->newmsgheader;
	linecnt = 0;

	while ((*hdrpp)[linecnt] != NULL) ++linecnt;

	hdrp2 = (char**)erealloc(*hdrpp,sizeof(char **) * (linecnt+3));

	if (!hdrp2) return -1;
	hdrp2[linecnt] = (char*) emalloc(linelen+3);
	memcpy(hdrp2[linecnt],linebuf,linelen+2);
	hdrp2[++linecnt] = NULL;
	*hdrpp = hdrp2;
	return linecnt;
}

void
output_content_type(rp,ct,old)
struct rcpt *rp;
struct ct_data *ct;
char **old;
{
	/* Output the  Content-Type: with  append_header()
	   Sample output:
		Content-Type: text/plain; charset=ISO-8859-1;
			boundary="12fsjdhf-j4.83+712";
			name="ksjd.ksa";
			attr_1="83r8310032 askj39";
			attr_2="ajdsh 8327ead"
	 */

	char buf[200];
	char *lines[40]; /* XX: Hopefully enough.. */
	int  linecnt = 0, i;
	char **newmsgheaders;
	char **h1, **o1, **o2, ***basep;
	int  oldcnt, hdrlines, newlines;
	char *bp;
	char **unk = ct->unknown;

	sprintf(buf,"Content-Type:\t%s",ct->basetype);
	bp = buf + strlen(buf);

	if (ct->subtype) {
	  sprintf(bp,"/%s",ct->subtype);
	  bp = bp + strlen(bp);
	}
	if (ct->charset) {
	  strcat(bp,"; charset=");
	  bp = bp + strlen(bp);
	  strqcpy(bp,sizeof(buf)-1-(bp-buf),ct->charset);
	  bp = bp + strlen(bp);
	  if (ct->boundary != NULL ||
	      ct->name != NULL ||
	      ct->unknown != NULL) {
	    *bp++ = ';';
	    *bp = 0;
	  }
	}
/*if (verboselog) fprintf(verboselog,"CT_out: '%s'\n",buf);*/
	lines[linecnt++] = strdup(buf);
	*buf = 0; bp = buf;
	if (ct->boundary) {
	  strcat(buf,"\tboundary=");
	  bp = bp + strlen(bp);
	  strqcpy(bp,sizeof(buf)-1-(bp-buf),ct->boundary);
	  bp = bp + strlen(bp);
	  if (ct->unknown != NULL) {
	    *bp++ = ';';
	    *bp = 0;
	  }
	}
	if (*buf != 0) {
/*if (verboselog) fprintf(verboselog,"CT_out: '%s'\n",buf);*/
	  lines[linecnt++] = strdup(buf);
	}

	*buf = 0; bp = buf;
	if (ct->name) {
	  strcat(buf,"\tname=");
	  bp = bp + strlen(bp);
	  strqcpy(bp,sizeof(buf)-1-(bp-buf),ct->name);
	  bp = bp + strlen(bp);
	  if (ct->boundary != NULL ||
	      ct->unknown != NULL) {
	    *bp++ = ';';
	    *bp = 0;
	  }
	}
	if (*buf != 0) {
/*if (verboselog) fprintf(verboselog,"CT_out: '%s'\n",buf);*/
	  lines[linecnt++] = strdup(buf);
	}
	*buf = 0; bp = buf;
	while (unk && *unk) {
	  if (*buf) {
	    /* There is something already, and more wants to push in.. */
	    strcat(bp,";");
/*if (verboselog) fprintf(verboselog,"CT_out: '%s'\n",buf);*/
	    lines[linecnt++] = strdup(buf);
	    *buf = 0;
	    bp = buf;
	  }
	  *bp++ = '\t';
	  strcpy(bp,*unk);
	  ++unk;
	}

	if (*buf != 0) {
/*if (verboselog) fprintf(verboselog,"CT_out: '%s'\n",buf);*/
	  lines[linecnt++] = strdup(buf);
	}

	/* The lines are formed, now save them.. */

	basep = (rp->newmsgheader);
	if (*(rp->newmsgheadercvt) != NULL)
	  basep = (rp->newmsgheadercvt);
	hdrlines = 0;
	h1 = *basep;
	for (; *h1; ++h1, ++hdrlines) ;

	oldcnt = 0;
	o1 = NULL;
	if (old != NULL) {
	  o1 = old;
	  o2 = o1+1;
	  while (*o2 != NULL && (**o2 == ' ' || **o2 == '\t'))
	    ++o2, ++oldcnt;
	}
	newlines = hdrlines + linecnt - oldcnt + 1;
	newmsgheaders = (char**)emalloc(sizeof(char*)*newlines);
	o2 = newmsgheaders;
	h1 = *basep;
	while (*h1 && h1 != old) {
	  *o2++ = *h1++;
	}
	if (h1 == old) {
	  /* Found the old entry ?  Skip over it.. */
	  ++h1;
	  while (*h1 && (**h1 == ' ' || **h1 == '\t')) ++h1;
	}
	for (i = 0; i < linecnt; ++i)
	  *o2++ = lines[i];
	while (*h1)
	  *o2++ = *h1++;
	*o2 = NULL;
	/* Whew...  Copied them over.. */
	/* Scrap the old one: */
	free(*basep);
	/* And replace it with the new one */
	*basep = newmsgheaders;
}

struct ct_data *
parse_content_type(ct_linep)
char **ct_linep;	/* Could be multiline! */
{
	char *s, *p, *pv, *ss;
	struct ct_data *ct = (struct ct_data*)emalloc(sizeof(struct ct_data));
	int unknowncount = 0;

	if (!ct) return NULL; /* Failed to parse it! */

	ct->basetype = NULL;
	ct->subtype  = NULL;
	ct->charset  = NULL;
	ct->boundary = NULL;
	ct->name     = NULL;
	ct->unknown  = NULL;

	s = *ct_linep;
	s += 13;	/* "Content-Type:" */

	while (*s == ' ' || *s == '\t') ++s;
	p = s;
	while (*s && *s != ' ' && *s != '/' && *s != '\t' && *s != ';')
	  ++s;
	ct->basetype = emalloc((s - p)+2);
	ss = ct->basetype;
	/* Copy over the basetype */
	while (p < s) *ss++ = *p++;
	*ss = 0;
	while (*s == ' ' || *s == '\t') ++s;
	if (*s == '/') {	/* Subtype defined */
	  ++s;
	  while (*s == ' ' || *s == '\t') ++s;
	  p = s;
	  while (*s && *s != ' ' && *s != '/' && *s != '\t' && *s != ';')
	    ++s;
	  ct->subtype = emalloc((s - p)+2);
	  ss = ct->subtype;
	  /* Copy over the subtype */
	  while (p < s) *ss++ = *p++;
	  *ss = 0;
	}

	while (1) {
	  /* Check for possible parameters on the first and/or continuation
	     line(s) of the header line... */
	  char paramname[40];
	  char *parval, c;

	  if (*s == 0) {
	  /* Check if we have a continuation line */
	    if ((s = ct_linep[1])) {
	      if (*s != ' ' && *s != '\t') /* No continuation */
		return ct;
	      while (*s == ' ' || *s == '\t') ++s;
	      if (*s == 0)
		return ct;	/* No continuation,
				   just a blank line w/ LWSP on it */
	      ++ct_linep;	/* Advance.. */
	    } else
	      return ct;	/* Last of the header lines */
	  }
	  while (*s == ';' || *s == ' ' || *s == '\t') ++s;
	  if (*s == 0) continue; /* last token on this line ? */

	  p = s;
	  c = *s;
	  while (c && (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') ||
		       ('0' <= c && c <= '9') || c == '-' || c == '_'))
	    c = *++s; /* Scan over a parameter name.. */

	  /* Ok, `p' points to a parameter name string */
	  if (s < (p+sizeof(paramname))) {
	    strncpy(paramname,p,s-p);
	    paramname[s-p] = 0;
	  } else {
	    strncpy(paramname,p,sizeof(paramname)-1);
	    paramname[sizeof(paramname)-1] = 0;
	  }
	  /* Picked up a param name, now scan the value */
	  pv = s;
	  if (*s == '=') {	    /* What if no `=' ?? */
	    ++pv;
	    ++s;
	    if (*s == '"') {
	      /* Scan a quoted string, stop at trailing '"' */
	      int quoted = 0; /* Quoted with '\' */
	      ++s;
	      while (*s) {
		if (!quoted && *s == '"') break;
		if (*s == '\\') /* This quote skips over the next char */
		  quoted = 2;
		if (quoted) --quoted;
		++s;
	      }
	      if (*s) ++s; /* Skip the trailing '"' */
	    } else {
	      /* Scan an alphanumeric string -- stop at ';', and LWSP */
	      while (*s && *s != ';' && *s != ' ' && *s != '\t')
		++s;
	    }
	  } else {
	    /* XX: what if no `=' after the parameter name ? */
	    /* ... it never happens, and then somebody screw things
	       up in 9th of June, 1996, and nic.funet.fi experienced
	       smtp crash.. */
	    /* pv is at the start of the stuff as is.. */
	    ++s;
	    if (*s == '"') {
	      /* Scan a quoted string, stop at trailing '"' */
	      int quoted = 0; /* Quoted with '\' */
	      ++s;
	      while (*s) {
		if (!quoted && *s == '"') break;
		if (*s == '\\') /* This quote skips over the next char */
		  quoted = 2;
		if (quoted) --quoted;
		++s;
	      }
	      if (*s) ++s; /* Skip the trailing '"' */
	    } else {
	      /* Scan an alphanumeric string -- stop at ';', and LWSP */
	      while (*s && *s != ';' && *s != ' ' && *s != '\t')
		++s;
	    }
	  }

	  parval = emalloc((s - pv) + 2);
	  ss = parval;
	  if (*pv == '"') { /* Copy the quoted string to parval */
	    int quoted = 0;
	    ++pv;
	    while (*pv && pv < s) {
	      if (!quoted && *pv == '"') break;
	      if (*pv == '\\') quoted = 2;
	      if (quoted)    --quoted;
	      if (!quoted)
		*ss++ = *pv;
	      ++pv;
	    }
	  } else { /* Copy the unquoted string to parval */
	    while (pv < s)
	      *ss++ = *pv++;
	  }
	  *ss = 0; /* Terminate the string */

	  if (cistrcmp("charset",paramname)==0) {
	    /* Parameter:  charset="..." */
	    ct->charset = parval;
	  } else if (cistrcmp("boundary",paramname)==0) {
	    /* Parameter:  boundary="...." */
	    ct->boundary = parval;
	  } else if (cistrcmp("name",paramname)==0) {
	    /* Parameter:  name="...." */
	    ct->name     = parval;
	  } else {
	    /* Unknown parameter.. */
	    int unklen = strlen(parval)+5+strlen(paramname);
	    int unkpos;
	    if (!ct->unknown) {
	      ct->unknown = (char**)emalloc(sizeof(char*)*2);
	      ct->unknown[1] = NULL;
	    } else {
	      ct->unknown = (char**)erealloc(ct->unknown,
					     sizeof(char*)*(unknowncount+2));
	    }
	    ct->unknown[unknowncount] = emalloc(unklen);
	    sprintf(ct->unknown[unknowncount],"%s=",paramname);
	    unkpos = strlen(ct->unknown[unknowncount]);
	    strqcpy(ct->unknown[unknowncount]+unkpos,unklen-unkpos,parval);
	    ct->unknown[++unknowncount] = NULL;
	  }
	}
	/*NOTREACHABLE*/
	abort();
}

struct cte_data *
parse_content_encoding(cte_linep)
char **cte_linep;	/* Propably is not a multiline entry.. */
{
	char *line, *s;
	struct cte_data *cte = emalloc(sizeof(struct cte_data));

	s = (*cte_linep) + 26;
	/* Skip over the 'Content-Transfer-Encoding:' */
	while (*s != 0 && (*s == ' ' || *s == '\t')) ++s;
	line = s;
	if (*s == '"') {
	  char *p;
	  cte->encoder = p = emalloc(strlen(s));
	  while (*s && *s != '"')
	    *p++ = *s++;
	  *p = 0;
	} else {
	  char *p;
	  cte->encoder = p = emalloc(strlen(s));
	  while (*s && *s != ' ' && *s != '\t')
	    *p++ = *s++;
	  *p = 0;
	}
	while (*s == ' ' || *s == '\t') ++s;
	/* XX: if (*s) -- errornoeus data */

	return cte;
}


/*
 *  Check for  "Content-conversion: prohibited" -header, and return
 *  non-zero when found it. ---  eh, "-1", return '7' when QP-coding
 *  is mandated.. (test stuff..)
 */
int
check_conv_prohibit(rp)
struct rcpt *rp;
{
	char **hdrs = *(rp->newmsgheader);
	if (!hdrs) return 0;

	while (*hdrs) {
	  if (cistrncmp(*hdrs,"Content-conversion:", 19)==0) {
	    char *s = *hdrs + 19;
	    while (*s == ' ' || *s == '\t') ++s;
	    if (cistrncmp(s,"prohibited",10)==0) return -1;
	    if (cistrncmp(s,"forced-qp",9)==0) return 7;
	    /* Prohibits (?) the content conversion.. */
	  }
	  ++hdrs;
	}
	return 0;	/* No "Content-Conversion:" header */
}

static const char *cCTE = "Content-Transfer-Encoding:";
static const char *cCT  = "Content-Type:";

int
cte_check(rp)
struct rcpt *rp;
{	/* "Content-Transfer-Encoding: 8BIT" */

	char **hdrs = *(rp->newmsgheader);
	int cte = 0;
	int mime = 0;

	/* if (*(rp->newmsgheadercvt) != NULL)
	   hdrs = *(rp->newmsgheadercvt); */ /* here we check the ORIGINAL headers.. */

	if (!hdrs) return 0;

	while (*hdrs && (!mime || !cte)) {
	  char *buf = *hdrs;
	  if (!cte && cistrncmp(buf,cCTE,26)==0) {
	    buf += 26;
	    while (*buf == ' ' || *buf == '\t') ++buf;
	    if (*buf == '8' /* 8BIT */) cte = 8;
	    else if (*buf == '7' /* 7BIT */) cte = 7;
	    else if (*buf == 'Q' || *buf == 'q') cte = 9; /*QUOTED-PRINTABLE*/
	    else cte = 1; /* Just something.. BASE64 most likely .. */
	  } else if (!mime && cistrncmp(buf,"MIME-Version:",13)==0) {
	    mime = 1;
	  }
	  ++hdrs;
	}
	if (mime && cte == 0) cte = 2;
	if (!mime) cte = 0;
	return cte;
}

char **  /* Return a pointer to header line pointer */
has_header(rp,keystr)
struct rcpt *rp;
const char *keystr;
{
	char **hdrs = *(rp->newmsgheader);
	int keylen = strlen(keystr);

	if (*(rp->newmsgheadercvt) != NULL)
	  hdrs = *(rp->newmsgheadercvt);

	if (hdrs)
	  while (*hdrs) {
	    if (cistrncmp(*hdrs,keystr,keylen)==0) return hdrs;
	    ++hdrs;
	  }
	return NULL;
}

void
delete_header(rp,hdrp)	/* Delete the header, and its possible
			   continuation lines */
struct rcpt *rp;
char **hdrp;
{
	char **h1 = hdrp;
	char **h2 = hdrp+1;
	ctlfree(rp->desc,*hdrp);
	while (*h2 && (**h2 == ' ' || **h2 == '\t')) {
	  ctlfree(rp->desc,*h2);
	  ++h2;
	}
	while (*h2)
	  *h1++ = *h2++;
	/* And one more time.. To copy the terminating NULL ptr. */
	*h1++ = *h2++;
}

int
downgrade_charset(rp, verboselog)
struct rcpt *rp;
FILE *verboselog;
{
	char **CT   = NULL;
	char **CTE  = NULL;
	struct ct_data *ct;

	/* Convert IN PLACE! -- if there is a need.. */
	CT = has_header(rp,cCT);
	CTE  = has_header(rp,cCTE);
	if (CT == NULL || CTE == NULL) return 0; /* ??? */

	ct = parse_content_type(CT);

	if (ct->basetype == NULL ||
	    ct->subtype  == NULL ||
	    cistrcmp(ct->basetype,"text") != 0 ||
	    cistrcmp(ct->subtype,"plain") != 0) return 0; /* Not TEXT/PLAIN! */

	if (ct->charset &&
	    cistrncmp(ct->charset,"ISO-8859",8) != 0 &&
	    cistrncmp(ct->charset,"KOI8",4)     != 0) return 0; /* Not ISO-* */

	if (ct->charset)
	  free(ct->charset);

	strcpy(*CTE, "Content-Transfer-Encoding: 7BIT");

	ct->charset = strdup("US-ASCII");

	/* Delete the old one, and place there the new version.. */
	output_content_type(rp,ct,CT);

	return 1;
}

void
downgrade_headers(rp, convertmode, verboselog)
struct rcpt *rp;
int convertmode;
FILE *verboselog;
{
	char ***oldmsgheader;
	char **CT   = NULL;
	char **CTE  = NULL;
	char **MIME = NULL;
	char **receivedp = NULL;
	struct ct_data *ct;
	int lines = 0;
	int i;
	int newlen;

	if (*(rp->newmsgheadercvt) != NULL)
	  return; /* Already converted ! */

	if (!cvtspace_copy(rp)) return; /* XX: auch! */

	oldmsgheader = rp->newmsgheadercvt;

	if (oldmsgheader)
	  while ((*oldmsgheader)[lines]) ++lines;

	MIME = has_header(rp,"MIME-Version:");
	CT   = has_header(rp,cCT);
	CTE  = has_header(rp,cCTE);

	if (verboselog)
	  fprintf(verboselog,"Header conversion control code: %d\n",convertmode);

	if (convertmode == _CONVERT_UNKNOWN) {
	  /* We downgrade by changing it to Q-P as per RFC 1428/Appendix A */
	  static const char *warning_lines[] = {
"X-Warning: Original message contained 8-bit characters, however during",
"           the SMTP transport session the receiving system was unable to",
"           announce capability of receiving 8-bit SMTP (RFC 1651-1653),",
"           and as this message does not have MIME headers (RFC 2045-2049)",
"           to enable encoding change, we had very little choices.",
"X-Warning: We ASSUME it is less harmful to add the MIME headers, and",
"           convert the text to Quoted-Printable, than not to do so,",
"           and to strip the message to 7-bits.. (RFC 1428 Appendix A)",
"X-Warning: We don't know what character set the user used, thus we had to",
"           write these MIME-headers with our local system default value.",
"MIME-Version: 1.0",
"Content-Transfer-Encoding: QUOTED-PRINTABLE",
NULL };

	  char **newmsgheaders = (char**)emalloc(sizeof(char**)*(lines+15));
	  char *defcharset = getzenv("DEFCHARSET");
	  char *newct;
	  if (!defcharset)
	    defcharset = "ISO-8859-1";
#ifdef HAVE_ALLOCA
	  newct = alloca(strlen(defcharset)+2+sizeof("Content-Type: TEXT/PLAIN; charset="));
#else
	  newct = emalloc(strlen(defcharset)+2+sizeof("Content-Type: TEXT/PLAIN; charset="));
#endif
	  sprintf(newct,"Content-Type: TEXT/PLAIN; charset=%s",defcharset);

	  if (!newmsgheaders) return; /* XX: Auch! */

	  for (lines = 0; warning_lines[lines] != NULL; ++lines)
	    newmsgheaders[lines] = strdup(warning_lines[lines]);
	  newmsgheaders[lines++] = strdup(newct);
#ifndef HAVE_ALLOCA
	  free(newct);
#endif
	  if (CT)	/* XX: This CAN be wrong action for
			       some esoteric SysV mailers.. */
	    delete_header(rp,CT);
	  /* These most propably won't happen, but the delete_header()
	     does scram the pointers anyway.. */
	  if (MIME) {
	    MIME = has_header(rp,"MIME-Version:");
	    delete_header(rp,MIME);
	  }
	  if (CTE) {
	    CTE  = has_header(rp,cCTE);
	    delete_header(rp,CTE);
	  }

	  for (i = 0; (*oldmsgheader)[i] != NULL; ++i)
	    newmsgheaders[lines+i] = (*oldmsgheader)[i];
	  newmsgheaders[lines+i] = NULL;

	  free(*oldmsgheader); /* Free the old one.. */
	  *oldmsgheader = newmsgheaders;
	  return;
	}

	/* Now look for the  Content-Transfer-Encoding:  header */

	receivedp = has_header(rp,"Received:");

	if (CTE == NULL) return; /* No C-T-E: ??? */

	/* strlen("Content-Transfer-Encoding: QUOTED-PRINTABLE") == 43
	   strlen("Content-Transfer-Encoding: 7BIT") == 31		*/

	/* Allocate space for the new value of  C-T-E */
	newlen = 31;
	if (convertmode == _CONVERT_QP) newlen = 43;

	*CTE = (char *)ctlrealloc(rp->desc,*CTE,newlen+2);

	if (convertmode == _CONVERT_QP) {

	  strcpy(*CTE, "Content-Transfer-Encoding: QUOTED-PRINTABLE");
	  mime_received_convert(rp," convert rfc822-to-quoted-printable");
	  return; /* No change on   Charset.. */

	} else
	  strcpy(*CTE, "Content-Transfer-Encoding: 7BIT");

	/* Ok, this was C-T-E: 7BIT, turn charset to US-ASCII if it
	   was  ISO-*  */
	if (CT == NULL && verboselog) {
	  fprintf(verboselog,"Had Content-Transfer-Encoding -header, but no Content-Type header ???  Adding C-T..\n");
	}
	
	if (CT == NULL) { /* ???? Had C-T-E, but no C-T ?? */
	  append_header(rp,"Content-Type: TEXT/PLAIN; charset=US-ASCII");
	  return;
	}

	ct = parse_content_type(CT);

	if (ct->basetype == NULL ||
	    ct->subtype  == NULL ||
	    cistrcmp(ct->basetype,"text") != 0 ||
	    cistrcmp(ct->subtype,"plain") != 0) return; /* Not TEXT/PLAIN! */

	if (ct->charset &&
	    cistrncmp(ct->charset,"ISO-8859",8) != 0 &&
	    cistrncmp(ct->charset,"KOI8",4)     != 0) return; /* Not ISO-* */

	if (ct->charset)
	  free(ct->charset);

	ct->charset = strdup("US-ASCII");

	/* Delete the old one, and place there the new version.. */
	output_content_type(rp,ct,CT);
}


static int /* Return non-zero for success */
mime_received_convert(rp, convertstr)
	struct rcpt *rp;
	char *convertstr;
{
	int convertlen = strlen(convertstr);

	char **inhdr = *(rp->newmsgheadercvt);

	/* We have one advantage: The "Received:" header we want to
	   fiddle with is the first of them at all. */

	while (inhdr && cistrncmp(*inhdr,"Received:",9) == 0) {
	  int receivedlen = strlen(*inhdr);
	  char *newreceived = NULL;
	  char *semicpos;
	  int  semicindex = receivedlen;

	  newreceived = emalloc(receivedlen + convertlen + 1);
	  if (!newreceived) return 0; /* Failed malloc.. */
	  strcpy(newreceived,*inhdr);
	  semicpos = strchr(newreceived,';');
	  if (semicpos != NULL) {
	    semicindex = semicpos - newreceived;
	    strcpy(newreceived+semicindex+convertlen,(*inhdr)+semicindex);
	  } else
	    semicpos = newreceived+semicindex;
	  memcpy(semicpos,convertstr,convertlen);

	  ctlfree(rp->desc,*inhdr);
	  *inhdr = newreceived;

	  /* if (verboselog) {
	     fprintf(verboselog,"Rewriting 'Received:' headers.\n");
	     fprintf(verboselog,"The new line is: '%s'\n",*inhdr);
	     }
	   */

	  inhdr = NULL; /* quit this header munging.. */
	}
	return 1;
}

/* [mea] Now change  C-T-E: QUOTED-PRINTABLE  to  C-T-E: 8BIT -- in place.. */
int /* Return non-zero for success */
qp_to_8bit(rp)
	struct rcpt *rp;
{
	char **inhdr;
	char *hdr, *p;
	char **CTE;

	if (!cvtspace_copy(rp))
	  return 0;	/* Failed to copy ! */

	inhdr = *(rp->newmsgheadercvt);

	CTE = has_header(rp,cCTE);

	if (!CTE) return 0; /* No C-T-E header! */

	hdr = *CTE;

	p = hdr + 26;
	while (*p == ' ' || *p == '\t') ++p;
	if (*p == 'Q' || *p == 'q') {
	  if (strlen(hdr+26) >= 5)
	    strcpy(hdr+26," 8BIT");
	  else { /* No room ??  What junk ?? */
	    delete_header(rp,CTE);
	    append_header(rp,"Content-Transfer-Encoding: 8BIT");
	  }

	  if (!mime_received_convert(rp," convert rfc822-to-8bit"))
	    return 0;	/* "Received:" conversion failed! */

	} /* else propably already decoded */

	return 1;
}


/* Return non-zero for any 8-bit char in the headers */
int
headers_need_mime2(rp)
	struct rcpt *rp;
{
	char **inhdr = *(rp->newmsgheader);
	while (inhdr && *inhdr) {
	  u_char *hdr = (u_char *)*inhdr;
	  for ( ; *hdr != 0 ; ++hdr)
	    if (*hdr != '\t' && (*hdr < ' ' || *hdr > 126))
	      return 1;
	  ++inhdr;
	}
	return 0; /* No 8-bit chars in the headers */
}
