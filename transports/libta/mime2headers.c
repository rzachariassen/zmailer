/*
 *	MIME-part-2 header 8-bit coding to MIME-coded-tokens
 *
 *      Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1996, 2000, 2002
 *	(and   Markku T Jarvinen <mta@sci.fi>)
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ta.h"
#include "sysprotos.h"

/* extern FILE *vlog; */

#ifndef	__
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif


extern void *emalloc();
extern void *erealloc();

/* #define DEFCHARSET "UNKNOWN-8BIT" */

int cvtspace_copy __((struct rcpt *rp));

#if 0
#define USE_NEW_MIME2_CODE /* TESTING! */ /* apparenly not yet ready.. */
#endif
#ifdef USE_NEW_MIME2_CODE

/*
 * The  header8bit2QP() -code is by  Markku T. Jarvinen <mta@sci.fi>
 * who made it for sendmail 8.7 (which lacks MIME-part-2)
 */

const char *Base16Code = "0123456789ABCDEF";

#define MINWORDLEN	   4
#define MAXENCODEDLINE	  75
#define MAXLINE		4096

#ifndef MAX
# define MAX(i1,i2) ((i1 < i2) ? i2 : i1)
#endif


static int
header8bit2QPnextword(line, word, len, inside, start_encode, fold, hdr_offset)
     unsigned char **line;
     unsigned char *word;
     int *len;
     int *inside;
     unsigned char *start_encode;
     int fold;
     int hdr_offset;
{
	int wordlen = 0, has8bit = (*inside), eightbitchars = 0;
	unsigned char c, *tmp;

	eightbitchars = strlen(start_encode)+2;

	while ((!isspace(c = *(*line+wordlen)) && c != '\0' && c != '\n'
	       && !(!fold && (c == '(' || c == ')')))
	      && wordlen+(*len)+has8bit*(eightbitchars) < MAXENCODEDLINE) {
	  if (c > 127)
	    has8bit = 1;
	  if (c > 127 || c == '_' || c == '?' || c == '=' || c < 32)
	    eightbitchars += 2;
	  wordlen++;
	}
	if (wordlen &&
	    wordlen+(*len)+has8bit*(eightbitchars) >= MAXENCODEDLINE) {
	  has8bit = 1;
	  wordlen--;
	  c = *(*line+wordlen);
	  if (c > 127 || c == '_' || c == '?' || c == '=' || c < 32)
	    eightbitchars -= 2;
	  while (wordlen+(*len)+has8bit*(eightbitchars) >= MAXENCODEDLINE) {
	    wordlen--;
	    c = *(*line+wordlen);
	    if (c > 127 || c == '_' || c == '?' || c == '=' || c < 32)
	      eightbitchars -= 2;
	  }
	  if (wordlen < MINWORDLEN) {
	    (*len) = hdr_offset;
	    if (fold)
	      strcpy(word, "\n "); /* next line */
	    else
	      strcpy(word, " "); /* next word */
	    return 1;
	  } 
	  (*inside) = 1;	/* need to split line, so continue inside */
	} else {
	  (*inside) = 0;	/* true word boundary */
	}
	tmp = word;
	if (has8bit) {
	  strcpy(word, start_encode);
	  tmp += strlen(start_encode);
	  (*len) += strlen(start_encode);
	}
	while (wordlen) {
	  if (has8bit &&
	      (**line>127 || **line=='?' || **line=='_' || **line<32)) {
	    *tmp++ = '=';
	    *tmp++ = Base16Code[(**line >> 4) & 0x0f];
	    *tmp++ = Base16Code[**line & 0x0f];
	    (*len) += 3;
	  } else {
	    *tmp++ = **line;
	    (*len)++;
	  }
	  (*line)++;
	  wordlen--;
	}
	if (has8bit) {
	  *tmp++ = '?';
	  *tmp++ = '=';
	  (*len) += 2;
	} 
	if ((*inside)==0) {
	  *tmp++ = (**line);
	  (*len)++;
	  (*line)++;
	}
	*tmp = '\0';
	return 0;
}	

/*
 * go the line word by word and return the result
 * line will be split on whitespace if possible
 */

static int
header8bit2QP(vlog, line, defcharset, outp, sizep, osizep, fold)
     FILE *vlog;
     unsigned char *line;
     const char *defcharset;
     unsigned char **outp;
     int *sizep, *osizep;
     int fold;
{
	unsigned char *ptr, *outptr, *outline;
	unsigned char tmp[MAX(MAXLINE,BUFSIZ)];
	unsigned char word[MAXENCODEDLINE+2];
	int len=0, abslen=0, lines=0, linelen=0, inside=0, hdr_offset=1;
	int fffppp;
  
	linelen = strlen(line);
	ptr = line;
	if (vlog)
	  fprintf(vlog,"header8bit2QP: QP\n");
	sprintf((void*)tmp, "=?%s?Q?", defcharset);
#ifndef TRUSTFORMAT
	while (*ptr != '\0' && *ptr != ':') {
	  ptr++;
	  hdr_offset++;
	}
	if (*ptr == '\0')
	  hdr_offset = 1;
	else
	  hdr_offset++;
	ptr = line;
#endif
	while (*ptr != '\0' && lines == 0) {
	  int wlen;
	  if (header8bit2QPnextword(&ptr, word, &len, &inside, tmp, fold, hdr_offset)) {
	    lines++;
	  }
	  wlen = strlen(word);
	  abslen += wlen;
	  if (abslen >= *sizep) {
	    *outp = erealloc(*outp,abslen+2);
	    *sizep = abslen+2;
	  }
	  memcpy(*outp+*osizep, word, wlen+1);
	  *osizep += wlen;
	}
#if 0
	{
	  int fffppp = open("/tmp/ss", 256+8+1, 0777);
	  write(fffppp, line, strlen(line));
	  write(fffppp, out, strlen(out));
	  close(fffppp);
	}
#endif
	return 1;
}
#endif

/* This is rather half-baked approach, it creates correct tokens,
   but if two tokens wind up adjacent, or one's length exceeds
   recommended maximum, or ... then things aren't perfect. */

int
headers_to_mime2(rp,defcharset,vlog)
	struct rcpt *rp;
	const char *defcharset;
	FILE *vlog;
{
#ifndef USE_NEW_MIME2_CODE
	char **inhdr;
	/* int wasmime2word = 0; */

	if (*(rp->newmsgheadercvt) == NULL)
	  if (!cvtspace_copy(rp))
	    return -1;	/* Failed to copy ! */

	inhdr = *(rp->newmsgheadercvt);

	while (inhdr && *inhdr) {
	  char *hdr = *inhdr;
	  char *s, *p, *q;
	  int len;
	  char *newbuf = NULL;

      qphdr_restart:

	  for (s = (char*)hdr; *s; ++s) {
	    int c = (*s) & 0xFF;
	    if (c != '\n' && c != '\t' && (c < ' ' || c > 126)) {

	      /* Bad stuff, can't exist in the headers! */
if (vlog) fprintf(vlog,"8-bit header: '%s'\n",hdr);

	      /* Now rewind BACK to begin of this token,
		 separators are: '\n', ' ','\t','(' */
	      while (s > (char*)hdr && *s != ' ' && *s != '\n' &&
		     *s != '\t' && *s != '(' && *s != ')')
		--s;
	      if (*s == ' ' || *s == '\t' || *s == ')' || *s == '\n') ++s;
	      /* Now the 's' points at the begin of the token */
	      p = (char*)hdr;
	      if (!newbuf) {
		len = strlen(s)*3; /* If it ALL turns into QP */
		len += (s - hdr) + 30; /* Slag at the length */
		newbuf = (char*)emalloc(len);
	      }
	      /* Copy the head */
	      q = newbuf;
	      while (p < s) *q++ = *p++;
	      sprintf(q,"=?%s?Q?", defcharset);
	      q += strlen(q);

	      for ( ; *s && (*s != ' ' && *s != '\t' && *s != ')' && *s != '\n'); ++s) {
		c = (*s) & 0xFF;
		if (c < ' '  || c > 126  || c == '"' ||
		    c == '=' || c == '?' || c == '_') {
		  sprintf(q, "=%02X", c);
		  q += 3;
		} else
		  *q++ = c;
	      }
	      strcpy(q,"?="); q += 2;
	      strcpy(q,(void*)s);
if(vlog)fprintf(vlog,"After processing: '%s'\n",newbuf);
	      ctlfree(rp->desc,*inhdr);
	      hdr = *inhdr = newbuf;
	      newbuf = NULL;
	      goto qphdr_restart;
	    } else {
	      
	    }
	  }
	  if (newbuf) free(newbuf);

	  ++inhdr;
	}
	return 0;
#else /* USE_NEW_MIME2_CODE */
	/* New MIME-2 code by mta@sci.fi in use.. */

	char **inhdr, **inhdr1;
	char **outhdr, *s, **oh;
	int   outcnt = 0;
	char *sumstr = emalloc(1);
	int   sumlen = 0;

	*sumstr = 0;
	outhdr = NULL;

	if (*(rp->newmsgheadercvt) == NULL)
	  if (!cvtspace_copy(rp))
	    return -1;	/* Failed to copy ! */

	inhdr = *(rp->newmsgheadercvt);
	inhdr1 = inhdr;

	while (inhdr && *inhdr) {
	  int thislen = strlen(*inhdr);
	  
	  if (**inhdr == ' ' || **inhdr == '\t') {
	    char *nn;
	    /* Continuation line.. */
	    nn = erealloc(sumstr,sumlen+thislen+2);
	    if (!nn) return -1; /* AUTCH! */
	    memcpy(nn+sumlen,*inhdr,thislen);
	    strcpy(nn+sumlen+thislen,"\n");
	    sumlen += thislen+1;
	    sumstr = nn;
	  } else {
	    /* Not a continuation line, Some sort of 'first line' */
	    if (sumlen > 0) {
	      char *s, *p;
	      int rc, size = sumlen;
	      char *outstr = emalloc(sumlen);
	      int osize = 0;

	      rc = header8bit2QP(vlog,sumstr,defcharset,&outstr,&size,&osize,1);
	      s = outstr;

	      if (outhdr == NULL)
		outhdr = (char **)emalloc(sizeof(void*) * 2);
	      else
		outhdr = (char**)erealloc(outhdr,
					  sizeof(void*) * (outcnt+2));
	      outhdr[outcnt] = (char*)emalloc(osize+1);
	      memcpy(outhdr[outcnt],s,osize+1);
	      ++outcnt;
	      outhdr[outcnt] = NULL;

	      /* Clean up the results */
	      sumlen = 0;
	      free(outstr);
	    } /* sumlen > 0 */

	    /* Collect the 'first line' */
	    sumstr = erealloc(sumstr,thislen+2);
	    if (!sumstr) return -1; /* AUTCH! */
	    strcpy(sumstr,*inhdr);
	    strcpy(sumstr+thislen,"\n");
	    sumlen = thislen+1;
	  }
	  ++inhdr;
	}

	/* Process the last of the headers */

	if (sumlen > 0) {
	  char *s, *p;
	  int rc, size = sumlen;
	  char *outstr = emalloc(sumlen);
	  int osize = 0;

	  rc = header8bit2QP(vlog,sumstr,defcharset,&outstr,&size,&osize,1);
	  s = outstr;

	  size = strlen(s);
	  if (outhdr == NULL)
	    outhdr = (char **)emalloc(sizeof(void*) * 2);
	  else
	    outhdr = (char**)erealloc(outhdr,
				      sizeof(void*) * (outcnt+2));
	  outhdr[outcnt] = (char*)emalloc(size+1);
	  strcpy(outhdr[outcnt],s);
	  ++outcnt;
	  outhdr[outcnt] = NULL;

	  /* Clean up the results */
	  sumlen = 0;
	  free(outstr);
	} /* sumlen > 0 */
	free(sumstr);


	/* replace the converted headers with  outhdr -set. */
	inhdr = outhdr;
	oh = NULL;
	outcnt = 0;
	while (*inhdr) {
	  char *s = *inhdr;
	  while (s && *s) {
	    char *p = strchr(s,'\n');
	    int len;

	    if (p) *p++ = 0;
	    len = strlen(s);

	    if (outcnt == 0)
	      oh = (char**)emalloc(sizeof(void*) * 2);
	    else
	      oh = (char**)erealloc(oh,sizeof(void*) * (outcnt+2));
	    /* -- copy -- */
	    oh[outcnt] = (char*)emalloc(len+1);
	    memcpy(oh[outcnt],s,len+1);
	    oh[++outcnt] = NULL;
	    /* -- Continuation line ? -- */
	    if (p) s = p;
	    else   s = NULL;
	  }
	  free(*inhdr);
	  ++inhdr;
	}
	free(outhdr);

	inhdr1 = inhdr = *(rp->newmsgheadercvt);
	*(rp->newmsgheadercvt) = oh;
	while (*inhdr)
	  ctlfree(rp->desc,*inhdr++);
	ctlfree(rp->desc,inhdr1);
	return 0;
#endif /* USE_NEW_MIME2_CODE */
}
