/*
 *  listexpand -- expand mailinglist from a file to have an envelope
 *		  containing all the addresses listed individually.
 *
 *  listexpand owner@address /path/to/file/containing/addresses [privuid]
 *
 *  This EXPECTS things from the listfile:
 *	recipient@address <TAB> (other data in comments) <NEWLINE>
 *
 *  By  Matti Aarnio <mea@nic.funet.fi>  1995,1998,2000
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include "sysexits.h"
#include "mailer.h"
#include "mail.h"
#include "ta.h"
#include "libz.h"

int bundlesize = 6000;

char *progname = "listexpand";
int D_alloc = 0;
#ifndef strchr
extern char *strchr();
#endif

extern  char * rfc821_path2 __((char *s, int strict));

/* this macro is from  compat/sendmail/sendmail.c */

#define RFC821_822QUOTE(newcp,cp) \
	if (cp && strchr(cp,'\\') != NULL && *cp != '"') {	\
	  const char *s1 = cp;					\
	  char *s2;						\
	  /* For this we can add at most 2 new quote chars */	\
	  s2 = emalloc(strlen(cp)+4);				\
	  newcp = s2;						\
	  *s2++ = '"';						\
	  while (*s1) {						\
	    if (*s1 == '@')					\
	      break; /* Unquoted AT --> move to plain copying! */ \
	    if (*s1 == '\\' && s1[1] != 0)			\
	      *s2++ = *s1++;					\
	    /* Normal copy */					\
	    *s2++ = *s1++;					\
	  }							\
	  *s2++ = '"';						\
	  while (*s1)						\
	    *s2++ = *s1++;					\
	  cp = newcp;						\
	}


void usage()
{
  fprintf(stderr,"%s: ['-debug'] ['+ezmlm'] [-{bundlesize}]  owner@address /path/to/file/containing/addresses [privuid]\n",
	  progname);
  exit(EX_USAGE);
}

struct rcpts {
  char *address;   /* The entire address */
  char *revdomain; /* Domain part, components reversed */
};

char * reverse_domain(origdomain)
char * origdomain;
{
  int len = strlen(origdomain);
  char *buf = malloc(len+1);
  char *s;

  *buf = 0;
  if (*origdomain == 0) return buf;

  while (*origdomain) {
    s = strrchr(origdomain,'.');
    if (!s) break;
    strcat(buf,s+1);
    strcat(buf,".");
    *s = 0;
  }
  strcat(buf,origdomain);
  return buf;
}

static int rcptcompare __((const void *, const void *));
static int rcptcompare(p1,p2)
const void *p1, *p2;
{
  struct rcpts *r1 = (struct rcpts*)p1, *r2 = (struct rcpts*)p2;
  return strcmp((r1)->revdomain, (r2)->revdomain);
}

int
main(argc,argv)
     int argc;
     char *argv[];
{
	FILE *mfp = NULL;
	FILE *addrfile;
	FILE *bodycopy;
	char *s, *p, *p2;
	char buf[8192];
	char *newcp;
	long privuid = -1;
	struct rcpts *rcpts = malloc(sizeof(*rcpts)*8);
	int rcpts_space = 8;
	int rcpts_count = 0;
	int ezmlmalike = 0;
	int debug = 0;

	if (argv[1] && strcmp(argv[1],"-debug")==0) {
	  ++argv;
	  --argc;
	  debug = 1;
	}

	if (argv[1] && strcmp(argv[1],"+ezmlm")==0) {
	  ++argv;
	  --argc;
	  ezmlmalike = 1;
	}

	if (argc > 3 && argv[1][0]=='-') {
	  bundlesize = atoi(argv[1]+1);
	  if (bundlesize < 1)
	    bundlesize = 1;
	  ++argv;
	  --argc;
	}

	if (bundlesize > 1) ezmlmalike = 0;

	if (argc < 3 || argc > 4)
	  usage();
	if ((addrfile = fopen(argv[2],"r")) == NULL)
	  usage();
	if (argc < 3)
	  if (sscanf(argv[3],"%ld",&privuid) != 1)
	    usage();

	while (!feof(addrfile) && !ferror(addrfile)) {

	  /* See if the file has some address in it! */
	  if (fgets(buf,sizeof(buf)-1,addrfile) == NULL) 
	    break;
	  s = strchr(buf,'\n'); if (s) *s = 0; /* Zap the trailing '\n' */

	  s = buf;
	  while(*s == ' ' || *s == '\t') ++s; /* Skip white */

	  p = rfc821_path2(s, 1); /* Strict syntax scanner */

	  /* Blank line -- or started with TAB or SPC.. */

	  if (p == s) {
	    if (debug) {
	      fprintf(stderr, "Input Address Syntax Fault: '%s'\n", buf);
	    } else {
	      /* Report the error to the given OWNER! */
	      if (!mfp) {
		mfp = mail_open(MSG_RFC822);
		if (!mfp) exit(EX_CANTCREAT); /* ??? */

		fprintf(mfp, "channel error\n");
		fprintf(mfp, "to %s\nenv-end\n", argv[1]);
		fprintf(mfp, "From: \"Expander of %s\" <>\n", argv[2]);
		fprintf(mfp, "To: List Owner <%s>\n", argv[1]);
		fprintf(mfp, "Subject: Bad data at listfile '%s'\n", argv[2]);
		fprintf(mfp, "\n");
		fprintf(mfp, "Following lines were found to have bad RFC 821\n");
		fprintf(mfp, "interpreted data at file: %s\n\n", argv[2]);
	      }

	      fprintf(mfp, "%s\n", buf);

	    }
	    continue;
	  }

	  *p = 0;
	  if (s == p || *s == '\n' || *s == 0) continue;

	  p2 = p = strrchr(s,'@');

	  /* Lowercasify the ASCII (domain) string */
	  for (; p && *p; ++p) {
	    if ('A' <= *p && *p <= 'Z') *p += 0x20;
	  }

	  if (rcpts_count >= rcpts_space) {
	    rcpts_space <<= 1;
	    rcpts = realloc(rcpts, sizeof(*rcpts)*rcpts_space);
	  }
	  rcpts[rcpts_count].address   = strdup(s);
	  rcpts[rcpts_count].revdomain = reverse_domain(p2 ? p2+1 : "");
	  ++rcpts_count;
	}
	fclose(addrfile);

	if (mfp)
	  mail_close(mfp);

	if (rcpts_count == 0) {
	  rcpts[rcpts_count].address = "postmaster";
	  rcpts[rcpts_count].revdomain = "";
	  ++rcpts_count;
	}

	if (rcpts_count > 1) {
	  qsort(rcpts, rcpts_count, sizeof(*rcpts), rcptcompare);
	}
#if 0
{
int i;
for (i = 0; i < rcpts_count; ++i)
  fprintf(stderr,"%s \t%s\n", rcpts[i].revdomain,rcpts[i].address);
}
#endif
	bodycopy = tmpfile();
	/* Copy the original file into the spool as is.. */
	/* Start with eating the first "From " -line.. */
	fgets(buf,sizeof(buf),stdin);
	if (strncmp(buf,"From ",5) != 0)
	  fputs(buf,bodycopy);
	while (1) {
	  int siz = fread(buf,1,sizeof(buf),stdin);
	  if (siz == 0) break;
	  if (fwrite(buf,1,siz,bodycopy) != siz) {
	    exit(EX_CANTCREAT);
	  }
	}
	fflush(bodycopy);
	if (ferror(bodycopy))
	  exit(EX_TEMPFAIL); /* Duh! Something wrong here... */
	fseek(bodycopy,0,SEEK_SET);



	rcpts_space = 0; /* Reuse the variable.. */
	while (rcpts_space < rcpts_count) {
	  int i;
	  /* Open the spool file  */
	  if (debug) {
	    mfp = stderr;
	    fprintf(mfp, "\n----------- %d -----------\n\n", rcpts_space);
	  } else
	    mfp = mail_open(MSG_RFC822);
	  if (!mfp) exit(EX_CANTCREAT); /* ??? */

	  if (!debug)
	    fprintf(mfp,"via listexpand\n");

	  if (argv[1][0] == 0 || argv[1][0] == ' ')
	    fprintf(mfp,"channel error\n");
	  else {
	    fprintf(mfp,"from %s",argv[1]);
	    if (!ezmlmalike)
	      fprintf(mfp,"\n");
	  }

	  /* Up to BUNDLESIZE recipient addresses */
	  for (i = 0;
	       rcpts_space < rcpts_count && i < bundlesize;
	       ++i) {
	    s = rcpts[rcpts_space].address;
	    ++rcpts_space;
	    RFC821_822QUOTE(newcp,s);

	    if (ezmlmalike) {
	      putc('+', mfp);
	      for (p = s; *p; ++p) {
		u_char c = *p;
	      if (('0' <= c && c <= '9') ||
		  ('A' <= c && c <= 'Z') ||
		  ('a' <= c && c <= 'z') ||
		  ('.' == c) || ('-' == c) || (c == '_')) {
		putc(c, mfp);
	      } else
		fprintf(mfp, "=%02X", c);
	      }
	      fprintf(mfp, "\n");
	    }

	    /* FIRST 'todsn', THEN 'to' -header! */
	    fprintf(mfp, "todsn ORCPT=rfc822;");
	    p = s;
	    for (p = s; *p; ++p) {
	      u_char c = *p;
	      if ('!' <= c && c <= '~' && c != '+' && c != '=')
		putc(c,mfp);
	      else
		fprintf(mfp,"+%02X",c);
	    }
	    /* if (notify)
	       fprintf(mfp," NOTIFY=%s", notify);
	       */
	    putc('\n',mfp);
	    fprintf(mfp,"to %s\n",s);
	  } /* End of recipient address printing */

	  fprintf(mfp,"env-end\n");

	  if (ferror(mfp) || feof(mfp)) {
	    mail_abort(mfp);
	    exit(EX_CANTCREAT);
	  }

	  if (!debug) {

	    fseek(bodycopy, 0, SEEK_SET);
	    while (1) {
	      int siz = fread(buf,1,sizeof(buf),bodycopy);
	      if (siz == 0) break;
	      if (fwrite(buf,1,siz,mfp) != siz) {
		mail_abort(mfp);
		exit(EX_CANTCREAT);
	      }
	    }

	    if (feof(mfp) || ferror(mfp)) {
	      mail_abort(mfp);
	      exit(EX_CANTCREAT);
	    }
	    if (privuid >= 0)
	      fchown(FILENO(mfp),privuid,-1);
	    mail_close(mfp);

	  } /* - not debug - */

	} /* All recipientbundles */

	return 0;
}
