/*
 *  listexpand -- expand mailinglist from a file to have an envelope
 *		  containing all the addresses listed individually.
 *
 *  listexpand owner@address /path/to/file/containing/addresses privuid
 *
 *  This EXPECTS things from the listfile:
 *	recipient@address <TAB> (other data in comments) <NEWLINE>
 *
 *  By  Matti Aarnio <mea@nic.funet.fi>  1995,1998
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include "sysexits.h"
#include "mailer.h"
#include "mail.h"
#include "ta.h"
#include "libz.h"

char *progname = "listexpand";
int D_alloc = 0;
extern char *strchr();

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
  fprintf(stderr,"%s:  owner@address /path/to/file/containing/addresses privuid\n",
	  progname);
  exit(EX_USAGE);
}

int
main(argc,argv)
     int argc;
     char *argv[];
{
	FILE *mfp = NULL;
	FILE *addrfile;
	char *s, *p;
	char buf[8192];
	int first = 1;
	char *newcp;
	long privuid;

	if (argc != 4)
	  usage();
	if ((addrfile = fopen(argv[2],"r")) == NULL)
	  usage();
	if (sscanf(argv[3],"%ld",&privuid) != 1)
	  usage();

	while (!feof(addrfile) && !ferror(addrfile)) {

	  /* See if the file has some address in it! */
	  if (fgets(buf,sizeof(buf)-1,addrfile) == NULL) 
	    break;
	  s = strchr(buf,'\n'); if (s) *s = 0; /* Zap the trailing '\n' */

	  s = buf;
	  while(*s == ' ' || *s == '\t') ++s;
	  p = skip821address(s);
	  /* Blank line -- or started with TAB or SPC.. */
	  *p = 0;
	  if (s == p || *s == '\n' || *s == 0) continue;

	  /* Open the spool file for the first recipient */
	  if (!mfp) {
	    mfp = mail_open(MSG_RFC822);
	    if (!mfp) exit(EX_CANTCREAT); /* ??? */
	    if (argv[1][0] == 0 || argv[1][0] == ' ')
	      fprintf(mfp,"channel error\n");
	    else
	      fprintf(mfp,"from %s\n",argv[1]);
	  }
	  if (first) {
	    fprintf(mfp,"via listexpand\n");
	    first = 0;
	  }

	  RFC821_822QUOTE(newcp,s);

	  /* FIRST 'todsn', THEN 'to' -header! */
	  fprintf(mfp, "todsn ORCPT=rfc822;");
	  p = s;
	  while (*p) {
	    u_char c = *p;
	    if ('!' <= c && c <= '~' && c != '+' && c != '=')
	      putc(c,mfp);
	    else
	      fprintf(mfp,"+%02X",c);
	    ++p;
	  }
	  /* if (notify)
	     fprintf(mfp," NOTIFY=%s", notify);
	  */
	  putc('\n',mfp);
	  fprintf(mfp,"to %s\n",s);

	  if (ferror(mfp) || feof(mfp)) {
	    mail_abort(mfp);
	    exit(EX_CANTCREAT);
	  }

	}
	fclose(addrfile);

	/* If the loop quit, and  mfp  is not open,
	   no addresses were found.. */
	if (!mfp) exit(EX_DATAERR);

	/* Copy the original file into the spool as is.. */
	/* Start with eating the first "From " -line.. */
	fgets(buf,sizeof(buf),stdin);
	if (strncmp(buf,"From ",5) != 0)
	  fputs(buf,mfp);
	while (1) {
	  int siz = fread(buf,1,sizeof(buf),stdin);
	  if (siz == 0) break;
	  if (fwrite(buf,1,siz,mfp) != siz) {
	    mail_abort(mfp);
	    exit(EX_CANTCREAT);
	  }
	}
	if (ferror(stdin)) {
	  mail_abort(mfp);
	  exit(EX_DATAERR);
	}
	if (feof(mfp) || ferror(mfp)) {
	  mail_abort(mfp);
	  exit(EX_CANTCREAT);
	}
	fchown(FILENO(mfp),privuid,-1);
	mail_close(mfp);
	return 0;
}
