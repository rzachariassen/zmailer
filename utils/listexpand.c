/*
 *  listexpand -- expand mailinglist from a file to have an envelope
 *		  containing all the addresses listed individually.
 *
 *  listexpand owner@address /path/to/file/containing/addresses
 *
 *  This EXPECTS things from the listfile:
 *	recipient@address <TAB> (other data in comments) <NEWLINE>
 */

#include <stdio.h>
#include "sysexits.h"
#include "mail.h"

char *progname = "listexpand";

extern char *strchr();

void usage()
{
  fprintf(stderr,"%s:  owner@address /path/to/file/containing/addresses\n",
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
	char *s;
	char buf[8192];

	if (argc != 3)
	  usage();
	if ((addrfile = fopen(argv[2],"r")) == NULL)
	  usage();

	while (!feof(addrfile) && !ferror(addrfile)) {

	  /* See if the file has some address in it! */
	  if (fgets(buf,sizeof(buf)-1,addrfile) == NULL) 
	    break;

	  /* Chop them of first TAB, SPC, or NEWLINE */
	  s = strchr(buf,'\t');
	  if (!s) s = strchr(buf,' ');
	  if (!s) s = strchr(buf,'\n');
	  if (s) *s = 0;

	  /* Blank line -- or started with TAB or SPC.. */
	  if (buf[0] == 0) continue;

	  /* Open the spool file for the first recipient */
	  if (!mfp) {
	    mfp = mail_open(MSG_RFC822);
	    if (!mfp) exit(EX_CANTCREAT); /* ??? */
	    if (argv[1][0] == 0 || argv[1][0] == ' ')
	      fprintf(mfp,"channel error\n");
	    else
	      fprintf(mfp,"from %s\n",argv[1]);
	  }
	  fprintf(mfp,"via listexpand\n");
	  fprintf(mfp,"to %s\n",buf);
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
	mail_close(mfp);
	return 0;
}
