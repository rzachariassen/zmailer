/* local-host-randomizer -- utility for the ZMailer by Matti Aarnio */

#include <stdio.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include "hostenv.h"
#include "mail.h"
#include <alloca.h>

/*
   local-host-randomizer  "local" "majordomo" range

   From the STDIN it eats lines containing names of the files in
   POSTOFFICE/transport/, and then processes each of them by
   looking up "r "/"r~" -entries with matching channel and
   possible host strings (strcmp() processed).
   If the line matches, it is modified by changeing the last
   char of the "host" component into a digit in range of: '0' .. 'range-1',
   which works for ranges up to 10..

   This is for splitting large queue of majordomo jobs into
   multiple parallel slices..

   (utility written for vger.rutgers.edu as a quick-hack..)

*/

extern int errno;

int process(fd,channel,host,digit)
int fd;
char *host, *channel, digit;
{
	struct stat stbuf;
	char *filebuf;
	char *s, *p, *q, *eof;

	if (fstat(fd,&stbuf) != 0) return 1;

	lseek(fd,0,0);
	filebuf = malloc(stbuf.st_size+2);
	if (!filebuf) return 2; /* HOW COME??? */

	if (read(fd,filebuf,stbuf.st_size) != stbuf.st_size)
	  { free(filebuf); return 3; }
	eof = filebuf + stbuf.st_size;
	s = p = filebuf;
	*eof = 0;

	while (s < eof) {
	  if (*s == 'r') {
	    char *ch, *ho;
	    p = s++;
	    if (*s == ' ' || *s == '~') {
	      /* We MAY have some job! */
	      ++s;
	      while (*s == ' ' || (*s >= '0' && *s <= '9')) ++s;
	      /* Now 's' points at the start of the channel name */
	      ch = s;
	      while (s < eof && *s != '\n' && *s != ' ' && *s != '\t') ++s;
	      if (*s != '\n')
		*s++ = 0;
	      if (host != NULL) {
		while (s < eof && (*s == ' ' || *s == '\t')) ++s;
		ho = s;
		while (s < eof && *s != '\n' && *s != ' ' && *s != '\t') ++s;
		if (*s != '\n')
		  *s = 0;
	      } else
		ho = NULL;
	      while (s < eof && *s != '\n') ++s;

	      /* Ok, "ch" and "ho" are found.. */
	      if (strcmp(ch, channel) == 0) {
		int doit = 0;
		if (host != NULL &&
		    strcmp(ho, host) == 0) {
		  doit = 1;
		} else if (host == NULL)
		  doit = 1;
		if (doit) {
		  char *h = strlen(ho) + ho -1;
		  lseek(fd, h - filebuf, 0);
		  if (write(fd,&digit,1) != 1) {
			free(filebuf);
			return 9;
		  }		  
		}
	      }
	    }
	  } else if (*s == 'm') {
	    /* rewritten headers, scan until "\n\n" is found! */
	    while (s < eof && s[0] == '\n' && s[1] == '\n') ++s;
	    ++s; /* To the second '\n' */
	  } else {
	    /* Any other (one line) input files.. */
	    while (s < eof && *s != '\n') ++s;
	  }
	  ++s; /* Skip the trailing '\n' */
	}
	free(filebuf);
	return 0;
}

int main(argc,argv)
int argc;
char *argv[];
{
	int fd, rc;
	char filename[512];
	char *channel = argv[1];
	char *host    = NULL;
	char *s;
	int err;
	int range;
	int i = 0;

	if (argc != 4) {
	  fprintf(stderr,"local-host-randomizer channelname hostname range   -- stdin eats filenames\n");
	  return 64;
	}
	host = argv[2];
	range = atoi(argv[3]);
	if (range < 2 || range > 10) {
	  fprintf(stderr,"  ... bad 'range' parameter!  Must be in range 2..10\n");
	  return 64;
	}

	while (!feof(stdin)) {
	  if (fgets(filename,sizeof(filename),stdin) == NULL)
	    break;
	  s = strchr(filename,'\n');
	  if (s) *s = 0;
	  else break; /* Not newline-terminated input! */
	  fd = open(filename,O_RDWR,0);
	  if (fd < 0) {
	    err = errno;
	    fprintf(stderr,"File '%s' could not be opened",filename);
	    errno = err;
	    perror(":");
	    continue;
	  }
	  rc = process(fd, channel, host, i+'0');
	  if (rc != 0) {
	    err = errno;
	    fprintf(stderr,"File '%s' processing returned code %d",
		    filename,rc);
	    errno = err;
	    perror("error code");
	  }
	  close(fd);
	  ++i;
	  if (i >= range)
	    i = 0;
	}
	return 0;
}
