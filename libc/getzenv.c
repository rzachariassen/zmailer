/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*LINTLIBRARY*/

/*
 *  The routines in this file will gulp in a configuration file in
 *  the syntax of printenv output, and allow access to the values read
 *  through an analogue of getenv().
 */

#include "mailer.h"
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include "mail.h"
#include "libc.h"

static char *zenviron = NULL;
static int zenvlen = 0;

int
readzenv(file)
	const char *file;
{
	int fd;
	struct stat stbuf;

	fd = open(file, 0);
	if (fd < 0) {
	  fprintf(stderr, "%s: open: %s: %s\n",
		  progname, file, strerror(errno));
	  return 0;
	}
	if (fstat(fd, &stbuf) < 0) {
	  fprintf(stderr, "%s: fstat: %s: %s\n",
		  progname, file, strerror(errno));
	  close(fd);
	  return 0;
	}
	zenviron = (char*)malloc((u_int) stbuf.st_size);
	if (zenviron == NULL) {
	  fprintf(stderr, "%s: malloc(size of %s): %d: out of memory\n",
		  progname, file, (int)stbuf.st_size);
	  close(fd);
	  return 0;
	}
	zenvlen = (int)stbuf.st_size;
	if (read(fd, zenviron, stbuf.st_size) != stbuf.st_size) {
	  fprintf(stderr, "%s: read: %s: %s\n",
		  progname, file, strerror(errno));
	  free(zenviron);
	  zenviron = NULL;
	  zenvlen = 0;
	  close(fd);
	  return 0;
	}
	close(fd);
	return 1;
}

#define BOL	1

char *
getzenv(variable)
	const char *variable;
{
	register int len, state;
	register unsigned char *cp;
	int varlen;
	char *save;

	if (variable == NULL)
	  return NULL;
	varlen = strlen(variable);
	if (varlen == 0)
	  return NULL;

	len = zenvlen;
	if (len <= 0) {
	  if (!readzenv(ZMAILER_ENV_FILE))
	    return NULL;
	  len = zenvlen;
	  if (len <= 0)
	    return NULL;
	}
	for (state = BOL, cp = zenviron; len > 0; --len, ++cp) {
	  if (*cp == '\n' || *cp == '\0') {
	    state = BOL;
	    continue;
	  }
	  if (state != BOL)
	    continue;
	  state = !BOL;
	  if (varlen < len && *variable == *cp
	      && strncmp(variable, cp, varlen) == 0
	      && *(cp+varlen) == '=')
	    break;
	}
	if (len > 0) {
	  for (cp += varlen+1; isascii(*cp) && isspace(*cp); ++cp)
	    if (*cp == '\n') {
	      *cp = '\0';
	      return cp;	/* empty value */
	    }
	  /*
	   * We want to return cp, but also make sure the string is
	   * properly terminated.
	   */
	  for (save = cp; *cp != '\0'; ++cp)
	    if (*cp == '\n') {
	      *cp = '\0';
	      break;
	    }
	  return save;
	}
	return NULL;
}
