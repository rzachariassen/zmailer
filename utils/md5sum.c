/*
 *  MD5SUM program - equivalent of GNU  textutils  'md5sum -b' program.
 *  Does not support any '-t' ("text") and '--check' options...
 *
 *  Added to ZMailer on 3-Nov-1999 to help "make install" to work nicely,
 *  and to detect when system supplied scripts have been altered, and
 *  when not -- to safely be able to replace unaltered ones with newer
 *  baseline versions.
 *
 */


#include "config.h"
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif
#include <fcntl.h>
#include <errno.h>

#include "md5.h"

extern char *optarg;
extern int optind;

int md5file(filename, md5result)
     char *filename;
     unsigned char *md5result;
{
  int fd;
  MD5_CTX M5;
  char buf[8192];
  int i;

  if (strcmp("-",filename) == 0)
    fd = fileno(stdin);
  else
    fd = open(filename,O_RDONLY,0);

  if (fd < 0) return -1;

  MD5Init(&M5);
  while (1) {
    i = 0;
    while (i < sizeof(buf)) {
      int r;
      r = read(fd, buf+i, sizeof(buf)-i);
      if (r < 0 && errno == EINTR)
	continue;
      if (r < 0) {
	i = r;
	break;
      }
      if (r == 0)
	break; /* EOF! */
      i += r;
    }

    /* if (i != sizeof(buf))
       printf("MD5Update() size = %d\n", i);
    */

    if (i == 0) break; /* EOF */
    if (i > 0)
      MD5Update(&M5, buf, i);
  }
  MD5Final(md5result, &M5);

  if (fd != fileno(stdin))
    close(fd);

  return 0;
}

static void usage()
{
  fprintf(stderr,"Usage: md5sum [-b] [filename|-|<stdin>]\n");
  fprintf(stderr,"  A SUBSET of e.g. GNU 'md5sum' program to do\n");
  fprintf(stderr,"  binary transparent MD5 sum of given input file.\n");
  fprintf(stderr,"  This is for ZMailer's installation/upgrade routines\n");
  fprintf(stderr,"  and applicability anywhere else is not guaranteed.\n");
  exit(64);
}


int main(argc, argv)
     int argc;
     char *argv[];
{
  int c, i;
  char *fname;
  unsigned char md5[16];

  while ((c = getopt(argc, argv, "bt")) != EOF) {
    switch(c) {
    case 'b':
      break;
    default:
      usage();
      break;
    }
  }

  if ((optind + 1) < argc)
    usage(); /* Only one non-option argument! */

  if (optind < argc)
    fname = argv[optind];
  else
    fname = "-";

  if (md5file(fname, md5))
    usage(); /* file open failed */

  for (i = 0; i < 16; ++i)
    printf("%02x", md5[i]);

  printf(" *%s\n", fname);

  return 0;
}
