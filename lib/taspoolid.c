/* taspoolid() -- build a spoolid into provided buffer
 *
 * Minimum spoolid space is about 17 chars!  Have at least 32 !
 * (8 for a timestamp, 8+1 for the i-node number and terminating null..)
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* These ARE NOT MIME BASE64 characters, but something by which it is
   fairly easily to MANUALLY decode the following result.. */
static char encodechars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123abcdefghijklmnopqrstuvwxyz4567890-=";

void taspoolid(buf,mtime,inodenum)
char *buf;
time_t mtime;
long inodenum;
{
  char *s = buf;
  struct tm *tt;

  /* GMT time */
  tt = gmtime(&mtime);

  tt->tm_year += 1900;

  /* Start with a capital 'S' .. */
  *s++ = 'S';

  sprintf(s,"%ld", inodenum);
  s += strlen(s);

  /* Year in 'base64', sort of.. */
  *s++ = encodechars[(tt->tm_year >> 12) & 63];
  *s++ = encodechars[(tt->tm_year >>  6) & 63];
  *s++ = encodechars[(tt->tm_year      ) & 63];
  /* Month */
  *s++ = encodechars[tt->tm_mon];
  /* Day */
  *s++ = encodechars[tt->tm_mday-1];
  /* Hour */
  *s++ = encodechars[tt->tm_hour];
  /* Minutes */
  *s++ = encodechars[tt->tm_min];
  /* Seconds */
  *s++ = encodechars[tt->tm_sec];

  *s = 0; /* terminate zero */

  /* .. and finally attach the inode-number part of the spool file name. */

}
