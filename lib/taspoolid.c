/* taspoolid() -- build a spoolid into provided buffer
 *
 * Minimum spoolid space is about 17 chars!  Have at least 32 !
 * (8 for a timestamp, 8+1 for the i-node number and terminating null..)
 *      64-bit decimal integer:    20 ch +
 *      compact encoded timestamp:  9 ch +
 *      string end NUL:             1 ch
 *  Total: 30 chars.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* These ARE NOT MIME BASE64 characters, but something by which it is
   fairly easily to MANUALLY decode the following result.. */
const char taspid_encodechars[] =
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
  *s++ = taspid_encodechars[(tt->tm_year >> 12) & 63];
  *s++ = taspid_encodechars[(tt->tm_year >>  6) & 63];
  *s++ = taspid_encodechars[(tt->tm_year      ) & 63];
  /* Month */
  *s++ = taspid_encodechars[tt->tm_mon];
  /* Day */
  *s++ = taspid_encodechars[tt->tm_mday-1];
  /* Hour */
  *s++ = taspid_encodechars[tt->tm_hour];
  /* Minutes */
  *s++ = taspid_encodechars[tt->tm_min];
  /* Seconds */
  *s++ = taspid_encodechars[tt->tm_sec];

  *s = 0; /* terminate zero */

  /* .. and finally attach the inode-number part of the spool file name. */

}
