/* taspoolid() -- build a spoolid into provided buffer
 *
 * Minimum spoolid space is about 6+6 chars!
 * (6 for a timestamp, 5+1 for the spoolid and terminating null..)
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char base64chars[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void taspoolid(buf,buflen,mtime,filename)
char *buf;
int buflen;
time_t mtime;
char *filename;
{
  int i;
  char *s = buf;
  char *fn;

  /* Start with a capital 'S' .. */
  *s++ = 'S';

  /* .. then fill in the base-64 encoded mtime .. */
  for (i = 5; i >= 0; --i)
    *s++ = base64chars[ (mtime >> (i*6)) & 63 ];

  fn = strrchr(filename,'/');
  if (!fn) fn = filename;
  else ++fn;

  /* .. and finally attach the inode-number part of the spool file name. */

  s = strchr(fn,'-'); if (s) *s = 0;
  sprintf(buf+7,"%.*s", buflen-8, fn); /* Truncate if longer than we have
					  room for! */
  if (s) *s = '-';
}
