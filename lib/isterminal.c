/*
 *  z_isterminal(fd):  Return true (non-zero), if passed fd yields
 *                     success on   tcgetattr()  ioctl.
 *
 */

#include "hostenv.h"

#ifdef HAVE_TERMIOS_H
#include <termios.h>	/* POSIX.1 says this exists.. */
#else
#include <termio.h>	/* POSIX.1 says this is obsolete.. */
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

int
z_isterminal(fd)
     const int fd;
{
  struct termios T; /* What to do if this isn't found ? */
  int rc;

  rc = tcgetattr(fd, &T);

  return (rc >= 0);
}
