/*
 * Several 'setreuid()' replacements for those systems that
 * don't have it, or have it under different names...
 */
#include "hostenv.h"

/*
 * From Ross Ridge's Xenix port:
 * - setreuid, setreuid, *sigh* this going to a big mondo problem porting
 *   Zmailer to a box without it or SysVR3's saved set-user ID.  Xenix is
 *   one of these beasties, so I resorted to a desperate hack: I wrote
 *   setreuid function that opens /dev/kmem and fiddles with the u area.
 */

/*
 * Simpleton ports of HPUX  setresuid() to setreuid() replacement..
 * Though maybe it is better to be done on macrolevel ?
 * This REQUIRES  "SETREUID" in the  hostenv/HPUX8 -file!
 */

/* Several tricks for IBM AIX for Zmailer
   by Matti Aarnio <mea@utu.fi> <mea@nic.funet.fi>

   Mostly these are pulled in from various sources :)

   On your AIX machine, see:

      /usr/lpp/bos/bsdport(.tr)

   file for the information about how to do the porting of
   BSD-oriented software into AIX systems.
   (A PostScript rendered version is on Zmailers  doc/aix-bsdport.ps)

*/
#if defined(AIX) || defined(_AIX)

#include <sys/types.h>
#include <sys/param.h>
#include <sys/id.h>
#include <sys/priv.h>


int
setreuid(ruid,euid)
uid_t ruid, euid;
{
	/* Pulled in from WUARCHIVE's FTPD source.. */

	/* AIX 3 lossage.  Don't ask.  It's undocumented.  */
	/* [mea]: WU-people did err, it IS documented; AIX is just
	          a bit peculiar.. */
	priv_t priv;

	priv.pv_priv[0] = 0;
	priv.pv_priv[1] = 0;
	setgroups(NULL, NULL);

	if (setpriv(PRIV_SET|PRIV_INHERITED|PRIV_EFFECTIVE|PRIV_BEQUEATH,
		    &priv, sizeof(priv_t)) < 0)
	  return -1;

	if (ruid != (uid_t)-1)
	  if (setuidx(ID_REAL|ID_EFFECTIVE, ruid) < 0)
	    return -1;

	if (euid != (uid_t)-1)
	  if (seteuid(euid) < 0)
	    return -1;

#ifdef UID_DEBUG
	lreply(230, "ruid=%d, euid=%d, suid=%d, luid=%d", getuidx(ID_REAL),
	       getuidx(ID_EFFECTIVE), getuidx(ID_SAVED), getuidx(ID_LOGIN));
	lreply(230, "rgid=%d, egid=%d, sgid=%d, lgid=%d", getgidx(ID_REAL),
	       getgidx(ID_EFFECTIVE), getgidx(ID_SAVED), getgidx(ID_LOGIN));
#endif
	return 0;
}

#else /* Not AIX */
#ifdef HAVE_SETREUID /* AIX has a sort of setreuid() at its libc, however
			it does not work... All others either have it, or
			don't, and need emulation: */
static int dummy = 0;
#else /* .. else need emulation */

#ifdef HAVE_SETEUID	/* Pure SysVR4 ? */
int setreuid(ruid, euid)
     uid_t ruid, euid;
{
	/* THIS IS NOT PURE IMPLEMENTATION! */
	/* INTENTION IS TO PROVIDE SOMETHING WORKABLE
	   WITHOUT TOO COMPLEX A PROGRAM... */

	int rc = 0;
	if (euid >= 0) {
	  rc = seteuid(euid);
	  if (ruid < 0)
	    return rc;
	}
	if (ruid >= 0)
	  return setuid(ruid);
	return rc;
}
#else

#ifdef	__hpux	/* HP-UX ?? */
#include <sys/types.h>

int
setreuid(ruid, euid)
uid_t ruid, euid;
{
	return setresuid(ruid,euid,(uid_t)-1);
}


#else /* Not HPUX 9.xx, (8.xx ?) */
/* Else something else funny.. */

/* We go via SysVr3 methods, which are horrible.. */

#ifdef	SYSV

/* Uhh...  We open process uarea from kernel memory, and poke it
   directly.  Seriously NOT FUN, but ...  */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/page.h>
#include <sys/seg.h>
#include <sys/sysmacros.h>
#include <sys/user.h>

#undef TEST

#ifndef TEST
#include "libsupport.h"
#include "sysprotos.h"
#endif

static struct user uu;
static int kmem_fd = -1;

static int
read_u() {
        if (lseek(kmem_fd, (long) SPTADDR, 0) == -1) {
                perror("lseek failed!");
                return -1;
        }
        if (read(kmem_fd, &uu, sizeof uu) == -1) {
                perror("read failed!");
                return -1;
        }
        return 0;
}

static int
write_uid(int uid, int euid) {
        if (lseek(kmem_fd,
                  (char *) &uu.u_ruid - (char *) &uu + (long) SPTADDR,
                  0) == -1L) {
                perror("lseek failed!");
                return -1;
        }
        uu.u_ruid = uid;
        if (write(kmem_fd, &uu.u_ruid, sizeof uu.u_ruid) == -1) {
                perror("write failed!");
                return -1;
        }
        if (lseek(kmem_fd,
                  (char *) &uu.u_uid - (char *) &uu + (long) SPTADDR,
                  0) == -1L) {
                perror("lseek failed!");
                return -1;
        }
        uu.u_uid = euid;
        if (write(kmem_fd, &uu.u_uid, sizeof uu.u_uid) == -1) {
                perror("write failed!");
                return -1;
        }
        return 0;
}

int
setreuid(int uid, int euid) {
        int cmask;

        if (kmem_fd == -1) {
                kmem_fd = open("/dev/kmem", O_RDWR);
                if (kmem_fd == -1) {
                        return -1;
                }
                if (read_u() == -1) {
                        abort(); /* kvm IO-error ! */
                }
                cmask = umask(0);
                umask(cmask);
                if (uu.u_ruid != getuid() || uu.u_rgid != getgid()
                    || uu.u_uid != geteuid() || uu.u_gid != getegid()
                    || uu.u_cmask != cmask) {
                        fprintf(stderr, "setreuid check failed!\n");
                        abort(); /* kvm IO-error ! */
                }
                if (fcntl(kmem_fd, F_SETFD, 1) == -1) {
                        perror("fcntl failed!");
                        abort(); /* kvm IO-error ! */
                }
        }

        if (uid == -1) {
                uid = getuid();
        } else if ((unsigned) uid >= MAXUID) {
                errno = EINVAL;
                return -1;
        }

        if (euid == -1) {
                euid = geteuid();
        } else if ((unsigned) euid >= MAXUID) {
                errno = EINVAL;
                return -1;
        }

        if (write_uid(uid, euid) == -1) {
                abort(); /* kvm IO-error ! */
        }
        return 0;
}

#ifdef TEST
main() {
        kmem_fd = open("/dev/kmem", O_RDWR);
        if (kmem_fd == -1) {
                perror("open failed!");
                return 1;
        }

        printf("SPTADDR = %#lx\n", SPTADDR);

        if (read_u() == -1) {
                return 1;
        }
        printf("u_uid: %d u_gid: %d u_rgid: %d u_ruid: %d\n",
               uu.u_uid, uu.u_gid, uu.u_rgid, uu.u_ruid);
        printf("u_cmask: %#03o u_limit: %ld\n", uu.u_cmask, (long) uu.u_limit);
        printf("u_psargs: '%-0.40s'\n", uu.u_psargs);

        setreuid(0, 1);
        printf("\ngeteuid() = %d\n", geteuid());

        if (read_u() == -1) {
                return 1;
        }
        printf("u_uid: %d u_gid: %d u_rgid: %d u_ruid: %d\n",
               uu.u_uid, uu.u_gid, uu.u_rgid, uu.u_ruid);
        printf("u_cmask: %#03o u_limit: %ld\n", uu.u_cmask, (long) uu.u_limit);
        printf("u_psargs: '%-0.40s'\n", uu.u_psargs);

        setreuid(0, 0);
        printf("\ngeteuid() = %d\n", geteuid());

        close(kmem_fd);
        return 0;
}
#endif

#else /* not SYSV - 386 ? ... */
static int foovar = 0; /* some systems want something into .o -file */
#endif /* Not SYSV */
#endif /* Not SYSV, not __hpux */
#endif /* HAVE_SETEUID */
#endif /* HAVE_SETREUID */
#endif /* Not AIX either.. */
