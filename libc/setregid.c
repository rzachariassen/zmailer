/*
 * Several 'setregid()' replacements for those systems that
 * don't have it, or have it under different names...
 *
 * This is just setreuid.c renamed, and all instances of "uid"
 * converted to "gid" -- it may, or may not work all right...
 */
#include "hostenv.h"

/*
 * From Ross Ridge's Xenix port:
 * - setregid, setregid, *sigh* this going to a big mondo problem porting
 *   Zmailer to a box without it or SysVR3's saved set-user ID.  Xenix is
 *   one of these beasties, so I resorted to a desperate hack: I wrote
 *   setregid function that opens /dev/kmem and fiddles with the u area.
 */

/*
 * Simpleton ports of HPUX  setresuid() to setregid() replacement..
 * Though maybe it is better to be done on macrolevel ?
 * This REQUIRES  "SETREGID" in the  hostenv/HPUX8 -file!
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
setregid(rgid,egid)
gid_t rgid, egid;
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

	if (rgid != (gid_t)-1)
	  if (setgidx(ID_REAL|ID_EFFECTIVE, rgid) < 0)
	    return -1;

	if (egid != (gid_t)-1)
	  if (setegid(egid) < 0)
	    return -1;

#ifdef GID_DEBUG
	lreply(230, "rgid=%d, egid=%d, suid=%d, luid=%d", getuidx(ID_REAL),
	       getuidx(ID_EFFECTIVE), getuidx(ID_SAVED), getuidx(ID_LOGIN));
	lreply(230, "rgid=%d, egid=%d, sgid=%d, lgid=%d", getgidx(ID_REAL),
	       getgidx(ID_EFFECTIVE), getgidx(ID_SAVED), getgidx(ID_LOGIN));
#endif
	return 0;
}

#else /* Not AIX */
#ifdef HAVE_SETREGID /* AIX has a sort of setregid() at its libc, however
			it does not work... All others either have it, or
			don't, and need emulation: */
/* static int dummy = 0; */
#else /* .. else need emulation */

#ifdef HAVE_SETEGID	/* Pure SysVR4 ? */
int setregid(rgid, egid)
     gid_t rgid, egid;
{
	/* THIS IS NOT PURE IMPLEMENTATION! */
	/* INTENTION IS TO PROVIDE SOMETHING WORKABLE
	   WITHOUT TOO COMPLEX A PROGRAM... */

	int rc = 0;
	if (egid >= 0) {
	  rc = setegid(egid);
	  if (rgid < 0)
	    return rc;
	}
	if (rgid >= 0)
	  return setgid(rgid);
	return rc;
}
#else

#ifdef	__hpux	/* HP-UX ?? */
#include <sys/types.h>

int
setregid(rgid, egid)
gid_t rgid, egid;
{
	return setresgid(rgid,egid,(gid_t)-1);
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
write_gid(int gid, int egid) {
        if (lseek(kmem_fd,
                  (char *) &uu.u_rgid - (char *) &uu + (long) SPTADDR,
                  0) == -1L) {
                perror("lseek failed!");
                return -1;
        }
        uu.u_rgid = gid;
        if (write(kmem_fd, &uu.u_rgid, sizeof uu.u_rgid) == -1) {
                perror("write failed!");
                return -1;
        }
        if (lseek(kmem_fd,
                  (char *) &uu.u_gid - (char *) &uu + (long) SPTADDR,
                  0) == -1L) {
                perror("lseek failed!");
                return -1;
        }
        uu.u_gid = egid;
        if (write(kmem_fd, &uu.u_gid, sizeof uu.u_gid) == -1) {
                perror("write failed!");
                return -1;
        }
        return 0;
}

int
setregid(int gid, int egid) {
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
                if (uu.u_rgid != getgid() || uu.u_rgid != getgid()
                    || uu.u_gid != getegid() || uu.u_gid != getegid()
                    || uu.u_cmask != cmask) {
                        fprintf(stderr, "setregid check failed!\n");
                        abort(); /* kvm IO-error ! */
                }
                if (fcntl(kmem_fd, F_SETFD, 1) == -1) {
                        perror("fcntl failed!");
                        abort(); /* kvm IO-error ! */
                }
        }

        if (gid == -1) {
                gid = getgid();
        } else if ((unsigned) gid >= MAXGID) {
                errno = EINVAL;
                return -1;
        }

        if (egid == -1) {
                egid = getegid();
        } else if ((unsigned) egid >= MAXGID) {
                errno = EINVAL;
                return -1;
        }

        if (write_gid(gid, egid) == -1) {
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
        printf("u_gid: %d u_gid: %d u_rgid: %d u_rgid: %d\n",
               uu.u_gid, uu.u_gid, uu.u_rgid, uu.u_rgid);
        printf("u_cmask: %#03o u_limit: %ld\n", uu.u_cmask, (long) uu.u_limit);
        printf("u_psargs: '%-0.40s'\n", uu.u_psargs);

        setregid(0, 1);
        printf("\ngetegid() = %d\n", getegid());

        if (read_u() == -1) {
                return 1;
        }
        printf("u_gid: %d u_gid: %d u_rgid: %d u_rgid: %d\n",
               uu.u_gid, uu.u_gid, uu.u_rgid, uu.u_rgid);
        printf("u_cmask: %#03o u_limit: %ld\n", uu.u_cmask, (long) uu.u_limit);
        printf("u_psargs: '%-0.40s'\n", uu.u_psargs);

        setregid(0, 0);
        printf("\ngetegid() = %d\n", getegid());

        close(kmem_fd);
        return 0;
}
#endif

#else /* not SYSV - 386 ? ... */
static int foovar = 0; /* some systems want something into .o -file */
#endif /* Not SYSV */
#endif /* Not SYSV, not __hpux */
#endif /* HAVE_SETEGID */
#endif /* HAVE_SETREGID */
#endif /* Not AIX either.. */
