#include "hostenv.h"
#include <stdio.h>

#include <sys/types.h>
#include <sys/fcntl.h>

#ifdef	HAVE_STATVFS
#include <sys/statvfs.h>
#define FSTATFS fstatvfs
#define STATFSTYPE struct statvfs
#else
#ifdef	SYSV
#include <sys/statfs.h>
/*# define FSTATFS fstatfs */
#define STATFSTYPE struct statfs
#else				/* Hmm.. Assuming it appears on all NON-SysV systems.. */
#include <sys/vfs.h>
#define FSTATFS fstatfs
#define STATFSTYPE struct statfs
#endif
#endif

int main()
{
    STATFSTYPE statbuf;
    int dirfd = open(".", O_RDONLY, 0);
    int rc;
    long availsize;

    printf("teststatfs:  dirfd=%d\n", dirfd);

    rc = FSTATFS(dirfd, &statbuf);

    printf("  fstatfs() rc = %d\n", rc);

    availsize = statbuf.f_bavail * statbuf.f_bsize;
    if (availsize < 0)
	availsize = 2000000000;	/* Over 2G ? */
    availsize >>= 1;

    printf("  f_avail=%d, f_bsize = %d\n",
	   statbuf.f_bavail, statbuf.f_bsize);

    printf("  availsize = %d\n", availsize);

    return 0;
}
