/*
 * load-average getter for the ZMailer
 *
 * By Matti Aarnio <mea@utu.fi> Dec-94
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
extern int errno;
#ifndef NO_LOADAVER

/* ================================================================ */
#ifdef	__linux__
#include	<fcntl.h>
int loadavg_current()
{
    /*
       $ cat /proc/loadavg 
       0.01 0.01 0.00
     */

    int rc, loadavg = 0;
    char buf[20];
    int fd = open("/proc/loadavg", O_RDONLY, 0);

    if (fd < 0)
	return 0;		/* Not available.. */

    do {
	rc = read(fd, buf, sizeof(buf) - 1);
	if (rc < 0) {
	    if (errno == EINTR)
		continue;
	    close(fd);
	    return 0;		/* Some other error */
	} else
	    break;
    } while (1);

    close(fd);
    buf[rc] = 0;

    loadavg = atoi(buf);
    if (loadavg < 0)
	return 0;		/* Error ?? */
    return loadavg;
}
#else
/* ================================================================ */
#if	defined(__svr4__) || defined(sun)
	/* These routines are pulled from  TOP ... */

	/* Linkage:
	   SVR4:      -lkvm -lelf
	   SunOS4.x:  -lkvm
	 */
#include <fcntl.h>
extern char *sys_errlist[];

#include <nlist.h>
#include <kvm.h>

static struct nlist nlst[] =
{
#if	defined(i386) || defined(__svr4__)
    {"avenrun"},
#else
    {"_avenrun"},		/* Sparc and 68k SunOS 4.x have it this way.. */
#endif
    {NULL}
};
static unsigned long avenrun_offset = 0;
static int kd_inited = 0;

/* [Thomas Knott] [German->English translation by Matti Aarnio]
 * On Solaris 2.x we use kvm_open() to open  /dev/ksyms.
 * The reading of /dev/ksyms is supported only on limited
 * number of file descriptors at a time (circa 10).
 *
 * The original version did a kvm_open() at the start of the
 * server, and kept them alive thru fork()s (to childs), and
 * thus soon used up the small resource.
 */


static int machine_init()
{
    kvm_t *kd;

    kd_inited = 1;
    kd = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
    if (kd == NULL)
	return 0;

    if (kvm_nlist(kd, nlst) < 0) {
	kvm_close(kd);
	kd = NULL;
	return 0;
    }
    if (nlst[0].n_type == 0) {	/* It wasn't found.. Our only! */
	kvm_close(kd);
	kd = NULL;
	return;
    }
    avenrun_offset = nlst[0].n_value;	/* 0:th offset */
    kvm_close(kd);
    return 1;
}

/*
 *  getkval(offset, ptr, size, refstr) - get a value out of the kernel.
 *      "offset" is the byte offset into the kernel for the desired value,
 *      "ptr" points to a buffer into which the value is retrieved,
 *      "size" is the size of the buffer (and the object to retrieve),
 */
static int getkval(offset, ptr, size)
unsigned long offset;
int *ptr;
int size;
{
    kvm_t *kd;
    int ret;

    kd = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
    ret = kvm_read(kd, offset, (char *) ptr, size);
    kvm_close(kd);
    return ret;
}

int loadavg_current()
{
    long avenrun[3];

    if (!kd_inited)
	if (machine_init() == 0)
	    return 0;

    /* get load average array */
    if (!getkval(avenrun_offset, (int *) avenrun, sizeof(avenrun), NULL))
	return 0;		/* Failed.. */
    return (int) (avenrun[0] >> 8);	/* a fixed-point decimal number */
}

#else
/* ================================================================ */
int loadavg_current()
{
    return 0;			/* Dummy.. */
}
/* ================================================================ */
#endif
#endif
#endif
