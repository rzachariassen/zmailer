/*
 *  Attach shared memory object where ZMailer's monitoring "MIB" lives in.
 *  
 *  This is (should be) file backed thing, and preferrably done with
 *  mmap(2) type of memory.
 *
 *  Part of ZMailer;  copyright Matti Aarnio <mea@nic.funet.fi> 2003
 *
 */

#include "hostenv.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif


#include "libc.h"
#include "zmalloc.h"
#include "libz.h"

#include "shmmib.h"

#ifndef HAVE_MMAP
#error "Sorry, support for systems without functional MMAP has not been done yet!"
#endif



/* Private static datablock just in case the actual public datablock is
   not available.. Wastes BSS memory, but ... */
static struct MIB_MtaEntry MIBMtaEntryLocal /* = {{0,},{0,}} */;

/* Public pointer to whatever datablock is at hand */
struct MIB_MtaEntry *MIBMtaEntry = &MIBMtaEntryLocal;


static int   SHM_storage_fd = -1;
static const char *SHM_SNMPSHAREDFILE_NAME;


int SHM_file_mode = 0664;

static int    SHM_block_size;
static void * SHM_block_ptr;

void Z_SHM_MIB_Detach __((void))
{
	if (SHM_storage_fd >= 0) {
	  int fd = SHM_storage_fd;
	  SHM_storage_fd = -1;

	  if (SHM_block_size &&  SHM_block_ptr) {
#ifdef HAVE_MMAP
#ifdef MS_SYNC
	    msync(SHM_block_ptr, SHM_block_size, MS_SYNC);
#endif /* MS_SYNC */
	    munmap(SHM_block_ptr, SHM_block_size);
#endif /* HAVE_MMAP */
	  }

	  SHM_block_size = 0;
	  SHM_block_ptr  = NULL;

	  close (fd);
	}
}

/* Flag telling if we really have shared segment online, or not.. */
int Z_SHM_MIB_is_attached __((void)) {
	return (SHM_block_ptr != NULL && SHM_block_size > 0);
}

void Z_SHM_MIB_Attach(rw)
	int rw;
{
	int storage_fd = -1;
	int block_size = sizeof(* MIBMtaEntry);
	struct stat stbuf;

	void *p; int i, r;

#ifdef HAVE_SYSCONF
#ifdef _SC_PAGESIZE
	int page_size = sysconf(_SC_PAGESIZE);
#else
	int page_size = sysconf(_SC_PAGE_SIZE);
#endif
#else
#ifdef HAVE_GETPAGESIZE
	int page_size = getpagesize();
#else
	int page_size = 16*1024; /* Fallback value */
#endif
#endif

	/* Round up to next full page size */
	block_size += page_size;
	block_size -= (block_size % page_size);

	  

	atexit(Z_SHM_MIB_Detach);

	SHM_SNMPSHAREDFILE_NAME = getzenv("SNMPSHAREDFILE");

	if (!SHM_SNMPSHAREDFILE_NAME) return; /* No attach, private data.. */

	for (;;) {
	  if (rw)
	    storage_fd = open(SHM_SNMPSHAREDFILE_NAME, O_RDWR, 0);
	  else
	    storage_fd = open(SHM_SNMPSHAREDFILE_NAME, O_RDONLY, 0);

	  if (storage_fd >= 0)
	    break;  /* GOT IT! */

	  if (errno == EAGAIN || errno == EINTR)
	    continue; /* Retry! */

	  if ((errno == ENOENT) && rw) {
	    for (;;) {
	      storage_fd = open(SHM_SNMPSHAREDFILE_NAME,
#ifdef O_NOFOLLOW
				O_NOFOLLOW |
#endif
				O_CREAT|O_EXCL|O_RDWR ,
				SHM_file_mode);
	      if (storage_fd >= 0)
		break; /* Got it */
	      if (errno == EINTR || errno == EAGAIN)
		continue;
	      break;
	    }
	    /* Now non-negative fd means we have a file.. */
	    if (storage_fd < 0) break;

	    p = calloc(1, block_size);
	    if (!p) {

storage_fill_failure: ;

	      close(storage_fd);
	      eunlink(SHM_SNMPSHAREDFILE_NAME,"-shm-storage-fill-failure-");
	      return; /* FAILURE! */
	    }

	    
	    for ( i = block_size; i > 0; ) {
	      r = write(storage_fd, p, i);
	      if (r > 0) {
		i -= r;
		continue;
	      }
	      if ((r < 0) && (errno == EINTR || errno == EAGAIN))
		continue;
	      /* We have failed at writing! */
	      free(p); /* No longer needed */
	      goto  storage_fill_failure;
	    }
	    free(p); /* No longer needed */

	    /* Successfully filled backing storage */

	    break;

	  }

	  break; /* Other unspecified error! */

	}

	if (storage_fd < 0) {
	  unlink("-shm-storage-open-failure-");
	  return; /* FAILURE! */
	}


	memset( &stbuf, 0, sizeof(stbuf) );
	for (;;) {
	  r = fstat(storage_fd, &stbuf);
	  if (r < 0 && (errno == EINTR || errno == EAGAIN))
	    continue;
	  /* BRR!! BAD !  Can't happen.. Shouldn't... */
	  break;
	}

	if (stbuf.st_size != block_size) {
	  /* NOT PROPER SIZE!  WTF! ??? */
	  close(storage_fd);
	  unlink("-shm-storage-bad-size-");
	  return; /* Bail out! */
	}

	lseek(storage_fd, 0, 0);


	if (rw)
	  p = (void*)mmap(NULL, block_size, PROT_READ|PROT_WRITE,
#ifdef MAP_FILE
			  MAP_FILE|
#endif
			  MAP_SHARED, storage_fd, 0);
	else
	  p = (void*)mmap(NULL, block_size, PROT_READ,
#ifdef MAP_FILE
			  MAP_FILE|
#endif
			  MAP_SHARED, storage_fd, 0);


	if (-1L == (long)p   ||  p == NULL) {
	  perror("mmap() of Shared MIB segment gave error");
	  unlink("-shm-storage-mmap-fail-");
	  return; /* Brr.. */
	}


	MIBMtaEntry = (struct MIB_MtaEntry *)p;

	if (MIBMtaEntry->m.magic == 0)
	  MIBMtaEntry->m.magic = ZM_MIB_MAGIC;

	if (MIBMtaEntry->m.magic != ZM_MIB_MAGIC) {
	  /* AAARRRRGGHHH!!!!  Version disagree! */

	  close(storage_fd);

	  MIBMtaEntry = &MIBMtaEntryLocal;

	  unlink("-shm-storage-version-mismatch-");

	  return;
	}

	/* Ok, MAGIC matches, pointers have been set...
	   Finalize:   */

	SHM_block_size = block_size;
	SHM_storage_fd = storage_fd;
	SHM_block_ptr  = p;

	return;
}
