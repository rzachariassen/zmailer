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

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include <fcntl.h>
#include <errno.h>
#include <time.h>


#include "libc.h"
#include "zmalloc.h"
#include "libz.h"

#include "shmmib.h"

#ifndef HAVE_MMAP
#error "Sorry, support for systems without functional MMAP has not been done yet!"
#endif

extern const char * postoffice;



/* Private static datablock just in case the actual public datablock is
   not available.. Wastes BSS memory, but ... */
static struct MIB_MtaEntry MIBMtaEntryLocal /* = {{0,},{0,}} */;

/* Public pointer to whatever datablock is at hand */
struct MIB_MtaEntry *MIBMtaEntry = &MIBMtaEntryLocal;


static int         SHM_storage_fd = -1;
static const char *SHM_SNMPSHAREDFILE_NAME;
static int         SHM_storage_writable;
static int         SHM_block_size;
static void *      SHM_block_ptr;

int SHM_file_mode = 0664;


long Z_SHM_FileSysFreeSpace __((void))
{
	if (SHM_storage_fd >= 0) {
	  return ( fd_statfs(SHM_storage_fd) / 1024 );
	} else {
	  return ( 2000000 );
	}
}


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

/* Flag telling if we really have shared segment online, or not..
 *   ZERO:     shared segment is not online
 *   Non-zero: shared segment is online
 *   POSITIVE: the segment is writable
 */
int Z_SHM_MIB_is_attached __((void)) {
	if (SHM_block_ptr != NULL && SHM_block_size > 0) {
	  return (SHM_storage_writable ? 1 : -1);
	}
	return 0;
}


/* Lock strategy is simple:
   - File handle associated lock with AUTOMATIC purge at handle close
     (simpler error routines)
   - Only RW mode locks
   - After attachment is verified successfully, lock is released
*/

static void Z_SHM_lock(rw, storage_fd)
     int rw, storage_fd;
{
	int r = errno;
	if (rw) {
	  while (lseek(storage_fd, 0, 0) < 0) {
	    if (errno == EINTR || errno == EAGAIN) continue;
	    perror("Z_SHM_lock lseek(storage_fd,0,0)");
	    errno = r;
	    return;
	  }
#ifdef HAVE_FLOCK
	  while (flock(storage_fd, LOCK_EX) < 0) {
	    if (errno == EINTR || errno == EAGAIN) continue;
	    perror("Z_SHM_lock flock(storage_fd,LOCK_EX)");
	    break;
	  }
#else
#ifdef F_SETLKW
	  for (;;) {
	    int i;
	    struct flock f;
	    f.l_type = F_WRLCK;
	    f.l_whence = 0;
	    f.l_start  = 0;
	    f.l_len    = 0;
	    f.l_pid    = getpid();
	    i = fcntl( storage_fd, SETLKW, &f );
	    if (i == 0) break; /* Ok! */
	    if (i < 0 &&  (errno == EINTR || errno == EAGAIN))
	      continue;
	    perror("Z_SHM_lock fcntl(storage_fd,F_SETLKW,&f)");
	    break;
	  }
#else
#ifdef HAVE_LOCKF
	  while (lockf(storage_fd, F_LOCK, 0) < 0) {
	    if (errno == EINTR || errno == EAGAIN) continue;
	    perror("Z_SHM_lock lockf(storage_fd,F_LOCK,0)");
	    break;
	  }
#else
# warning "No suitable locking code available ??  (LOCKF/FCNTL-SETLKW/LOCKF tried)"
#endif
#endif
#endif
	}
	errno = r;
}

static void Z_SHM_unlock(rw, storage_fd)
     int rw, storage_fd;
{
	int r = errno;
	if (rw) {
	  while (lseek(storage_fd, 0, 0) < 0) {
	    if (errno == EINTR || errno == EAGAIN) continue;
	    perror("Z_SHM_unlock lseek(storage_fd,0,0)");
	    errno = r;
	    return;
	  }
#ifdef HAVE_FLOCK
	  while (flock(storage_fd, LOCK_UN) < 0) {
	    if (errno == EINTR || errno == EAGAIN)
	      continue;
	    perror("Z_SHM_unlock flock(storage_fd, LOCK_UN)");
	    break;
	  }
#else
#ifdef F_SETLKW
	  for (;;) {
	    int i;
	    struct flock f;
	    f.l_type = F_UNLCK;
	    f.l_whence = 0;
	    f.l_start  = 0;
	    f.l_len    = 0;
	    f.l_pid    = getpid();
	    i = fcntl( storage_fd, F_SETLKW, &f );
	    if (i == 0) break; /* Ok! */
	    if (i < 0 &&  (errno == EINTR || errno == EAGAIN))
	      continue;
	    perror("Z_SHM_lock fcntl(storage_fd,F_SETLKW,&f)");
	    break;
	  }
#else
#ifdef HAVE_LOCKF
	  while (lockf(storage_fd, F_ULOCK, 0) < 0) {
	    if (errno == EINTR || errno == EAGAIN)
	      continue;
	    
	    break;
	  }
#endif
#endif
#endif
	}
	errno = r;
}


int Z_SHM_MIB_Attach(rw)
	int rw;
{
	int storage_fd = -1;
	int block_size = sizeof(* MIBMtaEntry);
	struct stat stbuf;
	int retrylimit = 5;

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

	if (!SHM_SNMPSHAREDFILE_NAME) return -1; /* No attach, private data.. */

	for (;;) {
	  if (rw)
	    storage_fd = open(SHM_SNMPSHAREDFILE_NAME, O_RDWR, 0);
	  else
	    storage_fd = open(SHM_SNMPSHAREDFILE_NAME, O_RDONLY, 0);

	  if (storage_fd >= 0) {
	    /* GOT IT!  Now lock.. */

	    Z_SHM_lock(rw, storage_fd);

	    break;
	  }

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
	      if (errno == EEXIST) /* Appeared while we were at it! */
		break;
	      break;
	    }
	    if (storage_fd < 0 && errno == EEXIST && --retrylimit > 0)
	      continue;

	    /* Now non-negative fd means we have a file.. */
	    if (storage_fd < 0) {
	      r = errno;
	      unlink("-shm-storage-excl-create-failure-");
	      errno = r;
	      return -2; /* FAILURE! */
	    }

	    /* if (rw) ... (we do!) */
	    Z_SHM_lock(rw, storage_fd);

	    p = calloc(1, block_size);
	    if (!p) {

storage_fill_failure: ;

	      r = errno;
	      Z_SHM_unlock(rw, storage_fd);
	      close(storage_fd);
	      eunlink(SHM_SNMPSHAREDFILE_NAME,"-shm-storage-fill-failure-");
	      errno = r;
	      return -3; /* FAILURE! */
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
	  /* Including: EACCES, EROFS, EMFILE, ENFILE ... */

	}

	if (storage_fd < 0) {
	  r = errno;
	  unlink("-shm-storage-open-failure-");
	  errno = r;
	  return -4; /* FAILURE! */
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
	  r = errno;
	  Z_SHM_unlock(rw, storage_fd);
	  close(storage_fd);
	  unlink("-shm-storage-bad-size-");
	  errno = r;
	  return -5; /* Bail out! */
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
	  r = errno;
	  perror("mmap() of Shared MIB segment gave error");

	  Z_SHM_unlock(rw, storage_fd);
	  close(storage_fd);

	  unlink("-shm-storage-mmap-fail-");
	  errno = r;
	  return -6; /* Brr.. */
	}


	MIBMtaEntry = (struct MIB_MtaEntry *)p;

	if (MIBMtaEntry->magic == 0) {
	  MIBMtaEntry->magic = ZM_MIB_MAGIC;
	  MIBMtaEntry->BlockCreationTimestamp = time(NULL);
	}

	if (MIBMtaEntry->magic != ZM_MIB_MAGIC) {
	  /* AAARRRRGGHHH!!!!  Version disagree! */

	  r = errno;

#ifdef HAVE_MMAP  /* Remove the mapping */
#ifdef MS_SYNC
	  msync(p, block_size, MS_SYNC);
#endif /* MS_SYNC */
	  munmap(p, SHM_block_size);
#endif /* HAVE_MMAP */

	  Z_SHM_unlock(rw, storage_fd);
	  close(storage_fd);

	  MIBMtaEntry = &MIBMtaEntryLocal;

	  unlink("-shm-storage-version-mismatch-");

	  errno = r;
	  return -7;
	}

	/* Ok, MAGIC matches, pointers have been set...
	   Finalize:   */

	Z_SHM_unlock(rw, storage_fd);

	SHM_block_size       = block_size;
	SHM_storage_fd       = storage_fd;
	SHM_storage_writable = rw;
	SHM_block_ptr        = p;

	return 0;
}
