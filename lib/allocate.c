/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Routines to maintain temporary storage which must be deallocated after
 * each message has been processed. Such storage is typically used in
 * quantities and requested relatively frequently, so the allocation routines
 * should be correspondingly efficient.
 */

#ifdef	MALLOC_TRACE
#undef	MALLOC_TRACE
#endif


#include "mailer.h"
#include "libz.h"

int	embytes = 0;
int	emcalls = 0;
memtypes stickymem = MEM_PERM;
extern int D_alloc;

#if defined(sparc) || defined(__sparc__)
#define NALIGN	8	/* SPARC wants doubles at 8-byte boundary, always!
			   The ZMailer does not use floating point, but
			   that is another story..
			   I think the IBM Power series has some reason
			   to behave like this too -- all machines with
			   64-bit pointers are handled below. */
#else
#if	SIZEOF_VOID_P == 8 /* various 64-bit machines */
#define NALIGN	8	/* bytesize of largest type needing alignment */
#else			/* So, perhaps it is mere 32-bit ? */
#define	NALIGN	4	/* bytesize of largest type needing alignment */
#endif
#endif
static void moremem __((const u_int, const memtypes));

#ifdef ALIGN	/* Some systems (BSD/OS) have ALIGN macro, redefine it! */
# undef ALIGN
#endif

#if	NALIGN == 2 || NALIGN == 4 || NALIGN == 8 || NALIGN == 16
/* if NALIGN is a power of 2, the next line will do ok */
#define	ALIGN(X) (char *)(((u_long)((char *)(X) + (NALIGN-1))) & ~(NALIGN-1))
#else
/* otherwise we need the generic version; hope the compiler isn't too smart */
static int nalign = NALIGN;
#define	ALIGN(X) (char *)((((u_long)((char *)(X) + (NALIGN-1)))/nalign)*nalign)
#endif

#define MALLOC_OVERHEAD	24	/* something just >= malloc overhead */
#define	CLICK_FIRST	15	/* allocate blocks of 2^this to start */
#define	CLICK_FINAL	15	/* malloc larger blocks until 2^this */
#define	CLICK_INCR(X)	(2*(X))	/* how to get to next larger size */
#define	BLOCK_SIZE(X)	((X) - MALLOC_OVERHEAD - (sizeof (struct block)))
#define	BLOCK_WASTE	40	/* "full" blocks have this many free bytes */

struct block {
	struct block	*next;
	char		*endp;		/* one beyond last byte in area */
	char		*cur;		/* current pointer into area */
	char		area[NALIGN];	/* array of 'size' bytes */
};

#define	INBLOCK(BP,A)	((BP)->area <= (A) && (BP)->cur >=/*sic*/ (A))

/*
 * The number of independent block lists.
 */
#ifndef	MEMTYPES
#define MEMTYPES	10
#endif

static struct block *blockhead [MEMTYPES] = { NULL };
static struct block *blockinuse[MEMTYPES] = { NULL };	/* points at tail */
static struct block *blockfull [MEMTYPES] = { NULL };	/* "full" blocks */

static u_long stackmem = 0;	/* bitmap: intend to use block memory as a stack */
				/* NOTE: This limits MEMTYPES to <= 32 !	*/

/*
 * Inline macros for allocating memory
 */
#if 0

#define	GETALIGNED(n,i,cp)	if (blockinuse[(int)(i)] == NULL || \
			    blockinuse[(int)(i)]->cur+(n) >= blockinuse[(int)(i)]->endp) \
					moremem((n), (i)); \
				(cp) = ALIGN(blockinuse[(int)(i)]->cur); \
				blockinuse[(int)(i)]->cur = ((char *)(cp)) + (n)

#define	GETMEMORY(n,i,cp)	if (blockinuse[(int)(i)] == NULL || \
			    blockinuse[(int)(i)]->cur+(n) >= blockinuse[(int)(i)]->endp) \
					moremem((n), (i)); \
				(cp) = blockinuse[(int)(i)]->cur; \
				blockinuse[(int)(i)]->cur += (n)

#else

#define GETALIGNED(n,i,cp) cp = GETALIGNED_((n),(i))

#ifndef __GNUC__
# define __inline
#endif

static __inline void * GETALIGNED_ __((u_int n, u_int i));
static __inline void *
GETALIGNED_(n,i)
u_int n, i;
{
  char *cp;
  if (blockinuse[i] == NULL ||
      blockinuse[i]->cur+ n >= blockinuse[i]->endp)
    moremem(n, i);
  cp = ALIGN(blockinuse[i]->cur);
  blockinuse[i]->cur = cp + n;
  return (void *)cp;
}

#define	GETMEMORY(n,i,cp) cp = GETMEMORY_((n),(i))

static __inline void * GETMEMORY_ __((u_int n, u_int i));
static __inline void *
GETMEMORY_(n,i)
u_int n, i;
{
  char *cp;
  if (blockinuse[i] == NULL ||
      blockinuse[i]->cur+ n >= blockinuse[i]->endp)
    moremem(n, i);
  cp = blockinuse[i]->cur;
  blockinuse[i]->cur += n;
  return (void *)cp;
}
#endif

/*
 * Statistics for calls to moremem()
 */
static int mmcalls  [MEMTYPES];
static int mmmallocs[MEMTYPES];


/*
 * moremem() does what it needs to to make sure blockinuse[i]
 * has enough space to allocate n bytes of data.
 */

static void
moremem(n, i)
	const u_int n;
	register const memtypes i;
{
	register struct block *bp, *bprev;
	register int stackflag;
	static int size[MEMTYPES];
	
	mmcalls[i]++;

	stackflag = (stackmem & (1<<i));
	if (stackflag != 0)
		bp = blockinuse[i];
	else
		bp = blockhead[i];
	/*
	 * See if there's a big enough one
	 */
	for (bprev = NULL; bp != NULL && bp->cur+n >= bp->endp; bp = bp->next)
		bprev = bp;
	if (bp == NULL) {
		mmmallocs[i]++;
#ifndef TMALLOC_DEBUGGING
		if (blockinuse[i] == NULL) {
			size[i] = (1<<CLICK_FIRST);
		} else {
			if (size[i] < (1<<CLICK_FINAL))
				size[i] = CLICK_INCR(size[i]);
		}
		while (size[i] < n)	/* paranoia */
			size[i] = CLICK_INCR(size[i]);
		bp = (struct block *)emalloc((u_int)(size[i] - MALLOC_OVERHEAD));
		bp->cur = &bp->area[0];
		/* this leaves enough slop for alignment */
		bp->endp = &bp->area[BLOCK_SIZE(size[i])];
#else /* TMALLOC_DEBUGGING */
		size[i] = n;
		bp = (struct block *)emalloc(sizeof(struct block) + n + 8);
		bp->cur = &bp->area[8];
		/* this leaves enough slop for alignment */
		bp->endp = &bp->area[ 8 + n ];
#endif
		if (blockinuse[i] == NULL) {
			blockhead[i] = blockinuse[i] = bp;
			bp->next = NULL;
		} else {
			if (stackflag)
				bp->next = blockinuse[i]->next;
			else
				bp->next = NULL;
			blockinuse[i]->next = bp;
			blockinuse[i] = bp;
		}
	} else if (!stackflag) {
		/* We have a big enough block.  Move it to end of list */
		if (bprev == NULL) {		/* first block */
			blockhead[i] = bp->next;
		} else {
			bprev->next = bp->next;
		}
		blockinuse[i]->next = bp;
		blockinuse[i] = bp;
		bp->next = NULL;
	} else /* stack */ {
		/* We have a big enough block.  Make it current */
		/* assert bprev != NULL */
		if (bp != blockinuse[i]->next && bprev != NULL) {
			bprev->next = bp->next;
			bp->next = blockinuse[i]->next;
			blockinuse[i]->next = bp;
		}
		blockinuse[i] = bp;
	}

	if (stackflag)
		return;

	/*
	 * remove blocks with less than BLOCK_WASTE bytes free from
	 * head of active list.  This will help prevent thrashing
	 * trying to fill up the little spaces at the end of blocks
	 * when processing messages with large memory requirements.
	 */
	bp = blockhead[i];
	while (bp->next != NULL && (bp->endp - bp->cur) < BLOCK_WASTE) {
		blockhead[i] = bp->next;
		bp->next = blockfull[i];
		blockfull[i] = bp;
		bp = blockhead[i];
	}
}

#if 0
int
blockmem(memtype, up)
	const int memtype;
	const univptr_t up;
{
	register struct block *bp;

	for (bp = blockhead[memtype]; bp != NULL; bp = bp->next)
	  if (INBLOCK(bp, ((const char*)up)))
	    return 1;
	return 0;
}
#endif

/*
 * malloc() replacement that allocates out of temporary storage.
 */

univptr_t
tmalloc(n)
	const size_t n;
{
	register char *cp;

	if (stickymem == MEM_MALLOC)
		return emalloc(n);
	GETALIGNED(n, stickymem, cp);
	return cp;
}

univptr_t
smalloc(memtype, n)
	const memtypes memtype;
	const size_t n;
{
	register univptr_t cp;

	if (memtype == MEM_MALLOC)
		return emalloc(n);
	GETALIGNED(n, memtype, cp);
	return cp;
}

void
memstats(memtype)
	const memtypes memtype;
{
	struct block *bp;

	for (bp = blockhead[memtype]; bp != NULL; bp = bp->next) {
	  int len;
	  char buf[200];
	  sprintf(buf,"Temp mem %d block (%lX): using %d of %d bytes\n",
		  memtype, (long)bp, (int)(bp->cur - &bp->area[0]),
		  (int)(bp->endp - &bp->area[0] + sizeof(bp->area)));
	  len = strlen(buf);
	  write(2,buf,len); /* STDERR the hard way.. */
	}
}

void
memcontents()
{
	memtypes memtype;

	for (memtype = MEM_PERM; memtype < MEMTYPES ; ++memtype)
	  if (blockhead[memtype])
	    memstats(memtype);
}

/*
 * Free all the temporary space we have allocated so far. Beautifully simple.
 */

void
tfree(memtype)
	const memtypes	memtype;
{
	register struct block *bp, *bpn;

	bp = blockfull[memtype];
	while (bp != NULL) {
	  bpn = bp->next;
	  bp->next = blockhead[memtype];
	  blockhead[memtype] = bp;
	  bp = bpn;
	}
	blockfull[memtype] = NULL;

	if (D_alloc)
	  memstats(memtype);

#ifdef TMALLOC_DEBUGGING
	for (bp = blockhead[memtype]; bp != NULL; bp = bpn) {
	  bpn = bp->next;
	  free(bp);
	}
	blockhead[memtype] = NULL;
#else /* ! TMALLOC_DEBUGGING */
	for (bp = blockhead[memtype]; bp != NULL; bp = bp->next)
	  bp->cur = &bp->area[0];
#endif
	if (D_alloc) {
	  printf("Memory refreshes for %d memory: %d\n",
		 memtype, mmcalls[memtype]);
	  printf("Requiring global memory: %d\n",
		 mmmallocs[memtype]);
	  printf("Total permanent %d memory: %d bytes from %d calls\n",
		 memtype, embytes, emcalls);
	}
	mmcalls[memtype] = mmmallocs[memtype] = 0;
}

/*
 * Return current allocation point and declare that we will use this memory
 * type as a stack (i.e. a setlevel() will be done in the future).
 */

univptr_t
getlevel(memtype)
	const memtypes memtype;
{
	stackmem |= (1<<memtype);
	if (blockinuse[memtype] == NULL)
	  moremem(0, memtype);
	return (univptr_t)blockinuse[memtype]->cur;
}

/*
 * Free part of the space we have allocated so far,
 * then start allocating at the memory address specified.
 */

void
setlevel(memtype, up)
	const memtypes memtype;
	const univptr_t up;
{
	register struct block *bp;
	register const char *s = (const char *) up;
#ifdef TMALLOC_DEBUGGING
	register struct block**bpp;
#endif

	if (!(stackmem & (1<<memtype)) || blockfull[memtype] != NULL) {
	  printf("Memory type %d is not usable as a stack!\n",
		 memtype);
	  return;
	}
#ifdef TMALLOC_DEBUGGING
	for (bpp = & blockhead[memtype]; *bpp != NULL; bpp = &(*bpp)->next) {
	  if (INBLOCK(*bpp, s))
	    break;
	}
	if (*bpp == NULL) {
	  printf("Illegal pointer into %d memory!\n", memtype);
	  return;
	}
	*bpp = NULL;

	bp->cur = (char*) s;
	blockinuse[memtype] = bp;
	for (bp = bp->next; bp != NULL; bp = bp->next)
	  bp->cur = &bp->area[0];

#else /* ! TMALLOC_DEBUGGING */
	if (INBLOCK(blockinuse[memtype], s)) {
	  blockinuse[memtype]->cur = (char*) s;
	} else {
	  for (bp = blockhead[memtype]; bp != NULL; bp = bp->next)
	    if (INBLOCK(bp, s))
	      break;
	  if (bp == NULL) {
	    printf("Illegal pointer into %d memory!\n", memtype);
	    return;
	  }
	  bp->cur = (char*) s;
	  blockinuse[memtype] = bp;
	  for (bp = bp->next; bp != NULL; bp = bp->next)
	    bp->cur = &bp->area[0];
	}
#endif
}


/*
 * Save a string that is n bytes long.
 */

char *
strnsave(s, n)
	const char *s;
	const size_t n;
{
	register char *cp;

	if (stickymem == MEM_MALLOC) {
		cp = emalloc(n+1);
	} else {
		GETMEMORY(n+1, stickymem, cp); /* lengthy macro.. */
	}
	memcpy(cp, s, n);
	*(cp+n) = '\0';
	return cp;
}

/*
 * Save a arbitary long string. (NIL ends)
 */

char *
strsave(s)
	const char *s;
{
	register size_t n = strlen(s);

	return strnsave(s,n);
}
