/*
 * ZMailer router LISPic memory allocator routines by Matti Aarnio
 * <mea@nic.funet.fi>  Copyright 1996
 *
 * LISPish memory object allocation routines.  We keep  conscells  in
 * bucket arrays for ease of finding them for the Deutch-Schorr-Waite
 * garbage collector (and to minimize malloc overheads..)
 */

#include "hostenv.h"
#include "listutils.h"

#ifndef __GNUC__x
#define __inline__ /* nothing for non-GCC */
#endif

/*
 * We allocate conscells in set of blocks, where we do garbage collections
 * at every N requests, or other trigger criteria..
 * Strings are allocated with malloc(), and explicitely freed at garbage
 * collection of unused cells.
 * Free cells are collected into a chain of free cells (via next ptr),
 * from which they are picked into use.
 */
typedef struct consblock {
    struct consblock *nextblock;
    int cellcount;
#ifdef __alpha /* Align the conscells by cache-line.. */
	void *dummy1;
	void *dummy2;
#endif
    conscell cells[1];		/* Array of ``cellcount'' cells */
} consblock;

#ifndef NO_CONSVARS
/*
 * Variable pointers -- arrays of pointers to conscells
 */
typedef struct consvarptrs {
    struct consvarptrs *nextvars;
    int count;			/* large (?) sets of vars */
    int first;			/* this block has vars of indices
				   ``first .. first+count-1'' */
    const conscell *vars[1];	/* Address of an variable */
} consvarptrs;
#endif


#define NSTATICVARS 16 /* SHOULD be enough for ZMailer...  */
static conscell **staticvec[NSTATICVARS] = { NULL };
static int staticidx = 0;

static void (*functionvec[NSTATICVARS])() = { NULL };
static int functionidx = 0;

/* Put an entry in staticvec, pointing at the variable
   whose address is given */

void staticpro (varaddress)
conscell **varaddress;
{
	staticvec[staticidx++] = varaddress;
	if (staticidx >= NSTATICVARS)
	  abort (); /* TOO MANY!  Should need only very few.. */
}

void functionpro (funcaddress)
void (*funcaddress) __((conscell *));
{
	functionvec[functionidx++] = funcaddress;
	if (functionidx >= NSTATICVARS)
	  abort();  /* TOO MANY!  Should need only very few.. */
}


/*
 * Some book-keeping variables, and one of GC-trigger counters
 */
int consblock_cellcount = 1000;	/* Optimizable for different systems.
				   Alphas have 8kB pages, and most others
				   have 4kB pages.. */
int newcell_gc_interval = 1000;	/* Number of newcell() calls before GC */
int newcell_gc_callcount = 0;	/* ... trigger-count of those calls ... */
int newcell_callcount = 0;	/* ... cumulative count of those calls ... */

consblock *consblock_root = NULL;
consblock *consblock_tail = NULL;
conscell *conscell_freechain = NULL;	/* pick first .. */
int consblock_count = 0;	/* How many allocated ? */

struct gcpro *gcprolist = NULL;	/* Dynamically growing list of protected
				   items.. */
#ifndef NO_CONSVARS
int consvars_cellcount = 4000;
consvarptrs *consvars_root = NULL;
consvarptrs *consvars_tail = NULL;
int consvars_cursor = 0;	/* How many variables are in use ?
				   Actually NOT direct pointer, and
				   the user might have to traverse
				   the chains a bit at first.. */
consvarptrs *consvars_markptr = NULL;	/* For speedier insert */
int consvars_count = 0;		/* Allocation count */
#endif

static consblock *new_consblock __((void));
static consblock *new_consblock()
{
    consblock *new;
    int i;
    int newsize = (sizeof(consblock) +
		   sizeof(conscell) * (consblock_cellcount - 1));

#ifdef DEBUG
    printf("new_consblock(%d cells)\n", consblock_cellcount);
#endif

    new = (consblock *) malloc(newsize);
    if (!new)
	return NULL;

    memset(new, 0, newsize); /* Sigh.. */

    new->cellcount = consblock_cellcount;
    new->nextblock = NULL;
    if (consblock_root == NULL)
	consblock_root = new;
    else
	consblock_tail->nextblock = new;
    consblock_tail = new;

    /* chain them together, and prepend to the free chain via ``next'' */
    new->cells[0].next = conscell_freechain;
    new->cells[0].flags = 0;
    for (i = 1; i < consblock_cellcount; ++i) {
	new->cells[i].next = &new->cells[i - 1];
	new->cells[i].flags = 0;
    }
    conscell_freechain = &new->cells[consblock_cellcount - 1];

    ++consblock_count;
    return new;
}

#ifndef NO_CONSVARS
static consvarptrs *new_consvars __((int));
static consvarptrs *new_consvars(first)
int first;
{
    consvarptrs *new;
    int newsize = (sizeof(consvarptrs) +
		   sizeof(conscell *) * (consvars_cellcount - 1));

#ifdef DEBUG
    printf("new_consvars(first=%d; %d varcells)\n", first, consvars_cellcount);
#endif

    new = (consvarptrs *) malloc(newsize);
    if (!new)
	return NULL;

    new->first = first;
    new->count = consvars_cellcount;
    new->nextvars = NULL;
    if (consvars_root == NULL) {
	consvars_root = new;
	consvars_markptr = new;
    } else
	consvars_tail->nextvars = new;
    consvars_tail = new;
    ++consvars_count;
    return new;
}

void *consvar_mark()
{
#ifdef DEBUG
  printf ("consvar_marker() returns 0x%p\n", (void*)consvars_cursor);
#endif
    return (void *) consvars_cursor;
}

void consvar_release(marker)
void *marker;
{
    int newmark = (int) marker;

    if (newmark > consvars_cursor) {
	abort();    /* XX: Something seriously wrong, release INCREASED
		       the count of variables! */
    }
    consvars_cursor = newmark;
    --newmark;	   /* change into index -- from counter (sort of) */

    if (consvars_markptr == NULL)
	return;	   /* no cells ? */

    if ((consvars_markptr->first <= newmark) &&
	(newmark < (consvars_markptr->first + consvars_markptr->count)))
	return;	   /* The markptr is ok */

    /* Lookup for the block marker */
    consvars_markptr = consvars_root;
    while (newmark < consvars_markptr->first) {
	consvars_markptr = consvars_markptr->nextvars;
    }
}


/* ConsCell variable pointer registry */
int consvar_register(varptr)
const conscell *varptr;
{
    int marklast, idx;

#ifdef DEBUG
    printf("consvar_register(varptr=0x%p)\n", varptr);
#endif

    if (consvars_root == NULL) {
	if (new_consvars(0) == NULL)
	    return -1;
	consvars_cursor = 0;
    }
    marklast = (consvars_markptr->first +
		consvars_markptr->count);
    ++consvars_cursor;
    if (marklast <= consvars_cursor) {
	if (consvars_markptr->nextvars == NULL)
	    consvars_markptr = new_consvars(marklast	/* the previous last is
							   the next first.. */ );
	else
	    consvars_markptr = consvars_markptr->nextvars;
	if (consvars_markptr == NULL)
	    return -1;
    }
    idx = (consvars_cursor - 1) - consvars_markptr->first;
    consvars_markptr->vars[idx] = varptr;
    return 0;			/* Stored ok.. */
}
#endif

/*
 *  Deutch-Schorr-Waite garbage collection routine of the conscells..
 *
 */
static void cons_DSW();

#define DSW_MASK  (DSW_MARKER | DSW_BACKPTR)

#define DSW_BLOCKLEFT(cptr)	\
		(((cptr)->flags & ~DSW_MASK) || ((cptr)->dtpr == NULL))

#define DSW_BLOCKRIGHT(cptr)	\
		((cptr)->next == NULL)
#define DSW_BLOCK(cptr)		\
		(((cptr)->flags & DSW_MARKER) ||	\
		 (DSW_BLOCKLEFT(cptr) && DSW_BLOCKRIGHT(cptr)))

/*static*/ void cons_DSW_rotate(pp1, pp2, pp3)
conscell **pp1, **pp2, **pp3;
{
    conscell *t1, *t2, *t3;

#ifdef DEBUG
    printf("cons_DSW_rotate(0x%x, 0x%x, 0x%x)\n", pp1, pp2, pp3);
#endif


    t1 = *pp1;
    t2 = *pp2;
    t3 = *pp3;
    *pp1 = t2;
    *pp2 = t3;
    *pp3 = t1;
}

/*static*/ void cons_DSW(source)
conscell *source;
{
    conscell *current, *prev;
    int state;

#if 0
#ifdef DEBUG
    printf("cons_DSW(source=0x%x)\n", (void*)source);
#endif
#endif


    if(source == NULL)
      return;
    if(source->next == NULL)
      return;

    current = source->next;
    prev = source;
    /* source->flags.back = 'next' -- current backptr value */
    source->flags  &=  ~DSW_BACKPTR; /* Source back == right */
    source->next = source; /* !! */
    source->flags  |=   DSW_MARKER;


    state = 1;
    while (state != 0) {
	switch (state) {
	case 1:
	    if(DEBUG)
	      printf("DEBUG: 1: ");
	    /* Mark in every case 
	    current->flags |= DSW_MARKER; */
	    /* Try to advance */
	    if (DSW_BLOCK(current)) {
		/* Prepare to retreat */
	        current->flags |= DSW_MARKER;
		state = 2;
		printf("prepare to retreat\n");

		if(DEBUG) {
		  printf("%d ", DSW_BLOCKLEFT(current));
		  printf("%d ", DSW_BLOCKRIGHT(current));
		  printf("%d\n", DSW_BLOCK(current));
		}
	    } else {
	        /* Advance */
	        current->flags |= DSW_MARKER;
		if (DSW_BLOCKLEFT(current)) {
		    if(DEBUG)
		      printf("adv. right\n");		    
		    /* Follow right (next) pointer */
		    current->flags &= ~DSW_BACKPTR; /* back == right */
		    cons_DSW_rotate(&prev, &current, &current->next);
		} else {
		    if(DEBUG)
		      printf("adv. left\n");
		    /* Follow left (dtpr) pointer */
		    current->flags |= DSW_BACKPTR; /* back == lext */
		    cons_DSW_rotate(&prev, &current, &current->dtpr);
		}
	    }
	    break;
	case 2:
	    printf("DEBUG: 2: ");
	    /* Finish, retreat or switch */
	    if (current == prev) {
		/* Finish */
		state = 0;
		if(DEBUG)
		  printf("finish\n");
	    }
	    else if ((prev->flags & DSW_BACKPTR)  /* prev.back == L */
		     && (!DSW_BLOCKRIGHT(prev))) {
	        /* Switch */
	        if(DEBUG)
		  printf("switch\n");
	        prev->flags &= ~DSW_BACKPTR; /* prev.back = R */
		cons_DSW_rotate(&prev->dtpr, &current, &prev->next);
		state = 1;
	    } else if (!(prev->flags & DSW_BACKPTR)) { /* prev.back == R*/
	        /* Retreat */
	        if(DEBUG)
		  printf("retreat R\n");
	        cons_DSW_rotate(&prev, &prev->next, &current);
	    }
	    else { /* prev.back == L */
	        if(DEBUG)
		  printf("retreat L\n");
	        cons_DSW_rotate(&prev, &prev->dtpr, &current);
	    }
	    break;
	default:
	    break;
	}
    }
}

int cons_garbage_collect()
{
    int i, freecnt;
    consblock *cb = NULL;
    conscell *cc;
    struct gcpro *gcp = gcprolist;
#ifndef NO_CONSVARS
    int cursor;
    consvarptrs *vb = NULL;
#endif


    if (consblock_root == NULL)
	return 0;		/* Nothing to do! */

    /* Start by clearing all DSW_MARKER bits */
    for (cb = consblock_root; cb != NULL; cb = cb->nextblock) {
	cc = cb->cells;
	for (i = 0; i < cb->cellcount; ++i, ++cc)
#if 0  /* Turn on for 'Purify' testing... */
	  if (cc->flags & (DSW_MARKER|DSW_BACKPTR))
#endif
	    cc->flags &= ~(DSW_MARKER|DSW_BACKPTR);
    }

    /* Hookay...  Now we run marking on all cells that are
       reachable from some (any) of our registered variables */
    /* Static variables */
    for (i = 0; i < staticidx; ++i)
      if (*staticvec[i] != NULL)
	cons_DSW(*staticvec[i]);
    /* Function-format iterators */
    for (i = 0; i < functionidx; ++i)
      if (*functionvec[i] != NULL)
	functionvec[i](cons_DSW);
    
    /* Dynamically inserted (and removed) GCPROx() -variables */
    while (gcp) {
      for (i= 0; i < gcp->nvars; ++i)
	cons_DSW(gcp->var[i]);
      gcp = gcp->next;
    }
    
#ifndef NO_CONSVARS
    cursor = 0;
    for (vb = consvars_root; vb != NULL; vb = vb->nextvars) {
      for (i = 0; i < vb->count; ++i,++cursor) {
	if (cursor < consvars_cursor) {
	  if (vb->vars[i] != NULL)
	    cons_DSW(*(vb->vars[i]));
	} else
	  break;
      }
    }
#endif


    /* All are marked.. now we can scan all non-marked, and declare
       them to belong into free..   Oh yes, all  ISNEW(cellptr)  cells
       will do  free(cellptr->string)    */

    conscell_freechain = NULL;
    freecnt = 0;
    for (; cb != NULL; cb = cb->nextblock) {
	cc = cb->cells;
	for (i = 0; i < cb->cellcount; ++i)
	    if (cc->flags & DSW_MARKER) {

		/* It was reachable, just clean the marker bit(s) */

		cc->flags &= ~(DSW_MARKER | DSW_BACKPTR);

	    } else {

		/* This was not reachable, no marker was added.. */
	        if (ISNEW(cc))   /* if (cc->flags & NEWSTRING) */
		    free(cc->string);
		cc->flags = 0;

		/* this resulting list is ``reversed'' in memory order,
		   however that should not cause any trouble anyway.. */

		cc->next = conscell_freechain;
		conscell_freechain = cc;
		++freecnt;
	    }
    }
    return freecnt;
}



/*
 * Actual heart of this all:  Allocate the conscell!
 */
conscell *
 newcell()
{
    conscell *new;

    /* At first, see if we are to do some GC ... */

#ifdef DEBUG
    printf("newcell() called\n");
#endif

    ++newcell_callcount;
    if (++newcell_gc_callcount >= newcell_gc_interval)
	cons_garbage_collect();

    /* Ok, if we were lucky, we got free cells from GC,
       or had them otherwise.. */

    if (conscell_freechain == NULL)
	if (new_consblock() == NULL)
	    if (cons_garbage_collect() == 0) {
		/* XX: Unable to allocate memory, nor any freeable!
		   Print something, and abort ? */
		return NULL;
	    }

    /* Ok, the devil is at loose now, if we don't have at least ONE cell
       in the free chain now..  We do NOT store anything into flags, or
       other fields of the structure -- to help memory access checkup
       routines, like Purify, or DEC OSF/1 ATOM Third-Degree */

    new = conscell_freechain;
    conscell_freechain = new->next;
#if 0
    new->next = NULL;
#else
    memset(new, 0, sizeof(*new));
#endif
#ifdef DEBUG
    printf(" ... returns 0x%p\n", new);
#endif
    return new;
}

#ifdef DEBUG			/* We test the beast... */
int main(argc, argv)
int argc;
char *argv[];
{
    int i;
    conscell *newc, *tmp;
    conscell *rootcell;

    newcell_gc_interval = 3;

    rootcell = conststring("const-string");
#ifndef NO_CONSVARS
    consvar_register(rootcell);
#endif

    for (i = 0; i < 30; ++i) {
      newc = conststring("subconst");
      newc->next = rootcell->next;
      rootcell->next = newc;
    }

    return 0;
}
#endif
