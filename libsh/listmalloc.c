/*
 * ZMailer router LISPic memory allocator routines by Matti Aarnio
 * <mea@nic.funet.fi>  Copyright 1996, 1998, 1999
 *
 * LISPish memory object allocation routines.  We keep  conscells  in
 * bucket arrays for ease of finding them for the Deutch-Schorr-Waite
 * garbage collector (and to minimize malloc overheads..)
 */

#include "hostenv.h"
#include "listutils.h"

#ifdef CELLDEBUG
#define DEBUG
#endif

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
    conscell **vars[1];		/* Address of an variable */
} consvarptrs;
#endif


#define NSTATICVARS 16 /* SHOULD be enough for ZMailer...  */
static conscell **staticvec[NSTATICVARS] = { NULL };
static int staticidx = 0;

static void (*functionvec[NSTATICVARS])() = { NULL };
static int functionidx = 0;

/* Put an entry in staticvec, pointing at the variable
   whose address is given */

void staticprot (varaddress)
conscell **varaddress;
{
	staticvec[staticidx++] = varaddress;
	if (staticidx >= NSTATICVARS)
	  abort (); /* TOO MANY!  Should need only very few.. */
}

void functionprot (funcaddress)
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
long consvars_cursor = 0;	/* How many variables are in use ?
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
    new->cells[0].flags = DSW_FREEMARK;
    for (i = 1; i < consblock_cellcount; ++i) {
	new->cells[i].next = &new->cells[i - 1];
	new->cells[i].flags = DSW_FREEMARK;
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
  printf ("consvar_marker() returns %p\n", (void*)consvars_cursor);
#endif
    return (void *)consvars_cursor;
}

void consvar_release(marker)
void *marker;
{
    long newmark = (long) marker;

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
    while (consvars_markptr && newmark < consvars_markptr->first) {
	consvars_markptr = consvars_markptr->nextvars;
    }
}


/* ConsCell variable pointer registry */
int consvar_register(varptr)
     conscell **varptr;
{
    int marklast, idx;

#ifdef DEBUG
    printf("consvar_register(varptr=%p)\n", varptr);
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
static void cons_DSW __((conscell *source));

#define DSW_MASK  (DSW_MARKER | DSW_BACKPTR)

#define DSW_BLOCKLEFT(cptr)	\
		(((cptr)->flags & ~DSW_MASK) || ((cptr)->dtpr == NULL))

#define DSW_BLOCKRIGHT(cptr)	\
		((cptr)->next == NULL)
#define DSW_BLOCK(cptr)		\
		(((cptr)->flags & DSW_MARKER) ||	\
		 (DSW_BLOCKLEFT(cptr) && DSW_BLOCKRIGHT(cptr)))

/*static*/ void cons_DSW_rotate __((conscell **, conscell **, conscell **));
/*static*/ void cons_DSW_rotate(pp1, pp2, pp3)
conscell **pp1, **pp2, **pp3;
{
    conscell *t1, *t2, *t3;

#ifdef DEBUG
    printf("cons_DSW_rotate(%p, %p, %p)\n", pp1, pp2, pp3);
#endif


    t1 = *pp1;
    t2 = *pp2;
    t3 = *pp3;
    *pp1 = t2;
    *pp2 = t3;
    *pp3 = t1;
}

int deepest_dsw = 0;

static void _cons_DSW(source, depth)
volatile conscell *source;
int depth;
{
	/* Use stack to descend CAR, scan thru CDR.
	   The trick is that there should not be deep
	   layers in the CAR branch (a sign of error
	   in fact if there are!), but CDR can be long. */

	conscell *current = (conscell*)source;
	volatile int cdrcnt = 0; /* These volatilities are for
				    debugging uses to forbid gcc
				    from removing the variable
				    as unnecessary during its
				    lifetime.. */

	if (depth > deepest_dsw)
		deepest_dsw = depth;
	if (depth > 20) *(long*)0 = 0; /* ZAP! */
	while (current && !(current->flags & DSW_MARKER)) {
		current->flags |= DSW_MARKER;
		if (!STRING(current))
			_cons_DSW(car(current),depth+1);
		current = cdr(current);
		++cdrcnt;
	}
}

static void cons_DSW(source)
conscell *source;
{
#if 1 /* Use stack to descend CAR, scan thru CDR */

  _cons_DSW(source,1);

#else /* --- pure DSW -- with problems ---- */
    conscell *current, *previous, *next;
    int done;

#if 0
#ifdef DEBUG
    printf("cons_DSW(source=%p)\n", source);
#endif
#endif


    current = source;
    previous = NULL;
    done = 0;

    while (!done) {
      /* Follow left pointers */
      while ((current != NULL) &&
	     !(current->flags & DSW_MARKER)) {
	current->flags |= DSW_MARKER;
	if (LIST(current)) {
	  next = car(current);
	  car(current) = previous;
	  previous = current;
	  current = next;
	}
      }
      /* retreat */
      while ((previous != NULL) &&
	     (current->flags & DSW_BACKPTR)) {
	current->flags &= ~DSW_BACKPTR;
	next = cdr(previous);
	cdr(previous) = current;
	current = previous;
	previous = next;
      }
      if (!previous)
	done = 1;
      else {
	/* Switch to right subgraph */
	previous->flags |= DSW_BACKPTR;
	next = car(previous);
	car(previous) = current;
	current = cdr(previous);
	cdr(previous) = next;
      }
    }

#if 0 /* OLD CODE -- OLD CODE -- OLD CODE */
    while (state != 0) {
	switch (state) {
	case 1:
#ifdef DEBUG
	      printf("DEBUG: 1: %p ",current);
#endif
	    /* Mark in every case 
	    current->flags |= DSW_MARKER; */
	    /* Try to advance */
	    if (DSW_BLOCK(current)) {
		/* Prepare to retreat */
	        current->flags |= DSW_MARKER;
		state = 2;
		printf("prepare to retreat\n");
#ifdef DEBUG
		printf("%d ", DSW_BLOCKLEFT(current));
		printf("%d ", DSW_BLOCKRIGHT(current));
		printf("%d\n", DSW_BLOCK(current));
#endif
	    } else {
	        /* Advance */
	        current->flags |= DSW_MARKER;
		if (DSW_BLOCKLEFT(current)) {
#ifdef DEBUG
		    printf("adv. right\n");
#endif
		    /* Follow right (next) pointer */
		    current->flags &= ~DSW_BACKPTR; /* back == right */
		    cons_DSW_rotate(&prev, &current, &current->next);
		} else {
#ifdef DEBUG
		    printf("adv. left\n");
#endif
		    /* Follow left (dtpr) pointer */
		    current->flags |= DSW_BACKPTR; /* back == lext */
		    cons_DSW_rotate(&prev, &current, &current->dtpr);
		}
	    }
	    break;
	case 2:
#ifdef DEBUG
	    printf("DEBUG: 2: %p ",current);
#endif
	    /* Finish, retreat or switch */
	    if (current == prev) {
		/* Finish */
		state = 0;
#ifdef DEBUG
		printf("finish\n");
#endif
	    }
	    else if ((prev->flags & DSW_BACKPTR)  /* prev.back == L */
		     && (!DSW_BLOCKRIGHT(prev))) {
	        /* Switch */
#ifdef DEBUG
		printf("switch\n");
#endif
	        prev->flags &= ~DSW_BACKPTR; /* prev.back = R */
		cons_DSW_rotate(&prev->dtpr, &current, &prev->next);
		state = 1;
	    } else if (!(prev->flags & DSW_BACKPTR)) { /* prev.back == R*/
	        /* Retreat */
#ifdef DEBUG
		printf("retreat R\n");
#endif
	        cons_DSW_rotate(&prev, &prev->next, &current);
	    } else { /* prev.back == L */
#ifdef DEBUG
		printf("retreat L\n");
#endif
	        cons_DSW_rotate(&prev, &prev->dtpr, &current);
	    }
	    break;
	default:
	    break;
	}
    }
#endif
#endif
}

int cons_garbage_collect()
{
    int i, freecnt, usecnt, newfreecnt;
    consblock *cb = NULL;
    conscell *cc, **freep;
    struct gcpro *gcp;
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
#ifdef PURIFY  /* Turn on for 'Purify' testing... */
	  if (cc->flags & (DSW_MARKER|DSW_BACKPTR))
#endif
	    cc->flags &= ~(DSW_MARKER|DSW_BACKPTR);
    }

    /* Hookay...  Now we run marking on all cells that are
       reachable from some (any) of our registered variables */
    /* Static variables */
    for (i = 0; i < staticidx; ++i)
      if (*staticvec[i] != NULL) {
#ifdef DEBUG_xx
	fprintf(stderr," cons_DSW(STATIC->%p)\n",*staticvec[i]);
#endif
	cons_DSW(*staticvec[i]);
      }
    /* Function-format iterators */
    for (i = 0; i < functionidx; ++i)
      if (*functionvec[i] != NULL)
	functionvec[i](cons_DSW);
    
    /* Dynamically inserted (and removed) GCPROx() -variables */
    gcp = gcprolist;
    while (gcp) {
#ifdef DEBUG_xx
      fprintf(stderr," cons_DSW(gcp-> %p )\n",gcp);
#endif
      for (i= 0; i < gcp->nvars; ++i) {
	if (*(gcp->var[i])) {
#ifdef DEBUG_xx
	  fprintf(stderr," cons_DSW(GCPRO->%p)\n",*(gcp->var[i]));
#endif
	  cons_DSW(*(gcp->var[i]));
	}
      }
      gcp = gcp->next;
    }
    
#ifndef NO_CONSVARS
    cursor = 0;
    for (vb = consvars_root; vb != NULL; vb = vb->nextvars) {
      for (i = 0; i < vb->count; ++i,++cursor) {
	if (cursor < consvars_cursor) {
	  if (vb->vars[i] != NULL) {
#ifdef DEBUG
	    fprintf(stderr," cons_DSW(consvar->%p)\n",*(vb->vars[i]));
#endif
	    cons_DSW(*(vb->vars[i]));
	  }
	} else
	  break;
      }
    }
#endif


    /* All are marked.. now we can scan all non-marked, and declare
       them to belong into free..   Oh yes, all  ISNEW(cellptr)  cells
       will do  free(cellptr->string)    */

    freep = & conscell_freechain;
    usecnt = freecnt = newfreecnt = 0;
    for (cb = consblock_root; cb != NULL; cb = cb->nextblock) {
	cc = cb->cells;
	for (i = 0; i < cb->cellcount; ++i,++cc)
	    if (cc->flags & DSW_MARKER) {

		/* It was reachable, just clean the marker bit(s) */

		cc->flags &= ~(DSW_MARKER | DSW_BACKPTR);
		++usecnt;

	    } else {

		/* This was not reachable, no marker was added.. */
		if (ISNEW(cc)) {   /* if (cc->flags & NEWSTRING) */
#ifdef DEBUG
		    fprintf(stderr," freestr(%p) cell=%p called from %p s='%s'\n",cc->string,cc,__builtin_return_address(0), cc->string);
#endif
		    freestr(cc->string);
		    cc->string = NULL;
		}
		if (!(cc->flags & DSW_FREEMARK)) {
#ifdef DEBUG
		  fprintf(stderr," freecell(%p)\n",cc);
#endif
		  ++newfreecnt;
		}
		cc->flags = DSW_FREEMARK;

		/* Forward-linked free cell list */
		*freep = cc;
		freep = &cc->next;
		++freecnt;
	    }
    }
    *freep = NULL;
#ifdef DEBUG
    fprintf(stderr,"cons_garbage_collect() freed %d, found %d free, and %d used cells\n",
	    newfreecnt, freecnt-newfreecnt, usecnt);
#endif
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
    if (++newcell_gc_callcount >= newcell_gc_interval) {
      cons_garbage_collect();
      newcell_gc_callcount = 0;
    }

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
    new->flags = 0;
#else
    memset(new, 0, sizeof(*new));
#endif
#ifdef DEBUG
    fprintf(stderr," newcell() returns %p to caller at %p\n", new,
	    __builtin_return_address(0));
#endif
    return new;
}

#ifdef DEBUG_MAIN		/* We test the beast... */
int main(argc, argv)
int argc;
char *argv[];
{
    int i;
    conscell *newc, *tmp;
    conscell *rootcell;
    GCVARS1;

    newcell_gc_interval = 3;

    rootcell = conststring("const-string");
#if 0
    GCPRO1(rootcell);
    printf("rootcell @ %p cell %p\n",&rootcell, rootcell);
#else
#ifndef NO_CONSVARS
    consvar_register(&rootcell);
    printf("consvars_cursor = %ld\n", consvars_cursor);
#endif
#endif

    for (i = 0; i < 30; ++i) {
      newc = conststring("subconst");
      newc->next = rootcell->next;
      rootcell->next = newc;
    }

    cons_garbage_collect();
    rootcell = NULL;
    /* UNGCPRO1; */
    cons_garbage_collect();

    return 0;
}
#endif

#ifndef copycell
conscell *copycell(conscell *X)
{
  conscell *tmp = newcell();
  *tmp = *X;
  if (STRING(tmp)) {
    tmp->string = dupstr(tmp->string);
    tmp->flags = NEWSTRING;
  }
  return tmp;
}
#endif
#ifndef nconc
/* nconc(list, list) -> old (,@list ,@list) */
conscell *nconc(conscell *X, conscell *Y)
{
  return ((car(X) != NULL) ?
	  cdr(s_last(car(X))) = Y :
	  (car(X) = Y, X));
}
#endif
#ifndef ncons
conscell *ncons(conscell *X)
{
  conscell *tmp = newcell();
  car(tmp) = X;
  tmp->flags = 0;
  cdr(tmp) = NULL;
  return tmp;
}
#endif
#ifndef cons
/* cons(s-expr, list) -> new (s-expr ,@list) */
conscell *cons(conscell *X, conscell* Y)
{
  conscell *tmp = ncons(X);
  cdar(tmp) = Y;
  return tmp;
}
#endif
#ifndef s_push
/* s_push(s-expr, list) -> old (s-expr ,@list) */
conscell *s_push(conscell *X, conscell* Y)
{
  cdr(X) = car(Y);
  car(Y) = X;
  return Y;
}
#endif
#ifndef newstring
conscell *newstring(char *s)
{
  conscell *tmp = newcell();
  tmp->string = s;
  tmp->flags = NEWSTRING;
  cdr(tmp) = NULL;
  return tmp;
}
#endif
#ifndef conststring
conscell *conststring(const char *s)
{
  conscell *tmp = newcell();
  tmp->cstring = s;
  tmp->flags = CONSTSTRING;
  cdr(tmp) = NULL;
  return tmp;
}
#endif


/* ********************************************************
 *
 *   STRING MALLOC ROUTINES:  DUPSTR(), DUPNSTR(), FREESTR()
 *
 * ******************************************************** */

const static int  strmagic = 0x53545200; /* 'STR\0' */

char *dupnstr(str,len)
     const char *str;
     const int len;
{
  char *p = malloc((len+5+1 +7) & ~7); /* XX: DEBUG MODE! */
  int *ip = (int*)p;

  if (!p) return p; /* NULL */
  p += 5;		/* Alignment OFF even bytes for debugging
			   of string element misuses in conscells. */
  memcpy(p, str, len);
  p[len] = 0;
  *ip = strmagic;
#ifdef DEBUG
  fprintf(stderr," dupnstr() returns %p to caller at %p\n", p,
	  __builtin_return_address(0));
#endif
  return (p);
}

#ifndef dupstr
char *dupstr(str)
const char *str;
{
  int slen = strlen(str);

  return dupnstr(str,slen);
}
#endif

void freestr(str)
     const char *str;
{
  char *p = (char*)str;
  int *ip = (int*)(p - 5);

  if (*ip != strmagic) *(int*)0L = 0; /* ZAP! */

  free(ip);
}

