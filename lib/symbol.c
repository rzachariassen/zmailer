/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Symbol routine: it maps an arbitrary string into a unique key
 * that can be used as an index into various tables.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/types.h>

#include "splay.h"
#include "malloc.h"
#include "libz.h"

#ifdef	symbol
#undef	symbol
#endif	/* symbol */

#undef _USE_CRC
#define _USE_CRC 0

#if _USE_CRC
/* crc table and hash algorithm from pathalias */
/*
 * fold a string into a long int.  31 bit crc (from andrew appel).
 * the crc table is computed at run time by crcinit() -- we could
 * precompute, but it takes 1 clock tick on a 750.
 *
 * This fast table calculation works only if POLY is a prime polynomial
 * in the field of integers modulo 2.  Since the coefficients of a
 * 32-bit polynomail won't fit in a 32-bit word, the high-order bit is
 * implicit.  IT MUST ALSO BE THE CASE that the coefficients of orders
 * 31 down to 25 are zero.  Happily, we have candidates, from
 * E. J.  Watson, "Primitive Polynomials (Mod 2)", Math. Comp. 16 (1962):
 *      x^32 + x^7 + x^5 + x^3 + x^2 + x^1 + x^0
 *      x^31 + x^3 + x^0
 *
 * We reverse the bits to get:
 *      111101010000000000000000000000001 but drop the last 1
 *         f   5   0   0   0   0   0   0
 *      010010000000000000000000000000001 ditto, for 31-bit crc
 *         4   8   0   0   0   0   0   0
 */

#define POLY32 0xf5000000       /* 32-bit polynomial */
#define POLY31 0x48000000       /* 31-bit polynomial */
#define POLY POLY31     /* use 31-bit to avoid sign problems */

static long CrcTable[128];

static void crcinit __((void));
static void
crcinit()
{       
	register int i,j;
	register long sum;

	for (i = 0; i < 128; i++) {
		sum = 0;
		for (j = 7-1; j >= 0; --j)
			if (i & (1 << j))
				sum ^= POLY >> j;
		CrcTable[i] = sum;
	}
}

#else

/*
 *  Modified PJW-hash
 */

unsigned long pjwhash32(ptr)
     register const unsigned char *ptr;
{
  register unsigned long hash, tmp;
  if (!ptr)
    return (~0);
    for (hash = 0; *ptr; ptr++) {
      hash <<= 4;
      hash += *ptr;
      /*
       *  On 32-bit systems the following
       *  AND-operation will be equal to
       *      hash & 0xf0000000
       *  but will automatically adapt
       *  also to larger implementations
       *  of "unsigned long" than the
       *  32 bits for which this code was
       *  originally designed preserving
       *  exactly the same results also
       *  on e.g. 64-bit systems.
       */
      if ((tmp = (hash & ~0x0fffffffL))) {
	hash ^= tmp >> 24;
	hash ^= tmp;
	/* Clear the high bits - fast! */
      }
    }
    return (hash);
    /* Must be divided by a prime! */
}
#endif

struct syment {
	const char    *name;
	struct syment *next;
};

struct sptree *spt_symtab = NULL;

spkey_t
symbol(s)
	const void *s;
{
	if (spt_symtab == NULL)
		spt_symtab = sp_init();
	return symbol_db(s, spt_symtab);
}

spkey_t
symbol_lookup(s)
	const void *s;
{
	if (spt_symtab == NULL)
		spt_symtab = sp_init();
	return symbol_lookup_db(s, spt_symtab);
}

spkey_t
symbol_lookup_db(s, spt)
	const void *s;
	struct sptree *spt;
{
	register const char *ucp;
	register spkey_t key;
	register struct syment *se, *pe;
	struct spblk *spl;

	if (s == NULL)
		return 0;

#if _USE_CRC
	/* Input string is to be CRCed to form a new key-id */
	key = 0;
	for (ucp = s; *ucp != '\0'; ++ucp)
		key = (key >> 7) ^ CrcTable[(key ^ *ucp) & 0x7f];
#else
	key = pjwhash32(s);
#endif

	/* Ok, time for the hard work.  Lets see if we have this key
	   in the symtab splay tree */

	pe = NULL;
	spl = sp_lookup(key, spt);
	if (spl != NULL) {
		/* Got it !  Now see that we really have it, and
		   not only have a hash collision */

		se = (struct syment *)spl->data;
		do {
			if (strcmp(se->name, s) == 0) {
				/* Really found it! */
				return (spkey_t)se;
			}
			pe = se;
			se = se->next;
		} while (se != NULL);
	}
	return 0;
}


spkey_t
symbol_db(s, spt)
	const void *s;
	struct sptree *spt;
{
	register const char *ucp;
	register spkey_t key;
	register struct syment *se, *pe;
	char *newname;
	struct spblk *spl;

	if (s == NULL)
		return 0;

#if _USE_CRC
	/* Input string is to be CRCed to form a new key-id */
	key = 0;
	for (ucp = s; *ucp != '\0'; ++ucp)
		key = (key >> 7) ^ CrcTable[(key ^ *ucp) & 0x7f];
#else
	key = pjwhash32(s);
#endif

	/* Ok, time for the hard work.  Lets see if we have this key
	   in the symtab splay tree */

	pe = NULL;
	spl = sp_lookup(key, spt);
	if (spl != NULL) {
		/* Got it !  Now see that we really have it, and
		   not only have a hash collision */

		se = (struct syment *)spl->data;
		do {
			if (strcmp(se->name, s) == 0) {
				/* Really found it! */
				return (spkey_t)se;
			}
			pe = se;
			se = se->next;
		} while (se != NULL);
	}
	se = (struct syment *)emalloc(sizeof (struct syment));
	newname = (char *) emalloc((u_int)(strlen(s)+1));
	strcpy(newname, s);
	se->name = newname;
	se->next = NULL;
	if (pe != NULL)
		pe->next = se;
	else {
		(void) sp_install(key, (const void *)se, 0, spt);
	}
	return (spkey_t)se;
}

/*
 * Empty the entire symbol splay tree
 */
static int
symbol_null(spl)
	struct spblk *spl;
{
	struct syment *se, *sn;
	se = (struct syment *)spl->data;
	for (sn = se ? se->next : NULL; se != NULL; se = sn) {
	  sn = se->next;
	  free((char*)(se->name));
	  free(se);
	}
	return 0;
}

void
symbol_null_db(spt)
	struct sptree *spt;
{
#if 0
	idname = "";
	idkey  = 0;
#endif
	sp_scan(symbol_null, (struct spblk *)NULL, spt);
	sp_null(spt);
}


/*
 * Remove named symbol from the splay tree
 */

void
symbol_free_db(s, spt)
	const void *s;
	struct sptree *spt;
{
	register const char *ucp;
	register spkey_t key;
	register struct syment *se, *pe;
	struct spblk *spl;

	if (s == NULL || spt == NULL)
		return;
#if _USE_CRC
	/* Input string is to be CRCed to form a new key-id */
	key = 0;
	for (ucp = s; *ucp != '\0'; ++ucp)
		key = (key >> 7) ^ CrcTable[(key ^ *ucp) & 0x7f];
#else
	key = pjwhash32(s);
#endif

	/* Ok, time for the hard work.  Lets see if we have this key
	   in the symtab splay tree (we can't use cache here!) */

	pe = NULL;
	spl = sp_lookup(key, spt);
	if (spl != NULL) {
		/* Got it !  Now see that we really have it, and
		   not only have a hash collision */

		se = (struct syment *)spl->data;
		do {
		  if (strcmp(se->name, s) == 0) {
		    /* Really found it! */
		    if (pe != NULL)
		      pe->next = se->next;
		    else
		      spl->data = (void*) se->next;
		    free((char*)(se->name));
		    free(se);
		    break;
		  }
		  pe = se;
		  se = se->next;
		} while (se != NULL);
	}

	if (spl != NULL && spl->data == NULL)
		sp_delete(spl, spt);
}

/*
 * Return a printable string representation of the symbol whose key is passed.
 */

const char *
pname(id)
	spkey_t id;
{
	return (const char *)((struct syment *)id)->name;
}

#ifdef	MALLOC_TRACE
int
icpname(spl)
	struct spblk *spl;
{
	register struct syment *se;

	for (se = (struct syment *)spl->data; se != NULL ; se = se->next)
		printf(">%s", se->name);
	putchar('\n');
	return 0;
}

prsymtable()
{
	sp_scan(icpname, (struct spblk *)NULL, spt_symtab);
}
#endif	/* MALLOC_TRACE */
