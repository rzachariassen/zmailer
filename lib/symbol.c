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
static int crcinit_done = 0;

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
	crcinit_done = 1;
}

struct syment {
	struct syment *next;
	int        namelen;
	const char name[1];
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
symbol_lookup_db_mem_(s, slen, spt, usecrc)
	const void *s;
	const int slen;
	struct sptree *spt;
	const int usecrc;
{
	register const char *ucp;
	register spkey_t key;
	register struct syment *se, *pe;
	struct spblk *spl;
	int i = slen;

	if (s == NULL)
		return 0;

	if (usecrc) {
	  if (!crcinit_done)
	    crcinit();
	  /* Input string is to be CRCed to form a new key-id */
	  key = 0;
	  for (ucp = s; i > 0; ++ucp, --i)
	    key = (key >> 7) ^ CrcTable[(key ^ *ucp) & 0x7f];
	} else
	  key = pjwhash32n(s, slen);

	/* Ok, time for the hard work.  Lets see if we have this key
	   in the symtab splay tree */

	pe = NULL;
	spl = sp_lookup(key, spt);
	if (spl != NULL) {
		/* Got it !  Now see that we really have it, and
		   not only have a hash collision */

		se = (struct syment *)spl->data;
		do {
			if (se->namelen == slen &&
			    memcmp(se->name, s, slen) == 0) {
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
symbol_lookup_db_mem(s, slen, spt)
	const void *s;
	const int slen;
	struct sptree *spt;
{
  return symbol_lookup_db_mem_(s, slen, spt, 0);
}



spkey_t
symbol_db_mem_(s, slen, spt, usecrc)
	const void *s;
	int slen;
	struct sptree *spt;
{
	register const char *ucp;
	register spkey_t key;
	register struct syment *se, *pe;
	char *newname;
	struct spblk *spl;
	int i = slen;

	if (s == NULL)
		return 0;

	if (usecrc) {
	  if (!crcinit_done)
	    crcinit();
	  /* Input string is to be CRCed to form a new key-id */
	  key = 0;
	  for (ucp = s; i > 0; ++ucp, --i)
	    key = (key >> 7) ^ CrcTable[(key ^ *ucp) & 0x7f];
	} else
	  key = pjwhash32n(s,slen);

	/* Ok, time for the hard work.  Lets see if we have this key
	   in the symtab splay tree */

	pe = NULL;
	spl = sp_lookup(key, spt);
	if (spl != NULL) {
		/* Got it !  Now see that we really have it, and
		   not only have a hash collision */

		se = (struct syment *)spl->data;
		do {
			if (se->namelen == slen &&
			    memcmp(se->name, s, slen) == 0) {
				/* Really found it! */
				return (spkey_t)se;
			}
			pe = se;
			se = se->next;
		} while (se != NULL);
	}
	se = (struct syment *)emalloc(sizeof (struct syment) + slen);
	memcpy((void*)se->name, s, slen);
	((char*)se->name)[slen] = 0;
	se->namelen = slen;
	se->next    = NULL;
	if (pe != NULL)
		pe->next = se;
	else {
		(void) sp_install(key, (const void *)se, 0, spt);
	}
	return (spkey_t)se;
}

spkey_t
symbol_db_mem(s, slen, spt)
	const void *s;
	int slen;
	struct sptree *spt;
{
  return symbol_db_mem_(s, slen, spt, 0);
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
symbol_free_db_mem(s, slen, spt)
	const void *s;
	int slen;
	struct sptree *spt;

{
	register const char *ucp;
	register spkey_t key;
	register struct syment *se, *pe;
	struct spblk *spl;
	int i = slen;

	if (s == NULL || spt == NULL)
		return;
#if _USE_CRC
	/* Input string is to be CRCed to form a new key-id */
	key = 0;
	for (ucp = s; i >= 0; ++ucp, --i)
		key = (key >> 7) ^ CrcTable[(key ^ *ucp) & 0x7f];
#else
	key = pjwhash32n(s, slen);
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
		  if (se->namelen == slen &&
		      memcmp(se->name, s, slen) == 0) {
		    /* Really found it! */
		    if (pe != NULL)
		      pe->next = se->next;
		    else
		      spl->data = (void*) se->next;
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

void
symbol_free_db(s, spt)
	const void *s;
	struct sptree *spt;
{
	if (s == NULL || spt == NULL)
		return;
	symbol_free_db_mem(s, strlen(s), spt);
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


spkey_t
symbol_lookup_db(s, spt)
	const void *s;
	struct sptree *spt;
{
	if (s == NULL)
		return 0;

	return symbol_lookup_db_mem(s, strlen(s), spt);
}


spkey_t
symbol_db(s, spt)
	const void *s;
	struct sptree *spt;
{
	if (s == NULL)
		return 0;
	return symbol_db_mem(s, strlen(s), spt);
}

