/*  This file should be edited with 4-column tabs! */
/*  Author: Mark Moraes <moraes@csri.toronto.edu> */

/*LINTLIBRARY*/
#include "adefs.h"
#include "arena.h"

RCSID("$Header: /home/mea/src/CVSROOT/zmailer/libmalloc/arena/malloc.c,v 1.1.1.1 1998/02/10 21:01:46 mea Exp $");

static Arena heap = AINIT;

univptr_t
malloc(nbytes)
size_t nbytes;
{
    return amalloc(&heap, nbytes);
}

void
free(cp)
univptr_t cp;
{
    afree(&heap, cp);
}


univptr_t
realloc(cp, nbytes)
univptr_t cp;
size_t nbytes;
{
    return arealloc(&heap, cp, nbytes);
}


univptr_t
calloc(nelem, elsize)
size_t nelem, elsize;
{
    return acalloc(&heap, nelem, elsize);
}
