/*
 *  Modified PJW-hash
 */

unsigned long
pjwhash32 (ptr)
    register const unsigned char    *ptr;
{
    register unsigned long  hash, tmp;

    if (! ptr)
	return (~(0UL));

    for (hash = 0; *ptr; ptr++) {
	hash <<= 4;
	hash += *ptr;

	/*
	 *  On 32-bit systems the following
	 *  AND-operation will be equal to
	 *	hash & 0xf0000000
	 *  but will automatically adapt
	 *  also to larger implementations
	 *  of "unsigned long" than the
	 *  32 bits for which this code was
	 *  originally designed preserving
	 *  exactly the same results also
	 *  on e.g. 64-bit systems.
	 */

	if (tmp = (hash & ~(0x0fffffffUL))) {
	    hash ^= tmp >> 24;
	    hash ^= tmp;	/* Clear the high bits - fast! */
	}
    }

    return (hash);	    /* Must be divided by a prime! */
}

unsigned long
pjwhash32n (ptr, n)
    register const unsigned char    *ptr;
    int n;
{
    register unsigned long  hash, tmp;

    if (! ptr)
	return (~(0UL));

    for (hash = 0; n > 0; --n, ptr++) {
	hash <<= 4;
	hash += *ptr;

	/*
	 *  On 32-bit systems the following
	 *  AND-operation will be equal to
	 *	hash & 0xf0000000
	 *  but will automatically adapt
	 *  also to larger implementations
	 *  of "unsigned long" than the
	 *  32 bits for which this code was
	 *  originally designed preserving
	 *  exactly the same results also
	 *  on e.g. 64-bit systems.
	 */

	if (tmp = (hash & ~(0x0fffffffUL))) {
	    hash ^= tmp >> 24;
	    hash ^= tmp;	/* Clear the high bits - fast! */
	}
    }

    return (hash);	    /* Must be divided by a prime! */
}
