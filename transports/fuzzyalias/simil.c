/* Ratcliff/Obershelp pattern matching
 *
 *	Approximate word matching: takes two words and returns a
 *	similarity score based on co-occurrence of subpatterns.
 *
 *	This code appeared in a letter to the editor in DDJ, 11/88.
 *	The original article on the pattern matching, "Pattern Matching
 *	by Gestalt" by John Ratcliff, appeared in the July 1988
 *	issue (#181) but the algorithm was presented in assembly.  
 *
 *	The 11/88 issue also contained another verison in C which was
 *	a more faithful translation of the original; it has the
 *	advantage of not being recursive.
 *
 *	The algorithm seems to work nicely for a variety of test cases.
 *	The main drawback of the algorithm is the cost of the pairwise
 *	comparisons.  It is significantly more expensive than stemming,
 *	soundex, and the like.  Might consider using this as a second
 *	phase...
 */

static int
GCsubstr(st1, end1, st2, end2)
char *st1, *end1, *st2, *end2;
{	register char *a1, *a2;
	char *b1, *s1, *b2, *s2;
	short max, i;

	if( end1 <= st1 || end2 <= st2 ) return(0);
	if( end1 == st1 + 1 && end2 == st2 + 1 ) return(0);
		
	max = 0;
	b1 = end1; b2 = end2;
	
	for( a1 = st1; a1 < b1; a1++ ) {
		for( a2 = st2; a2 < b2; a2++ ) {
			if( *a1 == *a2 ) {
				/* determine length of common substring */
				for( i = 1; a1[i] && (a1[i] == a2[i]); i++ ) 
					;
				if( i > max ) {
					max = i; s1 = a1; s2 = a2;
					b1 = end1 - max; b2 = end2 - max;
				}
			}
		}
	}
	if( !max ) return(0);
	max += GCsubstr(s1 + max, end1, s2 + max, end2);	/* rhs */
	max += GCsubstr(st1, s1, st2, s2);			/* lhs */
	return(max);
}

int
simil(s1, s2)
char *s1, *s2;
{	short l1, l2;

	l1 = strlen(s1);
	l2 = strlen(s2);
	
	/* exact match end-case */
	if( l1 == 1 && l2 == 1 && *s1 == *s2 )	return(100);
			
	return(200 * GCsubstr(s1, s1 + l1, s2, s2 + l2) / (l1 + l2));
}

#ifdef TEST
/* test program */
#include <stdio.h>
char *strtok();

main()
{
 char *first, *second;
 char buf[128];

	for(;;) {
		printf("Words: ");
		gets(buf);
		if( buf[0] == '\0' ) break;
		first = strtok(buf, " ");
		second = strtok(NULL, " ");
		printf("Score for %s : %s = %d\n", 
			first, second, simil(first, second));
	}
}
#endif
