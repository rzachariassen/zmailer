/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Random number generator; see Knuth Vol 2. 2nd ed. p.27 (section 3.2.2)
 */

#include "hostenv.h"
#include "mailer.h"
#include "libz.h"

extern time_t time __((time_t *));


/* 55 random numbers, not all even */

static unsigned long y[55] = {
		1860909544, 231033423, 437666411, 1349655137, 2014584962,
		504613712, 656256107, 1246027206, 573713775, 643466871,
		540235388, 1630565153, 443649364, 729302839, 1933991552,
		944681982, 949111118, 406212522, 1065063137, 1712954727,
		73280612, 787623973, 1874130997, 801658492, 73395958,
		739165367, 596047144, 490055249, 1131094323, 662727104,
		483614097, 844520219, 893760527, 921280508, 46691708,
		760861842, 1425894220, 702947816, 2006889048, 1999607995,
		1346414687, 399640789, 1482689501, 1790064052, 1128943628,
		1269197405, 587262386, 2078054746, 1675409928, 1652325524,
		1643525825, 1748690540, 292465849, 1370173174, 402865384
};

static int j = 23;
static int k = 54;

/* return random integer in the range 0 .. m */

u_int
ranny(m)
	u_int m;
{
	unsigned long r;
	static int done = 0;

	if (!done) {	/* randomize our random seed array a bit more */
		register int i;
		time_t now = (time((time_t *)0))|01;

		for (i = 0; i < 55; ++i)
			y[i] *= now;	/* overflow does a mod */
		done = 1;
	}
	y[k] += y[j];	/* overflow does a mod */
	r = y[k];
	if (k-- == 0) k = 54;
	if (j-- == 0) j = 54;
	return (u_int)(r % (m+1));
}

