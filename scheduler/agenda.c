/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1995
 */

#include "hostenv.h"
#include <sfio.h>
#include "scheduler.h"
#include "prototypes.h"

int	/* return non-zero when there are some childs
	   available for start				*/
doagenda()
{
	struct thread *ncuritem, *nncuritem;
	int didsomething = 0;

	mytime(&now);

	ncuritem = thread_head;

	if (verbose)
	  sfprintf(sfstdout,"curitem %p curitem->wakeup %lu now %d\n",
		   ncuritem, ncuritem ? ncuritem->wakeup : 0, (int)now);

	/* thread_head -chain should be in time order, thus the while-loop
	   should be traversed only once, because  thread_start kicks
	   right away (or reschedules) */

	while (ncuritem  && ncuritem->wakeup <= now  ) {
	  /* Object pointed by  ncuritem  may disappear due to
	     expiration at thread_start() .. */
	  nncuritem = ncuritem->nexttr;
	  /* Not running, and wakeup in past ? */
	  if (ncuritem->proc == NULL && ncuritem->wakeup <= now)
	    /* Try to start it! */
	    while (thread_start(ncuritem, 0))
	      ++ didsomething;

	  ncuritem = nncuritem;

	  queryipccheck();
	}

	mytime(&now);

	/* if (verbose)
	   printf("alarmed %d\n", now);  */

	return (didsomething);
}

/* Do immediate scheduling of given host-indentifier. */
int
turnme(turnarg)
const char *turnarg;
{
	struct spblk *spl;
	struct web *wp;
	char *cp = strchr(turnarg,' ');
	struct thread *ncuritem, *nncuritem;
	spkey_t spk;
	int rc = 0;

	/* caller has done 'strlower()' to our input.. */
	if (cp) *cp++ = 0;
	/* If cp is non-null, some additional args were present.. */

	spk = symbol_lookup_db((void*)turnarg, spt_mesh[L_HOST]->symbols);
	spl = sp_lookup(spk, spt_mesh[L_HOST]);
	if (spl == NULL || spl->data == NULL) {
	  /* Not found, nothing to do.. */
	  return 0;
	}
	wp = (struct web *)spl->data;
	
	ncuritem = thread_head;
	while (ncuritem != NULL) {
	  /* Object pointed by  ncuritem  may disappear due to
	     expiration at thread_start()	 */
	  nncuritem = ncuritem->nexttr;

	  if (wp == ncuritem->whost && ncuritem->proc == NULL) {
	    ncuritem->wakeup = 0; /* Force its starttime! */
	    rc += thread_start(ncuritem, 1);
	    /* We MAY get multiple matches, though it is unlikely.. */
	  }
	  ncuritem = nncuritem;
	}
	return rc;
}   
