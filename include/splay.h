/*
** sptree.h:  The following type declarations provide the binary tree
**  representation of event-sets or priority queues needed by splay trees
**
**  assumes that data and datb will be provided by the application
**  to hold all application specific information
**
**  assumes that key will be provided by the application, comparable
**  with the compare function applied to the addresses of two keys.
*/

# ifndef SPTREE_H
# define SPTREE_H

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif

typedef unsigned long spkey_t; /* On Alpha this is BIG number.. */

struct spblk {
	struct spblk	*leftlink;	/* used also as free-chain */
	struct spblk	*rightlink;
	struct spblk	*uplink;
	spkey_t		key;
	const char	*data;
	long		mark;
};

struct sptree {
	struct spblk	*root;		/* root node */
	struct spblk	*free;		/* free-chain */
	struct sptree	*symbols;	/* If this db needs symbol support,
					   here is another sptree for those */
	int		eltscnt;	/* How many elements in this tree */
	int		lookups;	/* number of splookup()s */
	int		lkpcmps;	/* number of lookup comparisons */
	int		enqs;		/* number of spenq()s */
	int		enqcmps;	/* compares in spenq */
	int		splays;
	int		splayloops;
};

extern struct sptree *sp_init __((void)); /* init tree */
extern struct spblk *sp_lookup __((spkey_t key,
				   struct sptree *q));	/* find key in a tree*/
extern struct spblk *sp_install __((spkey_t key, const void *data, long mark,
				    struct sptree *q)); /* enter an item,
							   allocating or
							   replacing */
extern void sp_scan __((int (*f)(struct spblk *), struct spblk *n,
			struct sptree *q));	/* scan forward through tree */
extern void sp_delete __((struct spblk *n, struct sptree *q)); /* delete node
								  from tree */
extern void        sp_null __((struct sptree *));
extern const char *sp_stats __((struct sptree *q));/* return tree statistics */
extern spkey_t     symbol __((const void *s));	/* build this into a symbol */
extern spkey_t     symbol_lookup __((const void *s));
extern spkey_t     symbol_db        __((const void *, struct sptree *));
extern spkey_t     symbol_lookup_db __((const void *, struct sptree *));
extern spkey_t     symbol_db_mem    __((const void *, int, struct sptree *));
extern spkey_t symbol_lookup_db_mem __((const void *, int, struct sptree *));
extern void	   symbol_free_db __((const void *, struct sptree *));
extern void	   symbol_null_db __((struct sptree *));

extern struct spblk *lookup_incoresp __((const char *, struct sptree *));
extern int      add_incoresp __((const char *, const char *, struct sptree *));
extern int     addd_incoresp __((const char *, const void *, struct sptree *));

extern const char *pname  __((spkey_t id));
#ifdef MALLOC_TRACE
extern int  icpname    __((struct spblk *spl));
extern void prsymtable __((void))
#endif

extern struct spblk * sp_fhead __((struct sptree *));
			/* fast non-splaying head */
extern struct spblk * sp_fnext __((struct spblk *));
			/* fast non-splaying next */

extern struct sptree	*spt_databases, *spt_files, *spt_modcheck,
			*spt_goodguys, *spt_uidmap, *spt_loginmap,
			*spt_fullnamemap, *spt_incoredbs, *spt_headers,
			*spt_eheaders, *spt_builtins, *spt_funclist;

#endif	/* SPTREE_H */
