/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	New database mechanism added by Matti Aarnio <mea@nic.funet.fi>
 *	over years 1992-1997
 */

/* Information needed by the database search routines */

#include "splay.h"

extern struct sptree *spt_files, *spt_modcheck;

#define	DESC_FILEP	0	/* FILE * */
#define	DESC_NDBMP	1	/* DB * */

typedef struct _search_info {
	const char	*file;
	const char	*key;
	time_t		 ttl;
	const char	*subtype;
} search_info;

struct file_map {
	FILE		*fp;
	time_t		mtime;		/* Last modification time	*/
	long		size;		/* File size			*/
	long		pos;		/* Position in file...		*/
	const char	*membuf;	/* MMAPed buffer start		*/
	int		lines;		/* Count of lines on the file	*/
	off_t		*offsets;	/* Array of line begin offsets	*/
};

#ifndef	__
#ifdef __STDC__
#define __(x) x
#else
#define __(x) ()
#define const
#define volatile
#endif
#endif

/* lookups */
extern conscell	*search_bin	__((search_info	*sip));
extern conscell	*search_core	__((search_info	*sip));
extern conscell	*search_dbm	__((search_info	*sip));
extern conscell	*search_gdbm	__((search_info	*sip));
extern conscell	*search_header	__((search_info	*sip));
extern conscell	*search_hosts	__((search_info	*sip));
extern conscell	*search_ndbm	__((search_info	*sip));
extern conscell	*search_btree	__((search_info	*sip));
extern conscell	*search_bhash	__((search_info	*sip));
extern conscell	*search_res	__((search_info	*sip));
extern conscell	*search_seq	__((search_info	*sip));
extern conscell	*search_yp	__((search_info	*sip));
extern conscell	*search_selfmatch __((search_info *sip));
extern conscell	*search_ldap    __((search_info *sip));
/* closes	*/
extern void	close_core	__((search_info	*sip));
extern void	close_seq	__((search_info	*sip));
extern void	close_ndbm	__((search_info	*sip));
extern void	close_btree	__((search_info	*sip));
extern void	close_bhash	__((search_info	*sip));
extern void	close_dbm	__((search_info	*sip));
extern void	close_gdbm	__((search_info	*sip));
extern void	close_header	__((search_info	*sip));
extern void	close_ldap	__((search_info	*sip));
/* adds	*/
extern int	add_core	__((search_info *sip, const char *value));
extern int	add_seq		__((search_info *sip, const char *value));
extern int	add_ndbm	__((search_info *sip, const char *value));
extern int	add_btree	__((search_info *sip, const char *value));
extern int	add_bhash	__((search_info *sip, const char *value));
extern int	add_dbm		__((search_info *sip, const char *value));
extern int	add_gdbm	__((search_info *sip, const char *value));
extern int	add_header	__((search_info *sip, const char *value));
/* removes	*/
extern int	remove_core	__((search_info	*sip));
extern int	remove_ndbm	__((search_info	*sip));
extern int	remove_btree	__((search_info	*sip));
extern int	remove_bhash	__((search_info	*sip));
extern int	remove_dbm	__((search_info	*sip));
extern int	remove_gdbm	__((search_info	*sip));
extern int	remove_header	__((search_info	*sip));
/* prints	*/
extern void	print_core	__((search_info *sip, FILE *outfp));
extern void	print_hosts	__((search_info *sip, FILE *outfp));
extern void	print_seq	__((search_info *sip, FILE *outfp));
extern void	print_ndbm	__((search_info *sip, FILE *outfp));
extern void	print_btree	__((search_info *sip, FILE *outfp));
extern void	print_bhash	__((search_info *sip, FILE *outfp));
extern void	print_dbm	__((search_info *sip, FILE *outfp));
extern void	print_gdbm	__((search_info *sip, FILE *outfp));
extern void	print_header	__((search_info *sip, FILE *outfp));
extern void	print_yp	__((search_info *sip, FILE *outfp));
extern void	print_selfmatch	__((search_info *sip, FILE *outfp));
/* counts	*/
extern void	count_core	__((search_info *sip, FILE *outfp));
extern void	count_seq	__((search_info *sip, FILE *outfp));
extern void	count_ndbm	__((search_info *sip, FILE *outfp));
extern void	count_btree	__((search_info *sip, FILE *outfp));
extern void	count_bhash	__((search_info *sip, FILE *outfp));
extern void	count_dbm	__((search_info *sip, FILE *outfp));
extern void	count_gdbm	__((search_info *sip, FILE *outfp));
extern void	count_header	__((search_info *sip, FILE *outfp));
extern void	count_selfmatch	__((search_info *sip, FILE *outfp));
/* owners	*/
extern void	owner_core	__((search_info *sip, FILE *outfp));
extern void	owner_seq	__((search_info *sip, FILE *outfp));
extern void	owner_ndbm	__((search_info *sip, FILE *outfp));
extern void	owner_btree	__((search_info *sip, FILE *outfp));
extern void	owner_bhash	__((search_info *sip, FILE *outfp));
extern void	owner_dbm	__((search_info *sip, FILE *outfp));
extern void	owner_gdbm	__((search_info *sip, FILE *outfp));
extern void	owner_header	__((search_info *sip, FILE *outfp));
extern void	owner_yp	__((search_info *sip, FILE *outfp));
/* modchecks	*/
extern int	modp_seq	__((search_info	*sip));
extern int	modp_ndbm	__((search_info	*sip));
extern int	modp_btree	__((search_info	*sip));
extern int	modp_bhash	__((search_info	*sip));
extern int	modp_gdbm	__((search_info	*sip));
extern int	modp_ldap	__((search_info	*sip));

/* misc stuff */
extern void init_header __((void));
extern int  deferit;
