/*
 * memtypes.h -- used on multiple places, all of which don't
 *		 tolerate their original location:  include/mailer.h
 *		 to be included..
 */

#ifndef	__MEMTYPES_H_
#define	__MEMTYPES_H_ 1

#if 0
#define MEMTYPES	10 /* Number of independent block lists: 0..n	*/
				/* MEMTYPES <= 32 !  (allocate.c)	*/
#define MEM_PERM	0	/* permanent memory, never freed	*/
#define MEM_MALLOC	-1	/* memory we will need to free		*/
#define	MEM_TEMP	1	/* temporary per-message memory		*/
#define	MEM_SHCMD	2	/* temporary per-sh-command memory	*/
#define	MEM_SHRET	3	/* temporary per-sh result return	*/
#else
typedef enum {
	MEM_PERM,	/* Permanent memory, never freed	*/
	MEM_MALLOC,	/* Memory we will need to free		*/
	MEM_TEMP,	/* temporary per-message memory		*/
	MEM_SHCMD,	/* temporary per-sh-command memory	*/
	MEM_SHRET,	/* temporary per-sh result return	*/
	MEMTYPES_N	/* Number of independent block lists	*/
#define MEMTYPES MEMTYPES_N
} memtypes;

#endif

#endif /* __MEMTYPES_H_ */
