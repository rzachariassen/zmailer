/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Modifications/maintance, Matti Aarnio, over years 1990-1998
 *
 *	'longestmatch' driver kissg@sztaki.hu 970209
 */

/*
 * Interface routines for the generic database mechanism.
 *
 * This is a scheme by which one can define particular unary or binary
 * relations, so they can be used by the functions of the configuration
 * file in a manner that is independent of the particular implementation
 * or lookup mechanism. This allows flexible autoconfiguration for the
 * needs or capabilities of each host.
 */

#include "mailer.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <sys/file.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include "libdb/search.h"
#include "splay.h"

#include "prototypes.h"

extern struct sptree *spt_databases; /* At conf.c */

/*
 * The following tables describes the kinds of lookups we support.
 */

typedef enum { Nul, Boolean, Pathalias, Indirect, NonNull } postprocs;

struct cache {
	char		*key;
	conscell	*value;
	time_t		expiry;
};

#define DBFUNC(_fn_)  (* _fn_) __((search_info *))
#define DBFUNCD(_fn_)  (* _fn_) __((conscell *DBFUNC(lookupfn), search_info *))
#define DBFUNCV(_fn_) (* _fn_) __((search_info *, const char *))
#define DBFUNCF(_fn_) (* _fn_) __((search_info *, FILE *))

struct db_info {
	const char	*file;			/* a file parameter */
	const char	*subtype;		/* optional selector */
	int		flags;			/* miscellaneous options */
	int		cache_size;		/* default cache size */
	time_t		ttl;			/* default time to live */
	conscell	*DBFUNCD(driver);	/* completion routine */
	conscell	*DBFUNC(lookup);	/* low-level lookup routine */
	void		DBFUNC(close);		/* flush buffered data, close*/
	int		DBFUNCV(add);		/* add key/value pair */
	int		DBFUNC(remove);		/* remove key */
	void		DBFUNCF(print);		/* print database */
	void		DBFUNCF(count);		/* count database */
	void		DBFUNCF(owner);		/* print database owner */
	int		DBFUNC(modcheckp);	/* should we reopen database?*/
	postprocs	postproc;		/* post-lookup applicator */
	struct cache	*cache;			/* cache entry array */
};

/* bits in the flags field */
#define	DB_MAPTOLOWER	0x01
#define	DB_MAPTOUPPER	0x02
#define	DB_MODCHECK	0x04


struct db_kind {
	const char	*name;		/* database type identification */
	struct db_info	config;		/* default configuration information */
} db_kinds[] = {
{ "incore",	{ NULL, NULL, 0, 0, 0, NULL, search_core, close_core,
		  add_core,
		  remove_core,
		  print_core,
		  count_core,
		  owner_core,
		  NULL,
		  Nul } },
{ "header",	{ NULL, NULL, 0, 0, 0, NULL, search_header, close_header,
		  add_header, remove_header, print_header, count_header,
		  owner_header, NULL, Nul } },
{ "unordered",	{ NULL, NULL, 0, 10, 0, NULL, search_seq, close_seq,
		  add_seq, NULL, print_seq, count_seq, owner_seq, modp_seq,
		  Nul } },
#ifndef	HAVE_MMAP
{ "ordered",	{ NULL, NULL, 0, 10, 0, NULL, search_bin, close_seq,
		  NULL, NULL, print_seq, count_seq, owner_seq, modp_seq,
		  Nul } },
#else /* HAVE_MMAP */ /* When using MMAP(), no cache is needed for ordered.. */
{ "ordered",	{ NULL, NULL, 0, 0, 0, NULL, search_bin, close_seq,
		  NULL, NULL, print_seq, count_seq, owner_seq, modp_seq,
		  Nul } },
#endif

#ifdef	HAVE_RESOLVER
{ "hostsfile",	{ "/etc/hosts", NULL, 0, 10, 0, NULL, search_hosts, NULL,
		  NULL, NULL, print_hosts, NULL, NULL, NULL, Nul } },
#endif	/* HAVE_RESOLVER */
#ifdef	HAVE_RESOLVER
#ifndef RESOLV_CONF
# define RESOLV_CONF "/etc/resolv.conf"
#endif
{ "bind",	{ RESOLV_CONF, NULL, 0, 10, 0, NULL,
		  search_res, NULL, NULL, NULL, NULL, NULL, NULL, NULL, Nul }},
#endif	/* HAVE_RESOLV */
{ "selfmatch",	{ NULL, NULL, 0, 0, 0, NULL, search_selfmatch, NULL, NULL,
		  NULL, print_selfmatch, count_selfmatch, NULL, NULL, Nul } },
#ifdef	HAVE_NDBM_H
{ "ndbm",	{ NULL, NULL, 0, 10, 0, NULL, search_ndbm, close_ndbm,
		  add_ndbm, remove_ndbm, print_ndbm, count_ndbm, owner_ndbm,
		  modp_ndbm, Nul } },
#endif	/* HAVE_NDBM */
#ifdef	HAVE_GDBM_H
{ "gdbm",	{ NULL, NULL, 0, 10, 0, NULL, search_gdbm, close_gdbm,
		  add_gdbm, remove_gdbm, print_gdbm, count_gdbm, owner_gdbm,
		  modp_gdbm, Nul } },
#endif	/* HAVE_GDBM */
#ifdef	HAVE_DBM
{ "dbm",	{ NULL, NULL, 0, 10, 0, NULL, search_dbm, close_dbm,
		  add_dbm, remove_dbm, print_dbm, count_dbm, owner_dbm,
		  NULL, Nul } },
#endif	/* HAVE_DBM */
#ifdef	HAVE_DB_H
{ "btree",	{ NULL, NULL, 0, 10, 0, NULL, search_btree, close_btree,
		  add_btree, remove_btree, print_btree, count_btree,
		  owner_btree, modp_btree, Nul } },
{ "bhash",	{ NULL, NULL, 0, 10, 0, NULL, search_bhash, close_bhash,
		  add_bhash, remove_bhash, print_bhash, count_bhash,
		  owner_bhash, modp_bhash, Nul } },
#endif	/* HAVE_DB_H */
#ifdef	HAVE_YP
{ "yp",		{ NULL, NULL, 0, 10, 0, NULL, search_yp, NULL,
		  NULL, NULL, print_yp, NULL, owner_yp, NULL, Nul } },
#endif	/* HAVE_YP */
#ifdef HAVE_LDAP
{ "ldap",	{ NULL, NULL, 0, 10, 0, NULL, search_ldap, close_ldap,
		  NULL, NULL, NULL, NULL, NULL, modp_ldap, Nul } },
#endif
{ 0 }	/* proto_config is initialized from this entry */
};


/* drivers */
static conscell	*find_domain       __((conscell *DBFUNC(lookupfn), search_info *sip));
static conscell	*find_nodot_domain __((conscell *DBFUNC(lookupfn), search_info *sip));
static conscell *find_longest_match __((conscell *DBFUNC(lookupfn), search_info *sip));
/* others.. */
static void      cacheflush __((struct db_info *dbip));
extern conscell	*readchunk  __((const char *file, long offset));
static int	 iclistdbs  __((struct spblk *spl));



/*
 * Define a new relation according to the command line arguments.
 * (This is a built-in C-coded function.)
 */

int
run_relation(argc, argv)
	int		  argc;
	const char	**argv;
{
	struct db_info proto_config, *dbip;
	struct db_kind *dbkp;
	struct spblk *spl;
	int c, errflg, set_cache_size, dbtest;
	spkey_t symid;
	memtypes oval;
	char *cp, *dbtyp;

	if (spt_files == NULL)          spt_files          = sp_init();
	if (spt_files->symbols == NULL) spt_files->symbols = sp_init();

	errflg = 0;
	dbtyp = NULL;
	set_cache_size = 0;
	optind = 1;
	dbtest = 0;
	proto_config
		= db_kinds[sizeof db_kinds/(sizeof (struct db_kind))-1].config;
	while (1) {
		c = getopt(argc, (char*const*)argv, "Cbilmnpud:f:s:t:Te:");
		if (c == EOF)
			break;
		switch (c) {
		case 'b':	/* boolean postprocessor */
			proto_config.postproc = Boolean;
			break;
		case 'd':	/* driver routine */
			if (strcmp(optarg, "pathalias.nodot") == 0)
				proto_config.driver = find_nodot_domain;
			else if (strcmp(optarg, "pathalias") == 0)
				proto_config.driver = find_domain;
			else if (strcmp(optarg, "longestmatch") == 0)
				proto_config.driver = find_longest_match;
			else
				++errflg;
			break;
		case 'f':	/* file name */
			oval = stickymem;
			stickymem = MEM_PERM;
			proto_config.file = strsave(optarg);
			stickymem = oval;
			break;
		case 'i':	/* indirect reference postprocessor */
			proto_config.postproc = Indirect;
			break;
		case 'l':	/* map all keys to lower-case */
			proto_config.flags |= DB_MAPTOLOWER;
			break;
		case 'm':
			proto_config.flags |= DB_MODCHECK;
			break;
		case 'n':	/* ensure non-null return value postprocessor */
			proto_config.postproc = NonNull;
			break;
		case 'p':	/* pathalias postprocessor */
			proto_config.postproc = Pathalias;
			break;
		case 's':	/* cache size */
			proto_config.cache_size = atoi(optarg);
			set_cache_size = 1;
			break;
		case 't':	/* database type */
			dbtyp = optarg;
			if ((cp = strchr(optarg, ',')) != NULL
			    || (cp = strchr(optarg, '/')) != NULL) {
				*cp++ = '\0';
				oval = stickymem;
				stickymem = MEM_PERM;
				cp = strsave(cp);
				stickymem = oval;
			}
			proto_config.subtype = cp;
			break;
		case 'T':
			dbtest = 1;
			break;
		case 'e':	/* expiry - cache data time to live */
			proto_config.ttl = atol(optarg);
			break;
		case 'u':	/* map all keys to uppercase */
			proto_config.flags |= DB_MAPTOUPPER;
			break;
		case 'F':	/* find routine */
		case 'S':	/* search routine */
		default:
			++errflg;
			break;
		}
	}
	if (errflg || optind != argc - 1 || dbtyp == NULL) {
		fprintf(stderr,
		"Usage: %s -t dbtype[,subtype] [-f file -e# -s# -bilmnpu -d driver] name\n",
			argv[0]);
		fprintf(stderr,
		       "       %s -T -t dbtype dummyname\n", argv[0]);
		fprintf(stderr,
			"      dbtypes: ");
		for (dbkp = &db_kinds[0];
		     dbkp < &db_kinds[(sizeof db_kinds)/sizeof (struct db_kind)];
		     ++dbkp) {
		  if (dbkp->name != NULL)
		    if (dbkp == &db_kinds[0])
		      fprintf(stderr,"%s",dbkp->name);
		    else
		      fprintf(stderr,",%s",dbkp->name);
		}
		fprintf(stderr,"\n");
		return 1;
	}
	if ((proto_config.flags & (DB_MAPTOLOWER|DB_MAPTOUPPER)) ==
	    (DB_MAPTOLOWER|DB_MAPTOUPPER)) {
		fprintf(stderr,
		    "relation: the -l and -u flags are mutually exclusive\n");
		return 2;
	}
	for (dbkp = &db_kinds[0];
	     dbkp < &db_kinds[(sizeof db_kinds)/sizeof (struct db_kind)];
	     ++dbkp) {
		if (dbkp->name == NULL || strcmp(dbkp->name, dbtyp) == 0)
			break;
	}
	/* the -1 in the following compensates for the terminating null entry */
	if (dbkp >= &db_kinds[((sizeof db_kinds)/sizeof (struct db_kind))-1]) {
	  if (!dbtest)
	    fprintf(stderr,
		    "relation: I don't know about the %s database type!\n",
		    dbtyp);
	  return 3;
	}
	if (dbtest)
	  return 0;

	symid = symbol(argv[optind]); /* Database name symbol  */
	if (sp_lookup(symid, spt_databases) != NULL) {
		fprintf(stderr, "%s: %s is already a defined database!\n",
				argv[0], argv[optind]);
		return 4;
	}
	if (spt_builtins != NULL && sp_lookup(symid, spt_builtins) != NULL) {
		fprintf(stderr, "%s: %s is already a built in function!\n",
				argv[0], argv[optind]);
		return 5;
	}
	if (spt_funclist != NULL && sp_lookup(symid, spt_funclist) != NULL) {
		fprintf(stderr, "%s: %s is already a defined function!\n",
				argv[0], argv[optind]);
		return 6;
	}
	if (proto_config.postproc == Indirect &&
	    dbkp->config.owner != owner_seq) {
		fprintf(stderr,
			"%s: Indirect (-i) postprocessor can be used only with {un,}ordered databases!\n%s  Tried to use with: -t %s\n",
			argv[0], argv[0], dbtyp);
		return 7;
	}


	if (dbkp->config.lookup == search_core
	    || dbkp->config.lookup == search_header) {
		/* The database name is used as a key by the incore routines */
		oval = stickymem;
		stickymem = MEM_PERM;
		proto_config.file = strsave(argv[optind]);
		stickymem = oval;
		/* and the subtype is used to stash the splay tree */
		proto_config.subtype = (char*) sp_init();
	} else {
		if (proto_config.file == NULL)
			proto_config.file = dbkp->config.file;
		if (proto_config.subtype == NULL)
			proto_config.subtype = dbkp->config.subtype;
	}
	if (proto_config.flags == 0)
		proto_config.flags = dbkp->config.flags;
	if (!set_cache_size || proto_config.cache_size < 0)
		proto_config.cache_size = dbkp->config.cache_size;
	if (proto_config.ttl < 0)
		proto_config.ttl = dbkp->config.ttl;
	if (proto_config.driver == NULL)
		proto_config.driver = dbkp->config.driver;
	if (proto_config.lookup == NULL)
		proto_config.lookup = dbkp->config.lookup;
	if (proto_config.close == NULL)
		proto_config.close = dbkp->config.close;
	if (proto_config.add == NULL)
		proto_config.add = dbkp->config.add;
	if (proto_config.remove == NULL)
		proto_config.remove = dbkp->config.remove;
	if (proto_config.print == NULL)
		proto_config.print = dbkp->config.print;
	if (proto_config.count == NULL)
		proto_config.count = dbkp->config.count;
	if (proto_config.owner == NULL)
		proto_config.owner = dbkp->config.owner;
	if (proto_config.modcheckp == NULL)
		proto_config.modcheckp = dbkp->config.modcheckp;
	if (proto_config.postproc == Nul)
		proto_config.postproc = dbkp->config.postproc;
	dbip = (struct db_info *)smalloc(MEM_PERM, sizeof (struct db_info));
	*dbip = proto_config;
	if (dbip->cache_size > 0) {
		dbip->cache = (struct cache *)
			smalloc(MEM_PERM, (u_int)(dbip->cache_size *
						  (sizeof (struct cache))));
		dbip->cache->key = NULL;	/* search terminator */
	} else
		dbip->cache = NULL;	/* superfluous, but why not ... */
	sp_install(symid, dbip, 0, spt_databases);
	spl = sp_lookup(symbol(DBLOOKUPNAME), spt_builtins);
	if (spl == NULL) {
		fprintf(stderr, "%s: '%s' isn't built in\n",
				argv[0], DBLOOKUPNAME);
		return 1;
	}
	sp_install(symid, spl->data, 0, spt_builtins);
	return 0;
}

/* return the splay tree associated with the named incore database */

struct sptree *
icdbspltree(name)
	const char *name;
{
	struct db_info *dbip;
	struct spblk *spl;

	spl = sp_lookup(symbol(name), spt_databases);
	if (spl == NULL)
		return NULL;
	dbip = (struct db_info *)spl->data;
	return (struct sptree *)dbip->subtype;
}

/*
 * Database maintenance.
 *
 * Usage: 	db add name key value
 *		db remove name key
 *		db flush name
 *		db print name
 *		db count name
 *		db index
 *		db owner name
 */

static int
iclistdbs(spl)
	struct spblk *spl;
{
	struct db_kind *dbkp;
	struct db_info *dbip;
	struct cache *cachep;
	const char *cp;
	int i;

	printf("%-13s", pname(spl->key));

	dbip = (struct db_info *)spl->data;
	cp = NULL;
	for (dbkp = &db_kinds[0];
	     dbkp < &db_kinds[(sizeof db_kinds)/sizeof (struct db_kind)];
	     ++dbkp) {
		if (dbkp->config.lookup == dbip->lookup) {
			cp = dbkp->name;
			break;
		}
	}
	printf(" %s", cp);
	i = strlen(cp);
	if (dbip->lookup != search_core && dbip->lookup != search_header
	    && dbip->postproc != Indirect && dbip->subtype != NULL) {
		printf(",%s", dbip->subtype);
		i += 1 + strlen(dbip->subtype);
	}
	i = (i > 10) ? 1 : 11 - i;

	printf("%*s", i, " ");
	
	if (dbip->cache_size == 0 || dbip->cache == NULL)
		printf("%*s", 11, " ");
	else {
		for (i = 0, cachep = dbip->cache;
		     i < dbip->cache_size && cachep->key != NULL;
		     ++cachep)
			++i;
		printf("%2d/%-2d ", i, dbip->cache_size);
		if (dbip->ttl > 0)
			printf("%4d ", (int)dbip->ttl);
		else
			printf("     ");
	}

	i = 0;
	if (dbip->flags & DB_MAPTOLOWER)
		putchar('l'), ++i;
	if (dbip->flags & DB_MAPTOUPPER)
		putchar('U'), ++i;
	switch (dbip->postproc) {
	case NonNull: putchar('n'), ++i; break;
	case Boolean: putchar('B'), ++i; break;
	case Pathalias: putchar('p'), ++i; break;
	case Indirect: putchar('@'), ++i; break;
	default: break;
	}
	if (i == 0)
		putchar('-'), ++i;
	i = (i > 2) ? 1 : 3 - i;

	printf("%*s", i, " ");
	
	if (dbip->lookup != search_core && dbip->lookup != search_header
	    && dbip->file != NULL) {
		printf("%s", dbip->file);
		if (dbip->postproc == Indirect)
			printf(" -> %s", dbip->subtype);
	}

	putchar('\n');
	return 0;
}

int
run_db(argc, argv)
	int argc;
	const char *argv[];
{
	int errflag;
	struct db_info *dbip;
	search_info si;
	struct spblk *spl;

	if (argc == 2 && (argv[1][0] == 'i' || argv[1][0] == 't')) {
		/* print an index/toc of the databases */
		sp_scan(iclistdbs, (struct spblk *)NULL, spt_databases);
		return 0;
	}

	errflag = 0;
	if (argc == 1)
		errflag = 1;
	else
		switch (argv[1][0]) {
		case 'a':	errflag = (argc != 5); break;
		case 'd':
		case 'r':	errflag = (argc != 4); break;
		case 'f':
		case 'n':
		case 'o':
		case 'c':
		case 'p':	errflag = (argc != 3); break;
		default:	errflag = 1; break;
		}
	if (errflag) {
		fprintf(stderr,
"Usage: %s { add|remove|flush|owner|print|count|toc } [ database [ key [ value ] ] ]\n",
			argv[0]);
		return 1;
	}

	spl = sp_lookup(symbol(argv[2]), spt_databases);
	if (spl == NULL) {
		fprintf(stderr, "%s: unknown database \"%s\"!\n",
				argv[0], argv[2]);
		return 2;
	}
	dbip = (struct db_info *)spl->data;
	if (dbip == NULL) {
		fprintf(stderr, "%s: null database definition for \"%s\"!\n",
				argv[0], argv[2]);
		return 3;
	}

	if (argv[3] != NULL) {
		if (dbip->flags & DB_MAPTOLOWER) {
			strlower((char*)argv[3]);
		} else if (dbip->flags & DB_MAPTOUPPER) {
			strupper((char*)argv[3]);
		}
	}

	si.file = dbip->file;
	si.key  = argv[3];
	si.subtype = dbip->subtype;
	si.ttl  = dbip->ttl;

	switch (argv[1][0]) {
	case 'a':	/* add db key value */
		if (dbip->add == NULL) {
			fprintf(stderr, "%s: %s: no add capability!\n",
					argv[0], argv[2]);
			return 1;
		}
		if ((*dbip->add)(&si, argv[4]) == EOF) {
			fprintf(stderr, "%s: %s: didn't add (\"%s\",\"%s\")!\n",
					argv[0], argv[2], argv[3], argv[4]);
			return 1;
		}
		break;
	case 'd':	/* delete db key */
	case 'r':	/* remove db key */
		if (dbip->remove == NULL) {
			fprintf(stderr, "%s: %s: no remove capability!\n",
					argv[0], argv[2]);
			return 1;
		}
		if ((*dbip->remove)(&si) == EOF) {
			fprintf(stderr, "%s: %s: didn't remove \"%s\"!\n",
					argv[0], argv[2], argv[3]);
			return 1;
		}
		break;
	case 'n':	/* null/nuke db */
	case 'f':	/* flush */
		cacheflush(dbip);
		if (dbip->close == NULL) {
			fprintf(stderr, "%s: %s: no flush capability!\n",
					argv[0], argv[2]);
			return 1;
		}

		/*
		 * Note that the close/flush routine should not remove the
		 * file/db name entry from the splay tree, because there may
		 * be multple references to it.  For example: /dev/null.
		 */
		(*dbip->close)(&si);

		/*
		 * Close auxiliary (indirect) data file as well (aliases.dat).
		 * There may be a subtle assumption here that the innards of
		 * the close routine only cares about si.file...
		 */
		if (dbip->postproc == Indirect) {
			si.file = dbip->subtype;
			(*dbip->close)(&si);
		}
		break;
	case 'o':	/* owner */
		if (dbip->owner == NULL) {
			fprintf(stderr,
				"%s: %s: no ownership information available!\n",
				argv[0], argv[2]);
			return 1;
		}
		(*dbip->owner)(&si, stdout);
		break;
	case 'p':	/* print db */
		if (dbip->print == NULL) {
			fprintf(stderr, "%s: %s: no printing capability!\n",
					argv[0], argv[2]);
			return 1;
		}
		(*dbip->print)(&si, stdout);
		break;
	case 'c':	/* count db */
		if (dbip->count == NULL) {
			fprintf(stderr, "%s: %s: no counting capability!\n",
					argv[0], argv[2]);
			return 1;
		}
		(*dbip->count)(&si, stdout);
		break;
	default:
		fprintf(stderr, "%s: unknown command '%s'\n", argv[0], argv[1]);
		return 5;
	}
	return 0;
}


#define	CACHE(x,f)	((dbip->cache+(x))->f)

/*
 * This is the basic interface to the database lookup routines.
 * It uses the configuration information for each relation properly,
 * implements caching, etc.
 */

conscell *
db(dbname, key)
	const char *dbname, *key;
{
	register int i, j, k;
	memtypes oval = stickymem;
	conscell *l, *ll, *tmp;
	struct spblk *spl;
	struct db_info *dbip;
	char *realkey;
	search_info si;
	struct cache tce;
	char kbuf[BUFSIZ];	/* XX: */

	if (spt_files == NULL)          spt_files          = sp_init();
	if (spt_files->symbols == NULL) spt_files->symbols = sp_init();

	if (key == NULL || *key == '\0') {
		fprintf(stderr,
			"Null key looked up in %s relation!\n", dbname);
		return NULL;
	}
	/* Is caching dbip worth it? I'm not so sure */
	spl = sp_lookup(symbol(dbname), spt_databases);
	dbip = (struct db_info *)spl->data;
	if (dbip == NULL) {
		fprintf(stderr, "Undefined database %s!\n", dbname);
		return NULL;
	}
	if (D_db)
		fprintf(stderr, "%s(%s)\n", dbname, key);
	/* apply flags */
	realkey = NULL;
	if (dbip->flags & DB_MAPTOLOWER) {
		strncpy(kbuf, key, sizeof(kbuf));
		kbuf[sizeof(kbuf)-1] = 0;
		strlower(kbuf);
		key = kbuf;
	} else if (dbip->flags & DB_MAPTOUPPER) {
		strncpy(kbuf, key, sizeof(kbuf));
		kbuf[sizeof(kbuf)-1] = 0;
		strupper(kbuf);
		key = kbuf;
	}
	si.file = dbip->file;
	si.key  = key;
	si.subtype = dbip->subtype;
	si.ttl  = dbip->ttl;
	if ((dbip->flags & DB_MODCHECK)
	    && dbip->modcheckp != NULL && (*dbip->modcheckp)(&si)) {
		if (dbip->close != NULL) {
			cacheflush(dbip);
			(*dbip->close)(&si);
			if (dbip->postproc == Indirect) {
				si.file = dbip->subtype;
				(*dbip->close)(&si);
				si.file = dbip->file;
			}
		}
	}
	/* look for the desired result in the cache first */
	j = 0;
	k = 0;
	if (dbip->cache_size > 0) {
		for (i=j=0; i < dbip->cache_size && CACHE(i,key) != NULL; ++i){
			if (CACHE(i,expiry) > 0 && CACHE(i,expiry) < now) {
				if (D_db)
					fprintf(stderr,
						"... expiring %s from cache\n",
						CACHE(i,key));
				if ((ll = CACHE(i,value)) != NULL)
					s_free_tree(ll);
				if (CACHE(i,key) != NULL) /* always true */
					free((char *)CACHE(i,key));
				continue;
			}
			if (i > j) { /* expiry */
				*(dbip->cache+j) = *(dbip->cache+i);
				if (D_db)
					fprintf(stderr,
						"... setting cache[%d]: %s\n",
						j, CACHE(j,key));
			}
			if (D_db)
				fprintf(stderr,
					"... comparing %s and %s in cache\n",
					CACHE(i,key), key);
			if (CISTREQ(CACHE(i,key), key)) {
				/* cache maintenance */
				tce = *(dbip->cache+i);
				if (j > 0 && D_db)
					fprintf(stderr,
						"... ripple down from %d\n",j);
				/* ripple down to beginning */
				for (k = j; j > 0; --j)
					*(dbip->cache+j) = *(dbip->cache+j-1);
				*(dbip->cache) = tce;
				if (i > k) {	/* ripple down to end */
					for (j = ++k, ++i;
					     i < dbip->cache_size
					      && CACHE(i,key) != NULL;
					     ++i, ++j)
						*(dbip->cache+j) =
							*(dbip->cache+i);
					CACHE(j,key) = NULL;
					if (D_db)
						fprintf(stderr,
						  "... ripple up to %d of %d\n",
						  i, j);
				}
				if (D_db)
					fprintf(stderr, "... found in cache\n");
				/* return a scratch value */
				return s_copy_tree(dbip->cache->value);
			}
			++j;
		}
		if (j < i)	/* stomp on expired entry */
			CACHE(j,key) = NULL;	/* mark end of cache entries */
		oval = stickymem;	/* cannot return before this is reset */
		stickymem = MEM_MALLOC;	/* this is reset down below */
		/* key gets clobbered somewhere, so save it here */
		realkey = strsave(key);
	}
	l = NULL;
	if ((dbip->driver == NULL &&
	     (l = (*dbip->lookup)(&si)) != NULL) ||
	    (dbip->driver != NULL &&
	     (l = (*dbip->driver)(dbip->lookup, &si)))) {

		switch (dbip->postproc) {
		case Boolean:
			if (stickymem == MEM_MALLOC)
				s_free_tree(l);
			l = newstring(strsave(key));
			break;
		case NonNull:
			if (STRING(l) && *(l->string) == '\0') {
				if (stickymem == MEM_MALLOC)
					s_free_tree(l);
				l = newstring(strsave(key));
			} else if (LIST(l) && car(l) == NULL) {
				car(l) = newstring(strsave(key));
			}
			break;
		case Indirect:
			/*
			 * If we got anything, it should be a byte offset into
			 * the file named by the subtype.  Used for aliases.
			 */
			if (LIST(l) || !isdigit(*(l->string))) {
				if (stickymem == MEM_MALLOC)
					s_free_tree(l);
				l = NULL;
				break;
			}
			i = atoi(l->string);	/* file offset */
			if (stickymem == MEM_MALLOC)
				s_free_tree(l);
			l = readchunk(dbip->subtype, (long)i);
			break;
		case Pathalias:
			/* X: fill this out */
			break;
		default:
			break;
		}
		if (D_db) {
			fprintf(stderr, "%s(%s) = ", dbname, key);
			s_grind(l, stderr);
			putc('\n', stderr);
		}
	} else if (dbip->postproc == NonNull) {
		if (D_db)
			fprintf(stderr, "%s(%s) = %s\n", dbname, key, key);
		l = newstring(strsave(key));
	} else {
		if (dbip->cache_size > 0) {
			stickymem = oval;
			free(realkey);
		}
		return NULL;
	}
	if (!deferit && dbip->cache_size > 0) {
		i = j;
		/* insert new cache entry at head of cache */
		if (i >= dbip->cache_size) {
			i = dbip->cache_size - 1;
			if (D_db)
				fprintf(stderr, "... freeing cache[%d]: %s\n",
						i, CACHE(i,key));
			if ((ll = CACHE(i,value)) != NULL)
				s_free_tree(ll);
			free((char *)CACHE(i,key));
		} else if (i < dbip->cache_size - 1) {
			if (D_db)
				fprintf(stderr, "... terminating cache[%d]\n",
						i);
			CACHE(i,key) = NULL;		/* terminator */
			++i;
		}
		/* ripple old entries up */
		while (--i >= 0)
			*(dbip->cache+i+1) = *(dbip->cache+i);
		dbip->cache->key = realkey;
		dbip->cache->value = l;
		if (D_db)
			fprintf(stderr, "... added %s to cache", realkey);
		if (si.ttl > 0) {
			dbip->cache->expiry = now + si.ttl;
			if (D_db)
				fprintf(stderr, " (ttl=%d)\n", (int)si.ttl);
		} else {
			dbip->cache->expiry = 0;
			if (D_db)
				fprintf(stderr, "\n");
		}
		stickymem = oval;
		ll = s_copy_tree(l);	/* scratch version returned to shell */
	} else if (dbip->cache_size > 0) {
		stickymem = oval;
		ll = s_copy_tree(l);	/* scratch version returned to shell */
		free(realkey);
		s_free_tree(l);
	} else
		ll = l;

	return ll;
}

const char *
dbfile(dbname)
	const char *dbname;
{
	struct db_info *dbip;
	struct spblk *spl;

	spl = sp_lookup(symbol(dbname), spt_databases);
	dbip = (struct db_info *)spl->data;
	if (dbip == NULL) {
		fprintf(stderr, "Undefined database '%s'!\n", dbname);
		return NULL;
	}
	return dbip->file;
}

/*
 * Flush all cache entries from a database definition.
 */

static void
cacheflush(dbip)
	struct db_info *dbip;
{
	int i;
	conscell *ll;

	if (dbip == NULL || dbip->cache_size == 0 || dbip->cache == NULL)
		return;

	/* flush cache */
	for (i = 0; i < dbip->cache_size && CACHE(i,key) != NULL; ++i) {
		ll = CACHE(i,value);
		if (ll != NULL)
			s_free_tree(ll);
		if (CACHE(i,key) != NULL) /* always true */
			free((char *)CACHE(i,key));
	}
	dbip->cache->key = NULL;	/* ensure terminator */
}

#ifdef	MALLOC_TRACE

/*
 * Flush everything; back to original state
 */

static void	_sptdbreset __((struct spblk *spl));
static void
_sptdbreset(spl)
	struct spblk *spl;
{
	char *av[4];

	av[0] = "db";
	av[1] = "flush";
	av[2] = pname((u_int)(spl->key));
	av[3] = NULL;
	printf("flushing cache of %s\n", av[2]);
	run_db(3, av);
}

void
dbfree()
{
	sp_scan(_sptdbreset, (struct spblk *)NULL, spt_databases);
}
#endif	/* MALLOC_TRACE */

const char *
dbtype(dbname)
	const char *dbname;
{
	struct db_info *dbip;
	struct db_kind *dbkp;
	struct spblk *spl;

	spl = sp_lookup(symbol(dbname), spt_databases);
	if (spl == NULL) {
		fprintf(stderr, "Undefined database '%s'!\n", dbname);
		return NULL;
	}
	dbip = (struct db_info *)spl->data;
	if (dbip == NULL) {
		fprintf(stderr, "Undefined database '%s'!\n", dbname);
		return NULL;
	}
	for (dbkp = &db_kinds[0];
	     dbkp < &db_kinds[(sizeof db_kinds)/sizeof (struct db_kind)];
	     ++dbkp) {
		if (dbkp->config.lookup == dbip->lookup)
			return dbkp->name;
	}
	return NULL;
}

/*
 * This routine is good for looking up foo.bar.edu in e.g. a gateway list.
 * It is typically used for pathalias database lookup.
 *
 * The lookup sequence for foo.bar.edu is:
 *
 *	foo.bar.edu
 *	.foo.bar.edu
 *	.bar.edu
 *	.edu
 *	.
 */

static conscell *
find_domain(lookupfn, sip)
	conscell *DBFUNC(lookupfn);
	search_info *sip;
{
	register char *cp;
	conscell *l;
	const char *realkey;
	char *buf;
	int keylen;

	/* check the key as given */
	l = (*lookupfn)(sip);
	if (l != NULL)
		return l;

	realkey = sip->key;
	keylen  = strlen(realkey);
#define PREDOT_TEST
#ifdef PREDOT_TEST
#ifdef HAVE_ALLOCA
	buf = (char*) alloca(keylen+2);
#else
	buf = (char*) emalloc(keylen+2);
#endif
	/* No exact match, see if you can find a  "." + keystring ? */
	if (*realkey != '.') {
		buf[0] = '.';
		strcpy(buf + 1, realkey);
	}
#else
	buf = realkey;
#endif
	/* iterate over the subdomains of the key */
	for (cp = buf; *cp;) {
		while (*cp && *cp != '.')
			++cp;
		while (*cp == '.')
			++cp;
		if (*(cp-1) == '.') {
			sip->key = cp-1;
			l = (*lookupfn)(sip);
			if (l != NULL) {
#ifdef PREDOT_TEST
#ifndef HAVE_ALLOCA
				free(buf);
#endif
#endif
				return l;
			}
		}
	}
#ifndef PREDOT_TEST
	/* if all else failed, try prepending a dot and look for subdomains */
	if (*realkey != '.') {
#ifdef HAVE_ALLOCA
		buf = (char*) alloca(keylen+2);
#else
		buf = (char*) emalloc(keylen+2);
#endif
		buf[0] = '.';
		memcpy(buf + 1, realkey, keylen+1);
		sip->key = buf;
		l = (*lookupfn)(sip);
#ifndef HAVE_ALLOCA
		free(buf);
#endif
		if (l != NULL)
			return l;
	}
#endif
	/* Still failed ?  Try to look for "." */
	sip->key = ".";
	l = (*lookupfn)(sip);
	if (l != NULL)
		return l;

	return NULL;
}

/*
 * The lookup sequence for foo.bar.edu is:
 *
 *	bar.edu
 *	edu
 */

static conscell *
find_nodot_domain(lookupfn, sip)
	conscell *DBFUNC(lookupfn);
	search_info *sip;
{
	register const char *cp;
	conscell *l = NULL;

	/* iterate over the subdomains of the key */
	for (cp = sip->key; *cp;) {
		while (*cp && *cp != '.')
			++cp;
		while (*cp == '.')
			++cp;
		if (*(cp-1) == '.') {
			sip->key = cp;
			l = (*lookupfn)(sip);
			if (l != NULL)
				return l;
		}
	}
#if 0
	/* if all else failed, try the name itself */
	l = (*lookupfn)(sip);
#endif
	return l;
}


/*
 * Searching the longest match.
 *
 * The lookup sequence for foo.bar.edu is:
 *
 *	foo.bar.edu
 *	.bar.edu
 *	.edu
 *	.
 *
 * The lookup sequence for 1.2.3.13 is:
 *
 *	1.2.3.13/32
 *	1.2.3.12/31
 *	1.2.3.12/30
 *	1.2.3.8/29
 *	1.2.3.0/28
 *      ...
 *	1.0.0.0/8
 *	...
 *	0.0.0.0/1
 *	0.0.0.0/0
 */

static conscell *
find_longest_match(lookupfn, sip)
	conscell *DBFUNC(lookupfn);
	search_info *sip;
{
	register char *cp;
	conscell *l;
	char buf[BUFSIZ]; 
	char *realkey;
	unsigned int oct1,oct2,oct3,oct4;

	if (sscanf((char*)(sip->key[0]=='[' ? sip->key+1 : sip->key),
	    "%3u.%3u.%3u.%3u",
	    &oct1,&oct2,&oct3,&oct4) == 4) { /* IP address with optional [] */
		unsigned int h_addr,h_mask;
		int prefix;

		h_addr = (((oct1 & 255) << 24) |
			  ((oct2 & 255) << 16) |
			  ((oct3 & 255) <<  8) |
			  ((oct4 & 255)));

		sip->key=buf;
		for (prefix=32, h_mask=0xffffffffL;
		    prefix>=0;  --prefix, h_mask<<=1) {
			sprintf((char*)buf,"%u.%u.%u.%u/%d",
				((h_addr&h_mask) >> 24) & 255,
				((h_addr&h_mask) >> 16) & 255,
				((h_addr&h_mask) >>  8) & 255,
				((h_addr&h_mask)      ) & 255,
				prefix);
			if ((l = (*lookupfn)(sip)) != NULL)
				return l;
		}
	}
	else {	/* domain name */
		/* check the key as given */
		if ((l = (*lookupfn)(sip)) != NULL)
			return l;
		realkey = (char *) sip->key;
		/* iterate over the superdomains of the key */
		for (cp = realkey; *cp;) {
			while (*cp && *cp != '.')
				++cp;
			while (*cp == '.')
				++cp;
			if (*(cp-1) == '.') {
				sip->key = cp-1;
				if ((l = (*lookupfn)(sip)) != NULL)
					return l;
			}
		}
		/* Still failed ?  Try to look for "." */
		sip->key = ".";
		if ((l = (*lookupfn)(sip)) != NULL)
			return l;
	}
	
	return NULL;
}
