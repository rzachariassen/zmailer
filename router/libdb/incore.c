/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "mailer.h"
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

extern struct sptree *spt_loginmap, *spt_uidmap;

/*
 * In-core database maintenance.
 *
 * Note that the keys are stashed forever because of the symbol() lookup
 * thing; this puts a practical limitation on the usefullness of this.
 * If people start using this seriously we need to rethink the key->hashid
 * mechanism.
 */


static struct sptree * open_core __((search_info *));
static struct sptree *
open_core(sip)
	search_info *sip;
{
	struct sptree *spt;

	spt = (struct sptree *)sip->subtype;
	if (spt == NULL)
		return NULL;
	if (spt->symbols == NULL)
		spt->symbols = sp_init();
	if (spt->symbols == NULL)  /* Failed, damn! */
		return NULL;
	return spt;
}

/*
 * Search an incore database for a key.
 */


struct spblk *
lookup_incoresp(name, db)
	const char *name;
	struct sptree *db;
{
	spkey_t spk;

	if (db->symbols == NULL)
		db->symbols = sp_init();
	spk = symbol_lookup_db(name, db->symbols);
	if (spk == (spkey_t)0)
		return NULL;
	return sp_lookup(spk, db);
}

conscell *
search_core(sip)
	search_info *sip;
{
	struct sptree *db;
	struct spblk *spl;
	conscell *tmp;
	spkey_t spk;

	db = open_core(sip);
	if (db == NULL)
		return NULL;
	spk = symbol_lookup_db(sip->key, db->symbols);
	if (spk == (spkey_t)0)
		return NULL;
	spl = sp_lookup(spk, db);
	if (spl == NULL)
		return NULL;
	if (spl->data == NULL)
		return newstring(strnsave("", 1));
	return newstring(strsave((char *)spl->data));
}

/*
 * Free any information stored in this database.
 */

static int icfreedata __((struct spblk *));
static int
icfreedata(spl)
	struct spblk *spl;
{
	if (spl->data)
		free((char *)spl->data);
	return 0;
}

void
close_core(sip)
	search_info *sip;
{
	struct sptree *db;

	db = open_core(sip);
	if (db == NULL)
		return;
	if (db->symbols != NULL) {
		symbol_null_db(db->symbols);
	}
	if (db != spt_loginmap)
		sp_scan(icfreedata, (struct spblk *)NULL, db);
	sp_null(db);
}

/*
 * Add the indicated key/value pair to the database.
 */

int
add_incoresp(name, value, db)
     const char *name, *value;
     struct sptree *db;
{
	search_info si;
	si.subtype = (void*) db;
	si.key     = name;

	return add_core( &si, value );
}

int
addd_incoresp(name, value, db)
	const char *name;
	const void *value;
	struct sptree *db;
{
	struct spblk *spl;
	spkey_t spk;

	if (db->symbols == NULL)
		db->symbols = sp_init();
	spk = symbol_db(name, db->symbols);
	spl = sp_lookup(spk, db);
	if (spl == NULL)
		sp_install(spk, (const void*)value, 0, db);
	else {
		icfreedata(spl);
		spl->data = (const void *) value;
	}
	return 0;
}

int
add_core(sip, value)
	search_info *sip;
	const char *value;
{
	struct sptree *db;
	struct spblk *spl;
	spkey_t spk;
	memtypes oval;

	db = open_core(sip);
	if (db == NULL)
		return EOF;

	oval = stickymem;
	stickymem = MEM_MALLOC;
	if (value == NULL || *value == '\0')
		value = NULL;
	else
		value = strsave(value);
	stickymem = oval;

	spk = symbol_db(sip->key, db->symbols);
	spl = sp_lookup(spk, db);
	if (spl == NULL)
		sp_install(spk, (const void*)value, 0, db);
	else {
		icfreedata(spl);
		spl->data = (const void *) value;
	}

	return 0;
}

/*
 * Remove the indicated key from the database.
 */

int
remove_core(sip)
	search_info *sip;
{
	struct sptree *db;
	struct spblk *spl;
	spkey_t spk;

	db = open_core(sip);
	if (db == NULL)
		return EOF;
	spk = symbol_lookup_db(sip->key, db->symbols);
	if (spk == (spkey_t)0)
		return EOF;
	spl = sp_lookup(spk, db);
	if (spl == NULL) {
		fprintf(stderr, "remove_core: no such key as \"%s\"!\n",
				sip->key);
		return EOF;
	}
	icfreedata(spl);
	sp_delete(spl, db);
	symbol_free_db(sip->key, db->symbols);
	return 0;
}

/*
 * Print the database.
 */

static FILE *pcfp;

static int icprintNS __((struct spblk *));
static int
icprintNS(spl)
	struct spblk *spl;
{
	if (spl->data != NULL)
		fprintf(pcfp, "%d\t%s\n", (int)spl->key, (char *)spl->data);
	else
		fprintf(pcfp, "%d\n", spl->key);
	return 0;
}

static int icprintSN __((struct spblk *));
static int
icprintSN(spl)
	struct spblk *spl;
{
	fprintf(pcfp, "%s\t%ld\n", pname(spl->key), (long)spl->data);
	return 0;
}

static int icprintSS __((struct spblk *));
static int
icprintSS(spl)
	struct spblk *spl;
{
	if (spl->data != NULL)
		fprintf(pcfp, "%s\t%s\n", pname(spl->key), (char *)spl->data);
	else
		fprintf(pcfp, "%s\n", pname(spl->key));
	return 0;
}

void
print_core(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	struct sptree *db;

	db = open_core(sip);
	if (db == NULL)
		return;
	pcfp = outfp;
	if (db == spt_loginmap)
		sp_scan(icprintSN, (struct spblk *)NULL, db);
	else if (db == spt_uidmap)
		sp_scan(icprintNS, (struct spblk *)NULL, db);
	else
		sp_scan(icprintSS, (struct spblk *)NULL, db);
	fflush(outfp);
}

/*
 * Count the database.
 */

static int pc_cnt;

static int iccount __((struct spblk *));
static int iccount(spl)
	struct spblk *spl;
{
	++pc_cnt;
	return 0;
}

void
count_core(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	struct sptree *db;
	pc_cnt = 0;

	db = open_core(sip);
	if (db != NULL) {
	  sp_scan(iccount, (struct spblk *)NULL, db);
	}
	fprintf(outfp,"%d\n",pc_cnt);
	fflush(outfp);
}

void
owner_core(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	fprintf(outfp, "%d\n", getuid());
	fflush(outfp);
}
