/*
 *	Copyright 1997 by Lai Yiu Fai (ccyflai@ust.hk), all rights reserved.
 *
 *	Merge to standard ZMailer distribution with autoconfiguration by
 *	Matti Aarnio <mea@nic.funet.fi> 1997
 */

/* LINTLIBRARY */

#include "mailer.h"
#include "search.h"
#include "io.h"
#ifdef HAVE_LDAP
#include "lber.h"
#include "ldap.h"

typedef struct ldapmap_struct {
	char *ldaphost;
	int  ldapport;
	char *base;
	char *binddn;
	char *passwd;
	int  scope;
	char *filter;
	char *attr;
} LDAPMAP;

extern int deferit;
extern void v_set();


static LDAPMAP *
open_ldap(sip, caller)
	search_info *sip;
	char *caller;
{
	LDAPMAP *lmap;
	spkey_t symid;
	struct spblk *spl;
	FILE *fp;
	char buf[256];

	if (sip->file == NULL)
		return NULL;

	symid = symbol_db((u_char *)sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_files);
	if (spl == NULL || (lmap = (LDAPMAP *)spl->data) == NULL) {

		fp = fopen(sip->file, "r");
		if (fp == NULL) {
			++deferit;
			v_set(DEFER, DEFER_IO_ERROR);
			fprintf(stderr, "%s: cannot open %s!\n",
					caller, sip->file);			
			return NULL;
		}

		lmap = (LDAPMAP *) malloc(sizeof(LDAPMAP));
		if (spl == NULL)
			sp_install(symid, (u_char *)lmap, 0, spt_files);
		else
			spl->data = (u_char *)lmap;

		lmap->ldaphost = NULL;
		lmap->ldapport = LDAP_PORT;
		lmap->base = NULL;
		lmap->binddn = NULL;
		lmap->passwd = NULL;
		lmap->scope = LDAP_SCOPE_SUBTREE;
		lmap->filter = NULL;
		lmap->attr = NULL;
	
		while (fgets(buf, sizeof(buf), fp) != NULL)  {
			register char *p = buf;

			buf[sizeof(buf)-1] = '\0';	/* make sure we didn't
							   overfill the buf */
			buf[strlen(buf)-1] = '\0';	/* chop() */
			while (isascii(*p) && isspace(*p))
				p++;
			if (*p == '#')			/* skip comment */
				continue;

			if (strncasecmp(p, "base", 4) == 0)  {
				p += 4;
				while (isascii(*++p) && isspace(*p))
					continue;
				lmap->base = strdup(p);
			}
			else if (strncasecmp(p, "ldaphost", 8) == 0) {
				p += 8;
				while (isascii(*++p) && isspace(*p))
					continue;
				lmap->ldaphost = strdup(p);
			}
			else if (strncasecmp(p, "ldapport", 8) == 0) {
				p += 8;
				while (isascii(*++p) && isspace(*p))
					continue;
				lmap->ldapport = atoi(p);
			}
			else if (strncasecmp(p, "binddn", 6) == 0) {
				p += 6;
				while (isascii(*++p) && isspace(*p))
					continue;
				lmap->binddn = strdup(p);
			}
			else if (strncasecmp(p, "passwd", 6) == 0) {
				p += 6;
				while (isascii(*++p) && isspace(*p))
					continue;
				lmap->passwd = strdup(p);
			}
			else if (strncasecmp(p, "attr", 4) == 0) {
				p += 4;
				while (isascii(*++p) && isspace(*p))
					continue;
				lmap->attr = strdup(p);
			}
			else if (strncasecmp(p, "filter", 6) == 0) {
				p += 6;
				while (isascii(*++p) && isspace(*p))
					continue;
				lmap->filter = strdup(p);
			}
			else if (strncasecmp(p, "scope", 5) == 0) {
				p += 5;
				while (isascii(*++p) && isspace(*p))
					continue;
				if (strncasecmp(p, "base", 4) == 0)
					lmap->scope = LDAP_SCOPE_BASE;
				else if (strncasecmp(p, "one", 3) == 0)
					lmap->scope = LDAP_SCOPE_ONELEVEL;
				else if (strncasecmp(p, "sub", 3) == 0)
       	                         	lmap->scope = LDAP_SCOPE_SUBTREE;
			}
		}
		fclose(fp);
	}
	return lmap;
}

/*
 * Search LDAP for a key attribute.
 */
conscell *
search_ldap(sip)
	search_info *sip;
{
	LDAPMAP *lmap;

	LDAP *ld = NULL;
	LDAPMessage *msg = NULL, *entry;
	char filter[LDAP_FILT_MAXSIZ + 1];
	char **vals = NULL;
	char *attrs[] = {NULL, NULL};

	conscell *tmp;
	u_char *us = NULL;

	lmap = open_ldap(sip, "search_ldap");
	if (lmap == NULL)
		return NULL;

	ld = ldap_open(lmap->ldaphost, lmap->ldapport);
	if (ld == NULL || ldap_simple_bind_s(ld, lmap->binddn,
					     lmap->passwd) != LDAP_SUCCESS) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "search_ldap: cannot connect %s!\n",
				lmap->ldaphost);
		goto ldap_exit;
	}

	sprintf(filter, lmap->filter, (char *)sip->key);
	attrs[0] = lmap->attr;
	if (ldap_search_s(ld, lmap->base, lmap->scope, filter,
			  attrs, 0, &msg) != LDAP_SUCCESS) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "search_ldap: ldap_search_s error!\n");
		goto ldap_exit;		 
	}

	entry = ldap_first_entry(ld, msg);
	if (entry == NULL)
		goto ldap_exit;

	/* only get the first attribute, ignore others if defined */
	vals = ldap_get_values(ld, entry, lmap->attr);
	if (vals != NULL)
		/* if there is more that one, use the first */
		us = (u_char *)strsave(vals[0]);

ldap_exit:
	if (vals != NULL)
		ldap_value_free(vals);
	if (msg != NULL)
		ldap_msgfree(msg);
	if (ld != NULL)
		ldap_unbind_s(ld);

	return (us) ? newstring(us) : NULL;
}

void
close_ldap(sip)
	search_info *sip;
{
	LDAPMAP *lmap;
	struct spblk *spl;
	spkey_t symid;

	if (sip->file == NULL)
		return;
	symid = symbol_db((u_char *)sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL)
		sp_delete(spl, spt_modcheck);
	spl = sp_lookup(symid, spt_files);
	if (spl == NULL || (lmap = (LDAPMAP *)spl->data) == NULL)
		return;
	sp_delete(spl, spt_files);
	symbol_free_db(sip->file, spt_files->symbols);

	if (lmap->base != NULL)
		free(lmap->base);
	if (lmap->ldaphost != NULL)
		free(lmap->ldaphost);
	if (lmap->binddn != NULL)
		free(lmap->binddn);
	if (lmap->passwd != NULL)
		free(lmap->passwd);
	if (lmap->filter != NULL)
		free(lmap->filter);
	if (lmap->attr != NULL)
		free(lmap->attr);
	free(lmap);
	return;
}

int
modp_ldap(sip)
	search_info *sip;
{
        LDAPMAP *lmap;
        struct stat stbuf;
        struct spblk *spl;
        spkey_t symid;
        int rval;

        if (sip->file == NULL
            || (lmap = open_ldap(sip, "modp_ldap")) == NULL)
                return 0;
        if (lstat(sip->file, &stbuf) < 0) {
                fprintf(stderr, "modp_ldap: cannot fstat(\"%s\")!\n",
                                sip->file);
                return 0;
        }

        symid = symbol_db((u_char *)sip->file, spt_files->symbols);
        spl = sp_lookup(symid, spt_modcheck);
        if (spl != NULL) {
                rval = ((long)stbuf.st_mtime != (long)spl->data
                        || (long)stbuf.st_nlink != (long)spl->mark);
        } else
                rval = 0;
        sp_install(symid, (u_char *)((long)stbuf.st_mtime),
                   stbuf.st_nlink, spt_modcheck);
        return rval;
}
#endif	/* HAVE_LDAP */
