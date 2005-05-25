/*
 *	Copyright 1997 by Lai Yiu Fai (ccyflai@ust.hk), all rights reserved.
 *
 *	Merge to standard ZMailer distribution with autoconfiguration by
 *	Matti Aarnio <mea@nic.funet.fi> 1997; Code reorganization 1999
 *	to do db bind at open_ldap(), *only* searches at  search_ldap()..
 *
 *	Support code for LDAPv3, and report about need to handle server
 *	going away (e.g. restart LDAP lookups) by:
 *	   Jeff Warnica <jeffw@chebucto.ns.ca>
 */

/* LINTLIBRARY */

#include "mailer.h"
#include "search.h"
#include "io.h"
#include "libc.h"
#include <ctype.h>
#ifdef USE_LDAP
#include "lber.h"
#include "ldap.h"

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ 1024
#endif

typedef struct ldapmap_struct {
	  /* Setup parameters */

	char *ldaphost;
	int  ldapport;
	int   wildcards;
	char *uri;
	char *base;
	int  scope;
	char *binddn;
	char *passwd;

	char *filter;
	char *attr;
	int   protocol;
	int debug;
#ifdef HAVE_OPENSSL
	int  use_tls;
#endif
	  /* Bound state */
	LDAP *ld;
	int simple_bind_result;
	int authmethod;
#ifdef HAVE_SASL2    
	char *sasl_secprops;
	char *sasl_mech;
	char *sasl_realm;
	char *sasl_authc_id;
	char *sasl_authz_id;
	unsigned sasl_flags;
#endif    
} LDAPMAP;

struct berval passwd = { 0, NULL };
struct berval   *servcred; 
 
static int _config_switch(const char *);
static int _read_config(const char *, LDAPMAP *, const char *);
extern int deferit;
extern void v_set();

static void open_lmap_ __((LDAPMAP *lmap));
static void
open_lmap_ (lmap)
     LDAPMAP *lmap;
{
	int rc = 0, ret = 0;
    
	if (lmap->ld)
		ldap_unbind_s(lmap->ld);
	lmap->ld = NULL;
    
    
	if ( lmap->debug ) {
	  if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &lmap->debug )
	      != LBER_OPT_SUCCESS ) {
	    fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n",
		     lmap->debug );
	  }
	  if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &lmap->debug )
	      != LDAP_OPT_SUCCESS ) {
	    fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n",
		     lmap->debug );
	  }
	}
    
#if 0 
	if (lmap->ldaphost)
	  lmap->ld = ldap_open(lmap->ldaphost, lmap->ldapport);
#else /* openldap specific? */ 
	if( ( lmap->ldaphost != NULL || lmap->ldapport ) &&
	    ( lmap->uri == NULL ) ) {

	  /* construct URL  */
	  LDAPURLDesc url;
	  memset( &url, 0, sizeof(url));
         
	  url.lud_scheme = "ldap";
	  url.lud_host = lmap->ldaphost;
	  url.lud_port = lmap->ldapport;
	  url.lud_scope = LDAP_SCOPE_DEFAULT;
         
	  lmap->uri = ldap_url_desc2str( &url );
	}

	fprintf(stderr, "using URI: %s\n", lmap->uri);
	rc = ldap_initialize( &lmap->ld, lmap->uri );
    
	if( rc != LDAP_SUCCESS ) {
	  ldap_perror(lmap->ld, "ldap_initialize");
	  ret = -1;
	} else
	  ret = 0;
#endif
    
	if( ldap_set_option( lmap->ld, LDAP_OPT_PROTOCOL_VERSION,
			     &lmap->protocol ) != LDAP_OPT_SUCCESS ) {
	  fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
		   lmap->protocol);
	  ret = -1;
	}
#ifdef HAVE_OPENSSL 
	if (lmap->use_tls && ( ldap_start_tls_s( lmap->ld, NULL, NULL )
			       != LDAP_SUCCESS )) {
	  ldap_perror( lmap->ld, "ldap_start_tls" );		  
	  fprintf( stderr, "Could not setup ldap_start_tls (%d): %s\n",
		   rc, ldap_err2string(rc) );
	  ret = -1;
	}
#endif
#ifdef HAVE_SASL2
	if (lmap->sasl_secprops != NULL) {
	  rc = ldap_set_option( lmap->ld, LDAP_OPT_X_SASL_SECPROPS,
				(void *) lmap->sasl_secprops);
	  if( rc != LDAP_OPT_SUCCESS ) {
            fprintf( stderr,  "Could not set LDAP_OPT_X_SASL_SECPROPS: %s\n", lmap->sasl_secprops);
	    ret = -1;
	  }
	}
    
	if (lmap->authmethod == LDAP_AUTH_SASL) {
	  if ( ldap_sasl_bind_s( lmap->ld, lmap->binddn,
				 lmap->sasl_mech, &passwd,
				 NULL, NULL, NULL ) != LDAP_SUCCESS ) {
            ldap_perror( lmap->ld, "ldap_sasl_bind_s" );    
	    ret = -1;
	  }
	} else {
#endif
	  if ( ldap_bind_s( lmap->ld, lmap->binddn, passwd.bv_val, lmap->authmethod )
	       != LDAP_SUCCESS) {
	    ldap_perror( lmap->ld, "ldap_bind_s" );
	    ret = -1;
	  }
#ifdef HAVE_SASL2        
	}
#endif

	if (lmap->debug != 0) {
	  struct berval *retdata = NULL;
	  rc = ldap_whoami_s( lmap->ld, &retdata, NULL, NULL );
	  if( retdata != NULL ) {
	    fprintf(stderr, "logged in as: %s\n", ( retdata->bv_len == 0 ) ? "anonymous" : retdata->bv_val);
	  } else {
	    fprintf(stderr, "Error doing ldap_whoami_s: %s (%d)\n", ldap_err2string( rc ), rc );
	    ret = -1;
	  }
	}

	/* Mark if there are any errors... */
	lmap->simple_bind_result = ret;
}


static LDAPMAP *
open_ldap(sip, caller)
	search_info *sip;
	char *caller;
{
	LDAPMAP *lmap;
	spkey_t symid;
	struct spblk *spl;
	const char * masterconf;

	if (sip->file == NULL)
		return NULL;

	symid = symbol_db((u_char *)sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_files);

	if (spl == NULL || (lmap = (LDAPMAP *)spl->data) == NULL) {
        
		lmap = (LDAPMAP *) emalloc(sizeof(LDAPMAP));

		if (spl == NULL)
			sp_install(symid, (u_char *)lmap, 0, spt_files);
		else
			spl->data = (u_char *)lmap;

		memset(lmap, 0, sizeof(LDAPMAP));

		lmap->ldapport = LDAP_PORT;
		lmap->scope = LDAP_SCOPE_SUBTREE;

		lmap->protocol = LDAP_VERSION2;
		lmap->authmethod = -1;
#ifdef HAVE_OPENSSL
		lmap->use_tls = 0;
#endif

		masterconf = getzenv("LDAP_MASTER_CONF");
		if (masterconf != NULL) {
		  _read_config(masterconf, lmap, caller);
		}
		_read_config(sip->file, lmap, caller);

		open_lmap_(lmap);
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

	LDAPMessage *msg = NULL;
	char filter[LDAP_FILT_MAXSIZ + 1];
	char **vals = NULL, *attrs[] = {NULL, NULL}, *filterstring = NULL;
	char *s, *a, *dn, *matched_msg = NULL, *error_msg = NULL;
	BerElement  *ber;
	int i, num_entries, num_refs, parse_rc, rc, msgtype, slen;
	LDAPControl      **serverctrls;
	conscell *tmp = NULL, *tmp2 = NULL;
	int once = 1;

 redo_search:
	lmap = open_ldap(sip, "search_ldap");

	if (lmap == NULL || lmap->ld == NULL ||
	    lmap->simple_bind_result != LDAP_SUCCESS) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "search_ldap: cannot connect\n");
		goto ldap_exit;
	}

	filterstring = (char *)sip->key;

	sprintf(filter, lmap->filter, filterstring);
	attrs[0] = lmap->attr;

	if ( lmap->debug >0 ) {
	  printf("ldap_search_s(lmap->ld, %s, %i, %s, %s, 0, &msg)\n", 
		 lmap->base, lmap->scope, filter, attrs[0]);
	}
	rc = ldap_search_s(lmap->ld, lmap->base, lmap->scope, filter, attrs, 0, &msg);
	if (rc != LDAP_SUCCESS && once) {
	  once = 0;
	  close_ldap(sip,"search_ldap access error redo");
	  goto redo_search;
	}

	if (rc != LDAP_SUCCESS) {
	  ++deferit;
	  v_set(DEFER, DEFER_IO_ERROR);
	  ldap_perror(lmap->ld, "lmap_search_s");
	  /* fprintf(stderr, "search_ldap: ldap_search_s error: %s\n",
	             ldap_err2string( rc )); */
	  goto ldap_exit;		 
	}

	num_entries = ldap_count_entries( lmap->ld, msg );
	num_refs = ldap_count_references( lmap->ld, msg );

	/* Iterate through the results. */
	for ( msg = ldap_first_message( lmap->ld, msg ); msg != NULL; 
	      msg = ldap_next_message( lmap->ld, msg ) ) {
          msgtype = ldap_msgtype( msg );
          switch( msgtype ) {
               /* The result is a search reference. */
              case LDAP_RES_SEARCH_REFERENCE:
                fprintf(stderr, "search_ldap: got a search reference, but dont know how to deal with references!\n");
                goto ldap_exit;
                break;
              /* The result is an entry. */
              case LDAP_RES_SEARCH_ENTRY:
                  /* Get and print the DN of the entry. */
                  if (( dn = ldap_get_dn( lmap->ld, msg )) != NULL ) {
                      if ( lmap->debug >0 ) {
                          printf( "dn: %s\n", dn );
                      }
                    ldap_memfree( dn );
                  }
                  /* Iterate through each attribute in the entry. */
                  for ( a = ldap_first_attribute( lmap->ld, msg, &ber );
                  a != NULL; a = ldap_next_attribute( lmap->ld, msg, ber ) ) {
                    /* Get and print all values for each attribute. */
                    if (( vals = ldap_get_values( lmap->ld, msg, a )) != NULL ) {
                        if ( lmap->debug >0) {
                            for ( i = 0; vals[ i ] != NULL; i++ ) {
                                printf( "%s: %s\n", a, vals[ i ] );
                            }
                        }
                        slen = strlen(vals[0]);
                        s = dupnstr(vals[0], slen);
                        
                        if (tmp == NULL) {
                            tmp = tmp2 = newstring(s, slen);
                        } else {
                            cdr(tmp2) = newstring(s, slen);
                            tmp2 = cdr(tmp2);
                        }
                    }
                    ldap_memfree( a );
                  }
                  if ( ber != NULL ) {
                    ber_free( ber, 0 );
                  }
                  if ( lmap->debug >0 ) { printf( "\n" ); }
              break;
              /* The result is the final result sent by the server. */
              case LDAP_RES_SEARCH_RESULT:
                
                  /* Parse the final result received from the server. Note the last
                   argument is a non-zero value, which indicates that the
                   LDAPMessage structure will be freed when done. (No need
                   to call ldap_msgfree().) */
                  parse_rc = ldap_parse_result( lmap->ld, msg, &rc, &matched_msg, &error_msg, NULL, &serverctrls, 1 );
                  if ( parse_rc != LDAP_SUCCESS ) {
                      ++deferit;
                      v_set(DEFER, DEFER_IO_ERROR);
                      ldap_perror(lmap->ld, "ldap_parse_result");
                      goto ldap_exit;
                  }
                  /* Check the results of the LDAP search operation. */
                  if ( rc != LDAP_SUCCESS ) {
                      ++deferit;
                      v_set(DEFER, DEFER_IO_ERROR);
                      ldap_perror(lmap->ld, "ldap_search_ext");
                      goto ldap_exit;
                  } else {
                      if ( lmap->debug >0 ) {
                          printf( "Search completed successfully.\n"
                          "Entries found: %d\n"
                          "Search references returned: %d\n",
                          num_entries, num_refs );
                      }
                  }
              break;
          }

    }
    
ldap_exit:
	if (vals != NULL)
		ldap_value_free(vals);
  
	return tmp;
}

void
close_ldap(sip,comment)
	search_info *sip;
	const char *comment;
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

	if (lmap->ld != NULL)
		ldap_unbind_s(lmap->ld);
	/*    
	      if (lmap->ldaphost != NULL)
	        free(lmap->ldaphost);
	*/    

	if (lmap->base != NULL)
	  free(lmap->base);
	if (lmap->binddn != NULL)
	  free(lmap->binddn);
	if (lmap->passwd != NULL)
		free(lmap->passwd);
	if (lmap->filter != NULL)
		free(lmap->filter);
	if (lmap->attr != NULL)
		free(lmap->attr);
#ifdef HAVE_SASL2    
	if (lmap->sasl_secprops != NULL)
	  free(lmap->sasl_secprops);
	if (lmap->sasl_mech != NULL)
	  free(lmap->sasl_mech);
	if (lmap->sasl_realm != NULL)
	  free(lmap->sasl_realm);
	if (lmap->sasl_authc_id != NULL)
	  free(lmap->sasl_authc_id);
	if (lmap->sasl_authz_id != NULL)
	  free(lmap->sasl_authz_id);
#endif    
#if 0 /*openLDAP specific? */
	if (lmap->ldapuri != NULL)
	  free(lmap->ldapuri);
#endif
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
    
	if (sip->file == NULL)
	  return 0; /* No file defined */
    
	if ((lmap = open_ldap(sip, "modp_ldap")) == NULL)
	  return 0; /* Fails to open ??? */
    
	if (lmap->simple_bind_result != LDAP_SUCCESS)
	  return 1; /* Rebind might help ?? */
	
	if (lstat(sip->file, &stbuf) < 0) {
	  fprintf(stderr, "modp_ldap: cannot fstat(\"%s\")!\n", sip->file);
	  return 0;
	}
    
	symid = symbol_db((u_char *)sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL) {
	  rval = ((long)stbuf.st_mtime != (long)spl->data
		  || (long)stbuf.st_nlink != (long)spl->mark);
	} else {
	  rval = 0;
	}
    
	sp_install(symid, (u_char *)((long)stbuf.st_mtime), stbuf.st_nlink, spt_modcheck);
    
	return rval;
}


static int _config_switch(val)
	const char *val;
{
	if (!val) return 0;
    
	if (*val == '0' || *val == 'n' ||
	    (*val == 'o' && val[1] == 'f') || *val == 'f') {
	  return 0;
	} else if (*val == '1' || *val == 'y' ||
		   (*val == 'o' && val[1] == 'n') || *val == 't') {
	  return 1;
	} else {
	  return 0;
	}
}

static int _read_config(fname, lmap, caller)
    const char *fname;
    LDAPMAP *lmap;
    const char *caller;
{
	FILE *fp;
	char buf[256];

	fp = fopen(fname, "r");
	if (fp == NULL) {
	  ++deferit;
	  v_set(DEFER, DEFER_IO_ERROR);
	  fprintf(stderr, "%s: cannot open %s!\n",
		  caller, fname);
	  return -1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL)  {
	  register char *p = buf;
	  
	  buf[sizeof(buf)-1] = '\0';	/* make sure we didn't
					   overfill the buf */
	  if (buf[0] != 0)
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

	  } else if (strncasecmp(p, "uri", 3) == 0) {
	    p += 3;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->uri = strdup(p);

	  } else if (strncasecmp(p, "ldaphost", 8) == 0) {
	    p += 8;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->ldaphost = strdup(p);

	  } else if (strncasecmp(p, "ldapport", 8) == 0) {
	    p += 8;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->ldapport = atoi(p);

	  } else if (strncasecmp(p, "scope", 5) == 0) {
	    p += 5;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    if (strncasecmp(p, "base", 4) == 0)
	      lmap->scope = LDAP_SCOPE_BASE;
	    else if (strncasecmp(p, "one", 3) == 0)
	      lmap->scope = LDAP_SCOPE_ONELEVEL;
	    else if (strncasecmp(p, "sub", 3) == 0)
	      lmap->scope = LDAP_SCOPE_SUBTREE;

	  } else if (strncasecmp(p, "binddn", 6) == 0) {
	    p += 6;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->binddn = strdup(p);

	  } else if (strncasecmp(p, "passwd", 6) == 0) {
	    p += 6;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->passwd = strdup(p);
	    passwd.bv_val = ber_strdup(p);
	    passwd.bv_len = strlen( passwd.bv_val );

	  } else if (strncasecmp(p, "authmethod", 10) == 0) {
	    p += 10;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    if (strcasecmp(p, "simple") == 0) {
	      lmap->authmethod = LDAP_AUTH_SIMPLE;
	    } else if (strcasecmp(p, "sasl") == 0) {
#ifdef HAVE_SASL2
	      lmap->authmethod = LDAP_AUTH_SASL;
#else
	      ++deferit;
	      v_set(DEFER, DEFER_IO_ERROR);
	      fprintf(stderr, "%s: SASL authentication chosen, but not compiled in.\n", caller);
	      fclose(fp);
	      return -1;
#endif   
	    }
	  }
#ifdef HAVE_SASL2            
	  else if (strncasecmp(p, "SASL_SECPROPS", 13) == 0) {
	    p += 13;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->sasl_secprops = strdup(p);
	  }
	  else if (strncasecmp(p, "SASL_REALM", 11) == 0) {
	    p += 11;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->sasl_realm = strdup(p);
	  }
	  else if (strncasecmp(p, "SASL_MECH", 11) == 0) {
	    p += 11;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->sasl_mech = strdup(p);
	  }
	  else if (strncasecmp(p, "SASL_AUTHC_ID", 13) == 0) {
	    p += 13;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->sasl_authc_id = strdup(p);
	  }
	  else if (strncasecmp(p, "SASL_AUTHZ_ID", 13) == 0) {
	    p += 13;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->sasl_authz_id = strdup(p);
	  }
#endif            
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
	  else if (strncasecmp(p, "protocol", 8) == 0) {
	    p += 8; 
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    if (strncasecmp(p, "3", 1) == 0)
	      lmap->protocol = LDAP_VERSION3;
	    else if (strncasecmp(p, "2", 1) == 0)
	      lmap->protocol = LDAP_VERSION2;
	  }
	  else if (strncasecmp(p, "debug", 5) == 0) {
	    p += 5;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->debug = atoi(p);
	  }
#ifdef HAVE_OPENSSL
	  else if (strncasecmp(p, "start_tls", 9) == 0) {
	    p += 9;
	    while (isascii(*++p) && isspace(*p))
	      continue;
	    lmap->use_tls = _config_switch(p);			
	  }
#endif            
	}
        
	fclose(fp);
        return 1;
}
 
#endif	/* USE_LDAP */
