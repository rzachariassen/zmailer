/*
 *	Copyright 1991 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "mailer.h"
#include <ctype.h>
#include <string.h>
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

#include "../prototypes.h"

extern struct sptree *spt_headers, *spt_eheaders;

/*
 * RFC822 header list maintenance.
 */


/* This initializes the list of headers to which we attach specific semantics */

struct headerinfo mandatory_hdrs[] = {
{ "bcc",		Addresses,	Recipient,	normal		},
{ "cc",			AddressList,	Recipient,	normal		},
{ "from",		AMailboxList,	Sender,		normal		},
{ "message-id",		MessageID,	nilUserType,	normal		},
{ "reply-to",		AddressList,	Sender,		normal		},
{ "resent-bcc",		Addresses,	Recipient,	Resent		},
{ "resent-cc",		AddressList,	Recipient,	Resent		},
{ "resent-from",	AMailboxList,	Sender,		Resent		},
{ "resent-message-id",	MessageID,	nilUserType,	Resent		},
{ "resent-reply-to",	AddressList,	Sender,		Resent		},
{ "resent-sender",	Mailbox,	Sender,		Resent		},
{ "resent-to",		AddressList,	Recipient,	Resent		},
{ "sender",		Mailbox,	Sender,		normal		},
{ "to",			AddressList,	Recipient,	normal		},
};

struct headerinfo optional_hdrs[] = {
{ "return-receipt-to",	AddressList,	Sender,		normal		},
#if 0
{ "return-path",	AMailboxList,	nilUserType,	normal		},
#endif
{ "date",		DateTime,	nilUserType,	normal		},
{ "resent-date",	DateTime,	nilUserType,	Resent		},
{ "encrypted",		Encrypted,	nilUserType,	normal		},
{ "errors-to",		AddressList,	Sender,		normal		},
{ "obsoletes",		MessageIDList,	nilUserType,	normal		},
#if 0
{ "keywords",		PhraseList,	nilUserType,	normal		},
{ "references",		References,	nilUserType,	normal		},
{ "in-reply-to",	References,	nilUserType,	normal		},
{ "received",		Received,	nilUserType,	normal		},
#endif
};

struct headerinfo envelope_hdrs[] = {
{ "authinfo",	nilHeaderSemantics,	nilUserType,	eIdentinfo	},
{ "bodytype",	nilHeaderSemantics,	nilUserType,	eBodytype	},
{ "channel",		AnyWord,	nilUserType,	eChannel	},
{ "comment",	nilHeaderSemantics,	nilUserType,	eComment	},
{ "env-end",	nilHeaderSemantics,	nilUserType,	eEnvEnd		},
{ "env-eof",	nilHeaderSemantics,	nilUserType,	eEnvEnd		},
{ "envid",	nilHeaderSemantics,	nilUserType,	eEnvid		},
{ "external",	nilHeaderSemantics,	nilUserType,	eExternal	},
{ "from",		AMailboxList,	Sender,		eFrom		},
{ "fullname",		Phrase,		nilUserType,	eFullname	},
{ "identinfo",	nilHeaderSemantics,	nilUserType,	eIdentinfo	},
{ "loginname",		UserAtDomain,	nilUserType,	ePrettyLogin	},
{ "notaryret",	nilHeaderSemantics,	nilUserType,	eNotaryRet	},
{ "rcvdfrom",		UserAtDomain,	nilUserType,	eRcvdFrom	},
{ "to",			AddressList,	Recipient,	eTo		},
{ "todsn",	nilHeaderSemantics,	Recipient,	eToDSN		},
{ "user",		Mailbox,	nilUserType,	eUser		},
{ "verbose",		AnyWord,	nilUserType,	eVerbose	},
{ "via",		AnyWord,	nilUserType,	eVia		},
{ "with",		AnyWord,	nilUserType,	eWith		},
};

struct semtrans {
	const char	*name;
	HeaderSemantics semantics;	/* S/SL rule name in rfc822.ssl */
} hdrsemtable[] = {
{	"AMailboxList",		AMailboxList		},
{	"Address",		Address			},
{	"Addresses",		Addresses		},
{	"AddressList",		AddressList		},
{	"AnyWord",		AnyWord			},
{	"DateTime",		DateTime		},
{	"DomainName",		DomainName		},
{	"Encrypted",		Encrypted		},
{	"LocalPart",		LocalPart		},
{	"Mailbox",		Mailbox			},
{	"Mailboxes",		Mailboxes		},
{	"MailboxList",		MailboxList		},
{	"MessageID",		MessageID		},
{	"MessageIDList",	MessageIDList		},
{	"Phrase",		Phrase			},
{	"Phrases",		Phrases			},
{	"PhraseList",		PhraseList		},
{	"Received",		Received		},
{	"References",		References		},
{	"Route",		Route			},
{	"RouteAddress",		RouteAddress		},
{	"RouteAddressInAngles",	RouteAddressInAngles	},
{	"SubDomain",		SubDomain		},
{	"UserAtDomain",		UserAtDomain		},
};

static HeaderSemantics semname2enum __((const char *));

static HeaderSemantics
semname2enum(name)
	const char *name;
{
	unsigned int i;

	for (i = 0; i < (sizeof hdrsemtable / sizeof hdrsemtable[0]); ++i) {
	  if (cistrcmp(name, hdrsemtable[i].name) == 0)
	    return hdrsemtable[i].semantics;
	}
	return nilHeaderSemantics;
}

static const char * semenum2name __((HeaderSemantics d));
static const char *
semenum2name(d)
	HeaderSemantics d;
{
	unsigned int i;

	for (i = 0; i < (sizeof hdrsemtable / sizeof hdrsemtable[0]); ++i) {
	  if (d == hdrsemtable[i].semantics)
	    return hdrsemtable[i].name;
	}
	return NULL;
}

void
init_header()
{
	struct headerinfo rh, *rhp;
	unsigned int i;
	spkey_t symid;

	if (spt_headers == NULL)           spt_headers           = sp_init();
	if (spt_headers->symbols == NULL)  spt_headers->symbols  = sp_init();
	if (spt_eheaders == NULL)          spt_eheaders          = sp_init();
	if (spt_eheaders->symbols == NULL) spt_eheaders->symbols = sp_init();

	for (i = 0; i < (sizeof mandatory_hdrs / sizeof mandatory_hdrs[0]); ++i) {
	  rh.hdr_name  = mandatory_hdrs[i].hdr_name;
	  rh.semantics = mandatory_hdrs[i].semantics;
	  rh.user_type = mandatory_hdrs[i].user_type;
	  rh.class     = mandatory_hdrs[i].class;
	  rhp  = (struct headerinfo *)emalloc(sizeof (struct headerinfo));
	  *rhp = rh;
	  symid = symbol_db(rhp->hdr_name, spt_headers->symbols);
	  sp_install(symid, (void *)rhp, 1, spt_headers);
	}
	for (i = 0; i < (sizeof optional_hdrs / sizeof optional_hdrs[0]); ++i) {
	  rh.hdr_name  = optional_hdrs[i].hdr_name;
	  rh.semantics = optional_hdrs[i].semantics;
	  rh.user_type = optional_hdrs[i].user_type;
	  rh.class     = optional_hdrs[i].class;
	  rhp  = (struct headerinfo *)emalloc(sizeof (struct headerinfo));
	  *rhp = rh;
	  symid = symbol_db(rhp->hdr_name, spt_headers->symbols);
	  sp_install(symid, (void *)rhp, 0, spt_headers);
	}
	for (i = 0; i < (sizeof envelope_hdrs / sizeof envelope_hdrs[0]); ++i) {
	  rh.hdr_name  = envelope_hdrs[i].hdr_name;
	  rh.semantics = envelope_hdrs[i].semantics;
	  rh.user_type = envelope_hdrs[i].user_type;
	  rh.class     = envelope_hdrs[i].class;
	  rhp = (struct headerinfo *)emalloc(sizeof (struct headerinfo));
	  *rhp = rh;
	  symid = symbol_db(rhp->hdr_name, spt_eheaders->symbols);
	  sp_install(symid, (void *)rhp, 0, spt_eheaders);
	}
}

static struct sptree * open_header __((search_info *));

static struct sptree *
open_header(sip)
	search_info *sip;
{
	if (sip->subtype == NULL)
	  return NULL;
	return (struct sptree *)sip->subtype;
}

struct headerinfo *
find_header(hdb, name)
	struct sptree *hdb;
	const char *name;
{
	struct spblk *spl = NULL;
	register char *cp;
	spkey_t spk;
#ifdef	USE_ALLOCA
	int len = strlen(name);
	char *buffer = alloca(len+1);
#else
	static int blen = 0;
	static char *buffer = NULL;
	int len;

	if (buffer == NULL) {
		blen = 64;
		buffer = malloc(blen);
	}
	len = strlen(name);
	if ( len >= blen ) {
	  while (len < blen)
	    blen <<= 1;
	  buffer = realloc(buffer, blen);
	}
#endif
	strcpy(buffer, name);
	for (cp = buffer; *cp != '\0'; ++cp) {
	  int c = (*cp) & 0xFF;
	  if (isascii(c) && isupper(c))
	    *cp = tolower(c);
	}

	spk = symbol_lookup_db(buffer, hdb->symbols);
	if (spk != (spkey_t)0)
	  spl = sp_lookup(spk, hdb);
	if (spl == NULL)
	  return NULL;
	return (struct headerinfo *)spl->data;
}

/*
 * Search headers database for a key.
 */

conscell *
search_header(sip)
	search_info *sip;
{
	struct sptree *hdb;
	struct headerinfo *rhp;
	char buf[1024];
	int slen;
	char *s;

	hdb = open_header(sip);
	if (hdb == NULL)
	  return NULL;
	rhp = find_header(hdb, sip->key);
	if (rhp == NULL)
	  return NULL;
	sprintf(buf, "%s:%s:%s",
		semenum2name(rhp->semantics),
		rhp->user_type  == Sender    ? "Sender"    :
		(rhp->user_type == Recipient ? "Recipient" : ""),
		rhp->class      == Resent    ? "Resent"    : "");
	slen = strlen(buf);
	s = dupnstr(buf, slen);
	return newstring(s, slen);
}

/*
 * Free any information stored in this database.
 */

static int hdfreedata __((struct spblk *));
static int
hdfreedata(spl)
	struct spblk *spl;
{
	if (spl->data)
	  free((void *)spl->data);
	return 0;
}

void
close_header(sip,comment)
	search_info *sip;
	const char *comment;
{
	struct sptree *hdb;

	hdb = open_header(sip);
	if (hdb == NULL)
	  return;
	sp_scan(hdfreedata, (struct spblk *)NULL, hdb);
	sp_null(hdb);
}

static int enormal __((const char *));
static int
enormal(s)
	const char *s;
{
	return (s == NULL || *s == '\0' || cistrcmp(s, "none") == 0 ||
		cistrcmp(s, "normal") == 0 || cistrcmp(s, "-") == 0);
}

/*
 * Add the indicated key/value pair to the database.
 */

int
add_header(sip, cvalue)
	search_info *sip;
	const char *cvalue;
{
	struct sptree *hdb;
	struct spblk *spl;
	char *cp, *value;
#ifndef USE_ALLOCA
	char *vbuf;
#endif
	char *wcp;
	char *lcbuf;
	struct headerinfo rh, *rhp;
	int keylen;
	spkey_t spk;

	hdb = open_header(sip);
	if (hdb == NULL)
	  return EOF;

	/* parse a line like:  rulename:sender/recipient/-:resent/normal */
	if (*cvalue == '\0') {
	  fprintf(stderr, "add_header: null header specification\n");
	  return EOF;
	}

	keylen = strlen(cvalue);
#ifdef USE_ALLOCA
	value  = (char*)alloca(keylen+1);
#else
	value  = (char*)emalloc(keylen+1);
	vbuf   = value;
#endif
	memcpy(value, cvalue, keylen+1);

	cp = strchr(value, ':');
	if (cp == NULL) {
	  fprintf(stderr,
		  "add_header: missing sender/recipient and resent/normal fields in value\n");
#ifndef USE_ALLOCA
	  free(vbuf);
#endif
	  return EOF;
	}
	*cp++ = '\0';
	rh.semantics = semname2enum(value);
	if (rh.semantics == nilHeaderSemantics) {
	  fprintf(stderr, "add_header: unknown parse rule '%s'\n", value);
#ifndef USE_ALLOCA
	  free(vbuf);
#endif
	  return EOF;
	}
	value = cp;
	if (*value == '\0') {
#ifndef USE_ALLOCA
	  free(vbuf);
#endif
	  return EOF;
	}
	cp = strchr(value, ':');
	if (cp == NULL) {
	  fprintf(stderr,
		  "add_header: missing resent/normal field in value\n");
#ifndef USE_ALLOCA
	  free(vbuf);
#endif
	  return EOF;
	}
	*cp++ = '\0';
	if (enormal(value))
	  rh.user_type = nilUserType;
	else if (cistrcmp(value, "Sender") == 0)
	  rh.user_type = Sender;
	else if (cistrcmp(value, "Recipient") == 0)
	  rh.user_type = Recipient;
	else {
	  fprintf(stderr,
		  "add_header: sender/recipient misspecified as '%s'\n",
		  value);
#ifndef USE_ALLOCA
	  free(vbuf);
#endif
	  return EOF;
	}
	value = cp;
	cp = strchr(value, ':');
	if (cp != NULL) {
	  fprintf(stderr, "add_header: junk at end of value: '%s'\n",
		  value);
#ifndef USE_ALLOCA
	  free(vbuf);
#endif
	  return EOF;
	}
	if (enormal(value))
	  rh.class = normal;
	else if (cistrcmp(value, "Resent") == 0)
	  rh.class = Resent;
	else {
	  fprintf(stderr,
		  "add_header: resent/normal misspecified as '%s'\n",
		  value);
#ifndef USE_ALLOCA
	  free(vbuf);
#endif
	  return EOF;
	}

	/* make sure the key is lowercase, and
	   has only appropriate characters */

	keylen = strlen(sip->key);
#ifdef USE_ALLOCA
	lcbuf = alloca(keylen+1);
#else
	lcbuf = (char*) emalloc(keylen+1);
#endif
	memcpy(lcbuf, sip->key, keylen+1);
	for (wcp = lcbuf; *wcp != '\0'; ++wcp) {
	  int c = (*wcp) & 0xFF;
	  if (c != '-' && (!isalpha(c) || isspace(c) || c == ':')) {
	    fprintf(stderr,
		    "add_header: bad character in key '%s'\n",
		    sip->key);
#ifndef USE_ALLOCA
	    free(lcbuf);
#endif
	    return EOF;
	  }
	  if (isupper(c))
	    *wcp = tolower(c);
	  else
	    *wcp = c;
	}

	rh.hdr_name = sip->key;

	rhp  = (struct headerinfo *)emalloc(sizeof (struct headerinfo));
	*rhp = rh;

	spk = symbol_db(sip->key, hdb->symbols);
	spl = sp_lookup(spk, hdb);
	if (spl == NULL)
	  sp_install(spk, (void *)rhp, 0, hdb);
	else if (spl->mark == 0) {
	  hdfreedata(spl);
	  spl->data = (void *)rhp;
	} else {
	  free((void *)rhp);
	  fprintf(stderr,
		  "add_header: cannot change permanent definition of '%s'\n",
		  sip->key);
#ifndef USE_ALLOCA
	  free(lcbuf);
	  free(vbuf);
#endif
	  return EOF;
	}
#ifndef USE_ALLOCA
	free(lcbuf);
	free(vbuf);
#endif

	return 0;
}

/*
 * Remove the indicated key from the database.
 */

int
remove_header(sip)
	search_info *sip;
{
	struct sptree *hdb;
	struct spblk *spl = NULL;
	spkey_t spk;

	hdb = open_header(sip);
	if (hdb == NULL)
	  return EOF;
	spk = symbol_lookup_db(sip->key, hdb->symbols);
	if ((spkey_t)0 != spk)
	  spl = sp_lookup(spk, hdb);
	if (spl == NULL) {
	  fprintf(stderr, "remove_header: no such key as \"%s\"!\n",
		  sip->key);
	  return EOF;
	} else if (spl->mark == 1) {
	  fprintf(stderr, "remove_header: cannot remove permanent definition of '%s'\n", sip->key);
	  return EOF;
	}
	hdfreedata(spl);
	sp_delete(spl, hdb);
	return 0;
}

/*
 * Print the database.
 */

static FILE *pcfp;

static int hdprintdata __((struct spblk *));
static int
hdprintdata(spl)
	struct spblk *spl;
{
	const struct headerinfo *rhp;

	rhp = (const struct headerinfo *)spl->data;
	fprintf(pcfp, "%-16s\t%s:%s:%s (%s)\n", pname(spl->key),
		semenum2name(rhp->semantics),
		rhp->user_type  == Sender    ? "Sender"    :
		(rhp->user_type == Recipient ? "Recipient" : "-"),
		rhp->class      == Resent    ? "Resent"    : "-",
		spl->mark       == 0         ? "optional"  : "permanent");
	return 0;
}


void
print_header(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	struct sptree *hdb;

	hdb = open_header(sip);
	if (hdb == NULL)
	  return;
	pcfp = outfp;
	sp_scan(hdprintdata, (struct spblk *)NULL, hdb);
	fflush(outfp);
}

/* Count the database */

static int   pc_cnt;

static int hdcountdata __((struct spblk *));
static int
hdcountdata(spl)
	struct spblk *spl;
{
	++pc_cnt;
	return 0;
}

void
count_header(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	struct sptree *hdb;
	pc_cnt = 0;

	hdb = open_header(sip);
	if (hdb != NULL)
	  sp_scan(hdcountdata, (struct spblk *)NULL, hdb);
	fprintf(outfp,"%d\n",pc_cnt);
	fflush(outfp);
}

void
owner_header(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	fprintf(outfp, "%d\n", getuid());
	fflush(outfp);
}
