/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include "mailer.h"

/* all users in this group are considered 'trusted'... i.e. From: is believed */
const char * trusted_group = "zmailer";

/* these are the users to be trusted if trusted_group doesn't exist */
const char * default_trusted[] = { "root", "daemon", "daemons", "uucp", 0 };

/* this group will own control and message files after the router is done. */
/* Users in this group can view the entire mail queue contents, if it doesn't
 * exist, the original permissions will prevail.
 */
char	*files_group = NULL;		/* if this is NULL, we use files_gid */
int	files_gid = 0;

/* the list of message headers containing addresses used to identify sender */
const char * prio_list[] = { "sender", "from", "reply-to", "errors-to", 0 };
	
/* the list of message headers containing addresses used for bouncing mail */
const char * err_prio_list[] = { "sender", "errors-to", 0 };

/* stdout and stderr end up in logdir/progname when router runs as a daemon */
const char * logdir = "/usr/spool/log";

/* suffix of the router configuration file, as in MAILSHARE/progname.suffix */
const char * cf_suffix = "cf";

/* how often (in seconds) should the router directory be scanned? */
u_int	sweepintvl = 15;

/* initial startup stability of router directory scan (boolean) */
int	stability = 1;

/* ongoing stability of router directory scan (boolean) */
int	real_stability = 0;

/* maximum number of Received headers, for primitive loop detection */
int	maxReceived = 50;

/* we want those nice tabs between the header field name and value */
#ifdef RFC822TABS
int	wanttabs = RFC822TABS;
#else
int	wanttabs = 1;
#endif

/* depending on what you postmaster wants from   $(filepriv ...) to see:
   022 for usual        644 or more strict,
   002 for more relaxed 664 view of things
   But see  filepriv "-M"   option!					*/
int filepriv_mask_dir = 022;	/* Directory */
int filepriv_mask_reg = 022;	/* File      */


struct sptree *spt_databases, *spt_files, *spt_modcheck;
struct sptree *spt_goodguys, *spt_uidmap, *spt_loginmap;
struct sptree *spt_fullnamemap, *spt_incoredbs, *spt_headers;
struct sptree *spt_eheaders;

struct sptree_init splaytrees[] = {
  /* { &spt_incoredbs,	0 }, */		/* incore database name -> splay tree */
{ &spt_databases,	0 },		/* database name -> descriptor */
{ &spt_files,		0 },		/* file name -> FILE * or DB * */
{ &spt_modcheck,	0 },		/* modtime and nlinks */
{ &spt_eheaders,	0 },		/* envelope header name -> descriptor */
{ &spt_headers,		"headers" },	/* header name -> descriptor */
{ &spt_goodguys,	"trusted" },	/* trusted uid -> boolean */
{ &spt_uidmap,		"pwuid" },	/* uid -> login name */
{ &spt_loginmap,	"pwnam" },	/* login name -> uid */
{ &spt_fullnamemap,	"fullname" },	/* login name -> full name */
{ 0, 0 }
};
