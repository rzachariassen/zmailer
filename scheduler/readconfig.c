/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2001
 */

#include "mailer.h"
#include <sfio.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include "scheduler.h"
#include "prototypes.h"
#include "mail.h"
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h> /* for syspriority .. */
#endif

#include "libz.h"
#include "libc.h"

#define SKIPSPACE(Y) while (*Y == ' ' || *Y == '\t' || *Y == '\n') ++Y
#define SKIPTEXT(Y)  while (*Y && *Y != ' ' && *Y != '\t' && *Y != '\n') ++Y
#define SKIPDIGIT(Y) while ('0' <= *Y && *Y <= '9') ++Y

static void celink __((struct config_entry *, struct config_entry **, struct config_entry **, int copy));
static int readtoken __((Sfio_t *fp, char *buf, int buflen, int *linenump));
static int paramparse __((char *line));

#define RCKEYARGS __((char *key, char *arg, struct config_entry *ce))

static int rc_command		RCKEYARGS;
static int rc_expform		RCKEYARGS;
static int rc_expiry		RCKEYARGS;
static int rc_expiry2		RCKEYARGS;
static int rc_group		RCKEYARGS;
static int rc_interval		RCKEYARGS;
static int rc_maxchannel	RCKEYARGS;
static int rc_maxring		RCKEYARGS;
static int rc_maxta		RCKEYARGS;
static int rc_maxthr		RCKEYARGS;
static int rc_idlemax		RCKEYARGS;
static int rc_retries		RCKEYARGS;
static int rc_reporttimes	RCKEYARGS;
static int rc_user		RCKEYARGS;
static int rc_skew		RCKEYARGS;
static int rc_bychannel		RCKEYARGS;
static int rc_ageorder		RCKEYARGS;
static int rc_queueonly		RCKEYARGS;
static int rc_wakeuprestartonly	RCKEYARGS;
static int rc_deliveryform	RCKEYARGS;
static int rc_overfeed		RCKEYARGS;
static int rc_priority		RCKEYARGS;
static int rc_nice		RCKEYARGS;
static int rc_syspriority	RCKEYARGS;
static int rc_sysnice		RCKEYARGS;

extern int errno;

struct config_entry *default_entry = NULL;
struct config_entry *rrcf_head     = NULL;

/* where the  MAILQv2  authentication dataset file is ? */
const char * mq2authfile = NULL;


static struct rckeyword {
	const char	*name;
	int		(*parsef)();
} rckeys[] = {
{	"ageorder",		rc_ageorder	},	/* boolean */
{	"bychannel",		rc_bychannel	},	/* boolean */
{	"command",		rc_command	},	/* array of strings */
{	"deliveryform",		rc_deliveryform	},	/* string */
{	"expiry",		rc_expiry	},	/* time */
{	"expiry2",		rc_expiry2	},	/* time */
{	"expiryform",		rc_expform	},	/* string */
{	"group",		rc_group	},	/* number */
{	"idlemax",		rc_idlemax	},	/* time */
{	"interval",		rc_interval	},	/* time */
{	"maxchannel",		rc_maxchannel	},	/* number */
{	"maxchannels",		rc_maxchannel	},	/* number */
{	"maxring",		rc_maxring	},	/* number */
{	"maxrings",		rc_maxring	},	/* number */
{	"maxta",		rc_maxta	},	/* number */
{	"maxthr",		rc_maxthr	},	/* number */
{	"maxtransport",		rc_maxta	},	/* number */
{	"maxtransports",	rc_maxta	},	/* number */
{	"nice",			rc_nice		},	/* number */
{	"overfeed",		rc_overfeed	},	/* number */
{	"priority",		rc_priority	},	/* number */
{	"queueonly",		rc_queueonly	},	/* boolean */
{	"reporttimes",		rc_reporttimes	},	/* array of numbers */
{	"retries",		rc_retries	},	/* array of numbers */
{	"skew",			rc_skew		},	/* number */
{	"sysnice",		rc_sysnice	},	/* number */
{	"syspriority",		rc_syspriority	},	/* number */
{	"user",			rc_user		},	/* number */
{	"wakeuprestartonly",	rc_wakeuprestartonly },	/* boolean */
{	NULL,			0		}
};


#define ISS(s) ((s)?(s):"<NULL>")
void
defaultconfigentry(ce,defaults)
	struct config_entry *ce, *defaults;
{
	if (defaults && ce != defaults) {
	  /* Use the configurations script defaults.. */
	  ce->next = NULL;
#if 0
	  ce->mark = 0;
#endif

	  ce->interval		= defaults->interval;
	  ce->idlemax		= defaults->idlemax;
	  ce->expiry		= defaults->expiry;
	  ce->expiry2		= defaults->expiry2;
	  ce->expiryform	= defaults->expiryform;
	  ce->uid		= defaults->uid;
	  ce->gid		= defaults->gid;
	  ce->command		= defaults->command;
	  ce->flags		= defaults->flags;
	  ce->maxkids		= defaults->maxkids;
	  ce->maxkidChannel	= defaults->maxkidChannel;
	  ce->maxkidThread	= defaults->maxkidThread;
	  ce->maxkidThreads	= defaults->maxkidThreads;
	  ce->argv		= defaults->argv;
	  ce->nretries		= defaults->nretries;
	  ce->retries		= defaults->retries;
	  ce->reporttimes[0]	= defaults->reporttimes[0];
	  ce->reporttimes[1]	= defaults->reporttimes[1];
	  ce->reporttimes[2]	= defaults->reporttimes[2];
	  ce->reporttimes[3]	= defaults->reporttimes[3];
	  ce->skew		= defaults->skew;
	  ce->deliveryform	= defaults->deliveryform;
	  ce->overfeed		= defaults->overfeed;
	  ce->priority		= defaults->priority;
	} else if (defaults == NULL) {
	  /* Compile these defaults in.. Only for the "*" / "* / *" entry.. */
	  ce->next	= NULL;
#if 0
	  ce->mark	= 0;
#endif

	  ce->interval	= -1;
	  ce->idlemax   = -1;
	  ce->expiry	= -1;
	  ce->expiry2	= -1;
	  ce->expiryform = NULL;
	  ce->uid	= -1;
	  ce->gid	= -1;
	  ce->command	= NULL;
	  ce->flags	= 0;
	  ce->maxkids	= -1;
	  ce->maxkidChannel = -1;
	  ce->maxkidThread  =  1;
	  ce->maxkidThreads = -1;
	  ce->argv	= NULL;
	  ce->nretries	= 0;
	  ce->retries	= NULL;
	  ce->reporttimes[0] = 0;
	  ce->reporttimes[1] = 0;
	  ce->reporttimes[2] = 0;
	  ce->reporttimes[3] = 0;
	  ce->skew	= 5;
	  ce->deliveryform = NULL;
	  ce->overfeed	= 0;
	  ce->priority  = 0; /* nice(0) -- no change */
	}
}

void
vtxprint(vp)
	struct vertex *vp;
{
	int i;
	struct config_entry *ce = &(vp->thgrp->ce);

	if (vp->orig[L_CHANNEL] != NULL && vp->orig[L_HOST] != NULL)
	  sfprintf(sfstdout, "%s/%s", vp->orig[L_CHANNEL]->name,
		   vp->orig[L_HOST]->name);
	else
	  sfprintf(sfstdout, "%s/%s", ISS(ce->channel), ISS(ce->host));
	sfprintf(sfstdout," %p  mark %d\n",	ce, ce->mark);
	sfprintf(sfstdout,"\tinterval %d\n",	(int)ce->interval);
	sfprintf(sfstdout,"\tidlemax %d\n",	ce->idlemax);
	sfprintf(sfstdout,"\texpiry %d\n",	(int)ce->expiry);
	sfprintf(sfstdout,"\texpiry2 %d\n",	(int)ce->expiry2);
	sfprintf(sfstdout,"\texpiryform %s\n",	ISS(ce->expiryform));
	sfprintf(sfstdout,"\tdeliveryform %s\n", ISS(ce->deliveryform));
	sfprintf(sfstdout,"\tuid %d\n",		ce->uid);
	sfprintf(sfstdout,"\tgid %d\n",		ce->gid);
	sfprintf(sfstdout,"\tcommand %s\n",	ISS(ce->command));
	sfprintf(sfstdout,"\tflags:");
	if (ce->flags == 0)
	  sfprintf(sfstdout," (none)");
	else {
	  if (ce->flags & CFG_WITHHOST)  sfprintf(sfstdout," WITHHOST");
	  if (ce->flags & CFG_AGEORDER)  sfprintf(sfstdout," AGEORDER");
	  if (ce->flags & CFG_QUEUEONLY) sfprintf(sfstdout," QUEUEONLY");
	  if (ce->flags & CFG_WAKEUPRESTARTONLY)sfprintf(sfstdout,
							 " WAKEUPRESTARTONLY");
	}
	sfprintf(sfstdout,"\n");
	sfprintf(sfstdout,"\tmaxkids %d\n",		ce->maxkids);
	sfprintf(sfstdout,"\tmaxkidChannel %d\n",	ce->maxkidChannel);
	sfprintf(sfstdout,"\tmaxkidThread  %d\n",	ce->maxkidThread);
	sfprintf(sfstdout,"\tmaxkidThreads %d\n",	ce->maxkidThreads);
	sfprintf(sfstdout,"\toverfeed %d\n",		ce->overfeed);

	if (ce->priority >= 80)
	  sfprintf(sfstdout,"\tpriority %d\n",	ce->priority - 100);
	else
	  sfprintf(sfstdout,"\tnice %d\n",		ce->priority);

	if (ce->argv != NULL) {
	  for (i = 0; ce->argv[i] != NULL; ++i)
	    sfprintf(sfstdout,"\targv[%d] = %s\n", i, ce->argv[i]);
	}

	sfprintf(sfstdout,"\tnretries %d\n", ce->nretries);
	if (ce->nretries > 0) {
	  sfprintf(sfstdout,"\tretries = (");
	  for (i = 0; i < ce->nretries ; ) {
	    sfprintf(sfstdout,"%d", ce->retries[i]);
	    ++i;
	    if (i < ce->nretries)
	      sfprintf(sfstdout," ");
	  }
	  sfprintf(sfstdout,")\n");
	}

	sfprintf(sfstdout,"\treporttimes = (");
	for (i = 0; i < 4 ; ++i ) {
	  sfprintf(sfstdout,"%d", ce->reporttimes[i]);
	  if (i < 3)
	    sfprintf(sfstdout," ");
	}
	sfprintf(sfstdout,")\n");

	sfprintf(sfstdout,"\tskew %d\n", ce->skew);
}

static void
celink(ce, headp, tailp, copy)
	struct config_entry *ce;
	struct config_entry **headp, **tailp;
	int copy;
{
	if (ce == default_entry && *headp != NULL && *tailp != NULL)
	  return; /* XX: ?? */

	if ((*headp) == NULL)
	  (*headp) = (*tailp) = ce;
	else {
	  (*tailp)->next = ce;
	  (*tailp) = ce;

	  if (!copy) return;

	  for (ce = (*headp); ce != (*tailp); ce = ce->next) {

	    if (verbose)
	      sfprintf(sfstdout,"celink() ce = %p  mark=%d\n", ce, ce->mark);

	    if (ce->mark == 0) continue;
	    ce->mark = 0;
	    ce->interval	= (*tailp)->interval;
	    ce->idlemax		= (*tailp)->idlemax;
	    ce->expiry		= (*tailp)->expiry;
	    ce->expiry2		= (*tailp)->expiry2;
	    ce->expiryform	= (*tailp)->expiryform;
	    ce->uid		= (*tailp)->uid;
	    ce->gid		= (*tailp)->gid;
	    ce->command		= (*tailp)->command;
	    ce->flags		= (*tailp)->flags;
	    ce->maxkids		= (*tailp)->maxkids;
	    ce->maxkidChannel	= (*tailp)->maxkidChannel;
	    ce->maxkidThread	= (*tailp)->maxkidThread;
	    ce->maxkidThreads	= (*tailp)->maxkidThreads;
	    ce->argv		= (*tailp)->argv;
	    ce->nretries	= (*tailp)->nretries;
	    ce->retries		= (*tailp)->retries;
	    ce->overfeed	= (*tailp)->overfeed;
	    ce->priority	= (*tailp)->priority;
	  }
	}
}

struct config_entry *
readconfig(file)
	const char *file;
{
	char *cp, *s, *a, line[BUFSIZ];
	int errflag, n;
	struct config_entry *ce, *head, *tail;
	struct rckeyword *rckp;
	struct vertex v;
	Sfio_t *fp;
	int linenum = 0;
	int attrs = 0;

	ce = head = tail = NULL;
	errflag = 0;

	if ((fp = sfopen(NULL, file, "r")) == NULL) {
	  sfprintf(sfstderr, "%s: %s: %s\n",
		   progname, file, strerror(errno));
	  return NULL;
	}
	while ((n = readtoken(fp, line, sizeof line, &linenum)) != -1) {
	  if (verbose)
	    sfprintf(sfstdout, "read '%s' %d\n",  line, n);
	  if (n == 1) {
	    /* Selector entry - or "PARAM" */
	    if (cistrncmp(line,"PARAM",5) == 0) {
	      if (paramparse(line+5)) {
		sfprintf(sfstderr, "%s: illegal syntax at %s:%d\n",
			progname, file, linenum);
		++errflag;
	      }
	      continue;;
	    }

	    if (ce != NULL)
	      celink(ce, &head, &tail, attrs);
	    attrs = 0;
	    ce = (struct config_entry *)emalloc(sizeof (struct config_entry));
	    memset((void*)ce, 0, sizeof(ce));
	    if (verbose) sfprintf(sfstdout,"CE= %p mark=1\n", ce);

	    defaultconfigentry(ce,NULL);
	    ce->mark = 1;
	    if ((s = strchr(line, '/')) != NULL) {
	      *s = 0;
	      ce->channel = strsave(line);
	      *s = '/';
	      ce->host    = strsave(s+1);
	    } else {
	      ce->channel = strsave(line);
	      ce->host    = strsave("*");
	    }
	    if (strcmp(line,"*/*") == 0 || strcmp(line,"*") == 0) {
	      /* The default entry.. */
	      if (default_entry != NULL) {
		if (ce->channel) free (ce->channel);
		if (ce->host) free(ce->host);
		free(ce);
		ce = default_entry;
	      }
	      defaultconfigentry(ce,default_entry);
	      if (default_entry == NULL)
		default_entry = ce;
	    } else
	      defaultconfigentry(ce,default_entry);
	  } else if (ce != NULL) {
	    a = NULL;
	    if ((cp = strchr(line, '=')) != NULL) {
	      char *p = cp-1;
	      *cp = '\0';
	      while (p >= line && (*p == ' ' || *p == '\t'))
		*p-- = '\0';
	      a = cp+1;
	      SKIPSPACE(a);
	      if (*a == '"') {
		++a;
		cp = a;
		while (*cp && *cp != '"') {
		  if (*cp == '\\' && cp[1] != 0)
		    ++cp;
		  ++cp;
		}
		if (*cp)
		  *cp = '\0';
	      }
	    }

	    if (ce && ce->mark) {
	      if (verbose)
		sfprintf(sfstdout," reading entry, ce = %p, mark=0\n", ce);
	      ce->mark = 0;
	    }

	    for (rckp = &rckeys[0]; rckp->name != NULL ; ++rckp)
	      if (cistrcmp(rckp->name, line) == 0) {
		errflag += (*rckp->parsef)(line, a, ce);
		break;
	      }
	    if (rckp->name == NULL) {
	      sfprintf(sfstderr,
		      "%s: unknown keyword %s in %s:%d\n",
		      progname, line, file, linenum);
	      ++errflag;
	    }

	    if (!errflag) attrs = 1;

	  } else {
	    sfprintf(sfstderr, "%s: illegal syntax at %s:%d\n",
		    progname, file, linenum);
	    ++errflag;
	  }
	}
	if (ce != NULL)
	  celink(ce, &head, &tail, 1);
	sfclose(fp);
	if (verbose) {
	  struct threadgroup tg;
	  v.orig[L_CHANNEL] = v.orig[L_HOST] = NULL;
	  v.thgrp = &tg;
	  for (ce = head; ce != NULL; ce = ce->next) {
	    tg.ce = *ce;
	    vtxprint(&v);
	  }
	}
	return errflag ? NULL : head;
}

static int
readtoken(fp, buf, buflen, linenump)
	Sfio_t *fp;
	char *buf;
	int buflen, *linenump;
{
	static char line[BUFSIZ];
	static char *lp = NULL;
	char *elp;
	int rv;

redo_readtoken:
	if (lp == NULL) {
	  if (csfgets(line, sizeof line, fp) < 0)
	    return -1;
	  *linenump += 1;
	  lp = line;
	}
	/* Skip initial white-space */
	SKIPSPACE(lp);
	/* Now it is one of: a token, a comment start, or end of line */
	if (*lp == '\0' || *lp == '#') {
	  /* Comment/EOL */
	  lp = NULL;
	  goto redo_readtoken;
	}
	/* Now we scan for the token + possible value */
	elp = lp;
	while (*elp && *elp != ' ' && *elp != '\t' && *elp != '\n' && *elp != '=' && *elp != '#')
	  ++elp;
	if (isspace(0xFF & *elp)) {
	  /* Allow spaces after the token and before '=' */
	  char *p = elp;
	  SKIPSPACE(p);
	  if (*p == '=')
	    elp = p;
	}
	/* Value indicator ? */
	if (*elp == '=') {
	  /* Allow spaces between '=', and value */
	  ++elp;
	  SKIPSPACE(elp);
	  if (*elp == '"') {
	    ++elp;
	    while (*elp != '"' && *elp != '\0') {
	      if (*elp == '\\' && *(elp+1) == '\n') {
		if (csfgets(elp, sizeof line - (elp - line), fp) < 0) {
		  sfprintf(sfstderr,
			  "%s: bad continuation line\n",
			  progname);
		  return -1;
		}
	      }
	      ++elp;
	    }
	    if (*elp == '\0') {
	      sfprintf(sfstderr,
		      "%s: missing end-quote in: %s\n",
		      progname, line);
	      return -1;
	    }
	    ++elp;
	  } else {
	    SKIPTEXT(elp);
	  }
	}
	strncpy(buf, lp, elp-lp);
	buf[elp-lp] = '\0';
	rv = (lp == line);
	if (*elp == '\0' || *elp == '\n')
	  lp = NULL;
	else
	  lp = elp;
	return rv;
}


struct config_entry *
rereadconfig(head, file)
	struct config_entry *head;
	const char *file;
{
	struct config_entry *ce, *nce, *head2;

	sfprintf(sfstderr,
		"%s: reread configuration file: %s\n", progname, file);
	/* free all the old config file entries */
	for (ce = head; ce != NULL; ce = nce) {
	  nce = ce->next;
	  /* Process the  default_entry  cleanup as the LAST one */
	  if (ce == default_entry)
	    continue;
	  /* Free up all malloc()ed blocks */
	  if (ce->command != NULL &&
	      (default_entry == NULL ||
	       ce->command != default_entry->command))
	    free(ce->command);
	  if (ce->argv != NULL &&
	      (default_entry == NULL ||
	       ce->argv != default_entry->argv))
	    free((char *)ce->argv);
	  if (ce->retries != NULL && ce->nretries > 0 &&
	      (default_entry == NULL ||
	       ce->retries != default_entry->retries))
	    free((char *)ce->retries);
	  free((char *)ce);

	  /* Process the  default_entry  cleanup as the LAST one */
	  if (nce == NULL) {
	    nce = default_entry;
	    if (nce != NULL)
	      nce->next = NULL; /* It no longer has any followers.. */
	    default_entry = NULL;
	  }
	}

	/* read the new stuff in */
	if ((head2 = readconfig(file)) == NULL) {
	  char *cp = emalloc(strlen(file)+50);
	  sprintf(cp, "null control file: %s", file);
	  die(1, cp);
	  /* NOTREACHED */
	}

	/* apply it to all the existing vertices */
	rrcf_head = head2;
	sp_scan(vtxredo, (struct spblk *)NULL, spt_mesh[L_CTLFILE]);

	endpwent(); /* Close the databases */
	endgrent();

	return head;
}

static int rc_command(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	char *cp, **av, *argv[100];
	int j;

	ce->command = strsave(arg);
	j = 0;
	for (cp = ce->command; *cp;) {
	  argv[j++] = cp;
	  if (j >= (sizeof argv)/(sizeof argv[0]))
	    break;
	  SKIPTEXT(cp);
	  if (*cp == '\0')  break;
	  *cp++ = '\0';
	  SKIPSPACE(cp);
	}
	argv[j++] = NULL;
	if (j > 0) {
	  ce->argv = (char **)emalloc(sizeof (char *) * j);
	  memcpy((char *)ce->argv, (char *)&argv[0], sizeof (char *) * j);
	}
	if (!(ce->flags & CFG_WITHHOST)) {
	  for (av = &ce->argv[0]; *av != NULL; ++av)
	    if (strcmp(*av, replhost) == 0) {
	      ce->flags |= CFG_WITHHOST;
	      break;
	    }
	}

	/* ``replchannel'' need not matched, idle processing
	   takes it properly into account. */

	return 0;
}

static int rc_expform(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->expiryform = strsave(arg);
	return 0;
}

static int rc_expiry(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->expiry = parse_interval(arg,NULL);
	return 0;
}

static int rc_expiry2(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->expiry2 = parse_interval(arg,NULL);
	return 0;
}

static int rc_group(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	struct Zgroup *gr;

	if (isascii(*arg) && isdigit(*arg))
	  ce->gid = atoi(arg);
	else if ((gr = zgetgrnam(arg)) == NULL) {
	  sfprintf(sfstderr, "%s: unknown group: '%s'\n", progname, arg);
	  return 1;
	} else
	  ce->gid = gr->gr_gid;
	return 0;
}

static int rc_interval(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->interval = parse_interval(arg,NULL);
	return 0;
}

static int rc_idlemax(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->idlemax = parse_interval(arg,NULL);
	return 0;
}

static int rc_overfeed(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->overfeed = atoi(arg);
	if (ce->overfeed < 0)
	  ce->overfeed = 0;
	return 0;
}

static int rc_priority(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	if (sscanf(arg,"%d",&ce->priority) != 1 ||
	    ce->priority < -20 || ce->priority > 19) {
	  sfprintf(sfstderr, "%s: Bad UNIX priority value, acceptable in range: -20..19; input=\"%s\"\n", progname, arg);
	  return 1;
	}
	ce->priority += 100;
	return 0;
}

static int rc_nice(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	if (sscanf(arg,"%d",&ce->priority) != 1 ||
	    ce->priority < -40 || ce->priority > 39) {
	  sfprintf(sfstderr, "%s: Bad UNIX nice offset value, acceptable in range: -40..39; input=\"%s\"\n", progname, arg);
	  return 1;
	}
	return 0;
}

static int rc_syspriority(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	int i;
	if (sscanf(arg,"%d",&i) != 1 ||
	    i < -20 || i > 19) {
	  sfprintf(sfstderr, "%s: Bad UNIX priority value, acceptable in range: -20..19; input=\"%s\"\n", progname, arg);
	  return 1;
	}
#if defined(HAVE_SETPRIORITY) && defined(HAVE_SYS_RESOURCE_H)
	/* PRIO_PROCESS depends likely of  HAVE_SYS_RESOURCE_H */
	setpriority(PRIO_PROCESS, 0, i);
#endif
	return 0;
}

static int rc_sysnice(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	int i;
	if (sscanf(arg,"%d",&i) != 1 ||
	    i < -40 || i > 39) {
	  sfprintf(sfstderr, "%s: Bad UNIX nice offset value, acceptable in range: -40..39; input=\"%s\"\n", progname, arg);
	  return 1;
	}
	nice(i);
	return 0;
}

static int rc_maxchannel(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->maxkidChannel = atoi(arg);
	if (ce->maxkidChannel <= 0)
	  ce->maxkidChannel = 10000;
	return 0;
}

static int rc_maxring(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->maxkidThreads = atoi(arg);
	if (ce->maxkidThreads <= 0)
	  ce->maxkidThreads = 10000;
	return 0;
}

static int rc_maxta(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->maxkids = atoi(arg);
	if (ce->maxkids <= 0)
	  ce->maxkids = 10000;
	if (ce->maxkids > global_maxkids)
	  ce->maxkids = global_maxkids;
	return 0;
}

static int rc_maxthr(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->maxkidThread = atoi(arg);
	if (ce->maxkidThread <= 0)
	  ce->maxkidThread = 1;
	return 0;
}

static int rc_retries(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	int i, j, arr[100];
	char c, *cp, *d;

	j = 0;
	for (cp = arg; *cp != '\0'; ++cp) {
	  SKIPSPACE(cp);
	  if (*cp == '\0')
	    break;
	  d = cp++;
	  SKIPTEXT(cp);
	  c = *cp;
	  *cp = '\0';
	  i = atoi(d);
	  if (i > 0)
	    arr[j++] = i;
	  else {
	    sfprintf(sfstderr,
		    "%s: not a numeric factor: %s\n",
		    progname, d);
	    return 1;
	  }
	  if (j >= (sizeof arr)/(sizeof arr[0]))
	    break;
	  *cp = c;
	  if (*cp == '\0')
	    break;
	}
	if (j > 0) {
	  ce->retries = (int *)emalloc((u_int)(sizeof (int) * j));
	  memcpy((char *)ce->retries, (char *)&arr[0], sizeof (int) * j);
	  ce->nretries = j;
	} else {
	  sfprintf(sfstderr, "%s: empty retry factor list\n", progname);
	  return 1;
	}
	return 0;
}

static int rc_reporttimes(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	int i, j, arr[_CFTAG_RCPTDELAYSIZE];
	char c, *cp, *d;

	for (j = 0; j < sizeof(arr)/(sizeof(arr[0])); ++j)  arr[j] = 0;

	j = 0;
	for (cp = arg; *cp != '\0'; ++cp) {
	  SKIPSPACE(cp);
	  if (*cp == '\0')
	    break;
	  d = cp++;
	  SKIPTEXT(cp);
	  c = *cp;
	  *cp = '\0';
	  i = parse_interval(d, NULL);
	  if (i > 0)
	    arr[j++] = i;
	  else {
	    sfprintf(sfstderr,
		    "%s: not a numeric factor: %s\n",
		    progname, d);
	    return 1;
	  }
	  if (j >= (sizeof arr)/(sizeof arr[0]))
	    break;
	  *cp = c;
	  if (*cp == '\0')
	    break;
	}

	for (j = 0; j < sizeof(arr)/(sizeof(arr[0])); ++j)
	  ce->reporttimes[j] = arr[j];

	return 0;
}

static int rc_user(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	struct Zpasswd *pw;

	if (isascii(*arg) && isdigit(*arg))
	  ce->uid = atoi(arg);
	else if ((pw = zgetpwnam(arg)) == NULL) {
	  sfprintf(sfstderr, "%s: unknown user: %s\n", progname, arg);
	  return 1;
	} else
	  ce->uid = pw->pw_uid;
	return 0;
}

static int rc_skew(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	int v;

	if (!isascii(*arg) || !isdigit(*arg) || (v = atoi(arg)) < 1) {
	  sfprintf(sfstderr, "%s: bad skew value: %s\n", progname, arg);
	  return 1;
	}
	ce->skew = v;
	return 0;
}

static int rc_bychannel(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	return 0;
}

static int rc_ageorder(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->flags |= CFG_AGEORDER;
	return 0;
}

static int rc_deliveryform(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->deliveryform = strsave(arg);
	return 0;
}

static int rc_queueonly(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->flags |= CFG_QUEUEONLY;
	return 0;
}

static int rc_wakeuprestartonly(key, arg, ce)
	char *key, *arg;
	struct config_entry *ce;
{
	ce->flags |= CFG_WAKEUPRESTARTONLY;
	return 0;
}

extern int mailqmode;

char *zenvexpand(line)
     char *line;
{
	char *s = line;
	char *v;
	const char *e;
	char end_c;
	int spotlen;
	int e_len;

	if (!line) return NULL;

	for (;*s;++s) {
	  if (*s == '$') {
	    if (s[1] == '{') {
	      v = s;
	      for (;*s && *s != '}'; ++s) ;
	      end_c = *s;
	      *s = 0;
	      spotlen = s - v + 1;
	      e = getzenv(v+2);
	      *s = end_c;
	      if (!e) continue; /* No such zenv-variable :-/ */
	      e_len = strlen(e);
	      if (e_len > spotlen) {
		/* Must expand a bit */
		char *n = malloc(strlen(line)+e_len-spotlen+2);
		int p = v - line;
		if (!n) continue; /* alloc failure */
		if (p > 0)
		  memcpy(n, line, p);
		s = n + p;
		memcpy(s, e, e_len);
		s += e_len;
		p += spotlen;
		strcpy(s, line + p); /* Tail */
		free(line);
		line = n;
	      } else {
		/* New data has same or smaller size */
		memcpy(v, e, e_len);
		if (e_len < spotlen) /* Smaller size */
		  strcpy(v + e_len, v + spotlen);
		v += e_len;
		s = v;
	      }
	    }
	  }
	}
	return line;
}


static int paramparse(line)
	char *line;
{
	char *s, *a = NULL;

	if ((s = strchr(line, '=')) != NULL) {
	  char *p = s-1;
	  *s = '\0';
	  while (p >= line && (*p == ' ' || *p == '\t'))
	    *p-- = '\0';
	  a = s+1;
	  SKIPSPACE(a);
	  if (*a == '"') {
	    ++a;
	    s = a;
	    while (*s && *s != '"') {
	      if (*s == '\\' && s[1] != 0)
		++s;
	      ++s;
	    }
	    if (*s)
	      *s = '\0';
	  }
	}

	if (cistrcmp(line,"authfile")==0 && a) {
	  if (mq2authfile)
	    free((void*)mq2authfile);
	  mq2authfile = zenvexpand(strsave(a));

	  if (mq2authfile && access(mq2authfile,R_OK)==0)
	    mailqmode = 2;

	  return 0;
	}

	if (cistrcmp(line,"mailqsock")==0 && a) {
	  if (mailqsock)
	    free((void*)mailqsock);
	  mailqsock = zenvexpand(strsave(a));
	  return 0;
	}

	if (cistrcmp(line,"msgwriteasync")==0 && a) {
	  msgwriteasync = atoi(a);
	  return 0;
	}

	if (cistrcmp(line,"notifysock")==0 && a) {
	  if (notifysock)
	    free((void*)notifysock);
	  notifysock = zenvexpand(strsave(a));
	  return 0;
	}

	if (cistrcmp(line,"global-report-interval")==0 && a) {
	  global_report_interval = parse_interval(a, NULL);
	  return 0;
	}

	if (cistrcmp(line,"store-error-on-error")==0 && a) {
	  store_error_on_error = atoi(a);
	  return 0;
	}

	return 1;
}
