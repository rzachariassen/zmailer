/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2000.
 */
/*
 * Zmailer SMTP-server divided into bits
 *
 * The command:
 *
 *  - ETRN/TURNME
 *
 */

#include "smtpserver.h"

static int local_etrn(SS, name, cp, silence)
SmtpState *SS;
const char *name, *cp;
int silence;
{
    FILE *mfp;
    int rc;

    mfp = mail_open(MSG_RFC822);

    if (!mfp && silence) return -1;
    if (!mfp) {
	type(SS, 452, m400, "Failed to initiate ETRN request;  Disk full?");
	typeflush(SS);
	return -1;
    }

    fprintf(mfp, "%c%c%s\n", _CF_TURNME, _CFTAG_NORMAL, cp);
    /* printf("050-My uid=%d/%d\r\n",getuid(),geteuid()); */
    runasrootuser();
    rc = mail_close_alternate(mfp, TRANSPORTDIR, "");
    runastrusteduser();
    if (rc && !silence) {
	type(SS,452,m400,"Failed to initiate local ETRN request; Permission denied?");
	typeflush(SS);
	return -1;
    } else if (!silence) {
      if (multilinereplies) {
	type(SS,-250,m200,"An ETRN request is initiated - lets hope the system");
	type(SS,-250,m200,"has resources to honour it. We call the remote,");
	type(SS, 250,m200,"if we have anything to send there.");
      } else {
	type(SS, 250, m200, "An ETRN request is submitted - something may get sent.");
      }
      typeflush(SS);
    }
    return 0;
}

static int etrn_mailqv2 __((etrn_cluster_ent *, SmtpState *, const char *, const char *));
static int etrn_mailqv2(node, SS, name, cp)
etrn_cluster_ent *node;
SmtpState *SS;
const char *name, *cp;
{
    /* TODO: IMPLEMENT CLUSTER-WIDE ETRN VIA MAILQv2 INTERFACE! */


    type(SS,-250,m200,"Attempting ETRN on cluster node: %s", node->nodename);
    typeflush(SS);
    sleep(1);
    type(SS,-250,m200,"CLUSTER ETRN UNIMPLEMENTED SO FAR!");
    typeflush(SS);
    return -1;
}

static int cluster_etrn(SS, name, cp)
SmtpState *SS;
const char *name, *cp;
{
    int rc, i;
    int some_fail = 0;

    if (etrn_cluster[0].nodename == NULL)
      return local_etrn(SS, name, cp, 0);

    for (i = 0; i < MAX_ETRN_CLUSTER_IDX && etrn_cluster[i].nodename; ++i) {
      rc = etrn_mailqv2(& etrn_cluster[i], SS, name, cp);
      if (rc)
	some_fail = 1;
    }

    if (some_fail)
      return local_etrn(SS, name, cp, 0);

    return 0;
}

void smtp_turnme(SS, name, cp)
SmtpState *SS;
const char *name, *cp;
{
    while (*cp == ' ' || *cp == '\t') ++cp;
    if (*cp == 0) {
	type(SS, 552, "5.0.0", "ETRN needs target domain name parameter.");
	typeflush(SS);
	return;
    }

    if (!((*cp >= 'A' && *cp <= 'Z') || (*cp >= 'a' && *cp <= 'z') ||
	  (*cp >= '0' && *cp <= '9'))) {
      /* Has some special character beginning it; we don't support
	 either arbitary subdomains (@foo.dom), nor "channel-based"
	 starting (#foo) */
      type(SS, 458, m571, "Sorry, only literal target domains accepted");
      typeflush(SS);
      return;
    }

    if (etrn_cluster)
      cluster_etrn(SS, name, cp);
    else
      local_etrn(SS, name, cp, 0);
}
