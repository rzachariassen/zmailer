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
 * TODO: IPv6 socket for MAILQv2 connection
 *
 */

#include "smtpserver.h"

#ifndef HAVE_OPENSSL
#include "md5.h"
#endif /* --HAVE_OPENSSL */

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


#define	MAGIC_PREAMBLE		"version "
#define	LEN_MAGIC_PREAMBLE	(sizeof MAGIC_PREAMBLE - 1)
#define	VERSION_ID		"zmailer 1.0"
#define	VERSION_ID2		"zmailer 2.0"

static int _getline(buf, bufsize, bufspace, fp)
     char **buf;
     int *bufsize;
     int *bufspace;
     FILE *fp;
{
  int c;

  if (!*buf) {
    *bufsize = 0;
    *bufspace = 110;
    *buf = malloc(*bufspace+3);
  }

  while ((c = fgetc(fp)) != EOF) {
    if (c == '\n')
      break;

    if (*bufsize >= *bufspace) {
      *bufspace *= 2;
      *buf = realloc(*buf, *bufspace+3);
    }
    (*buf)[*bufsize] = c;
    *bufsize += 1;
  }
  (*buf)[*bufsize] = 0;

  if (c == EOF && *bufsize != 0) {
    fprintf(stderr, "%s: no input from scheduler\n", progname);
    (*buf)[0] = '\0';
    return -1;
  }

  if (debug && *buf)
    fprintf(stderr, "- %s\n",*buf);

  return 0; /* Got something */
}


#define GETLINE(buf, bufsize, bufspace, fp) _getline(&buf, &bufsize, &bufspace, fp)


static int etrn_mailqv2 __((etrn_cluster_ent *, SmtpState *, const char *, const char *));
static int etrn_mailqv2(node, SS, name, cp)
etrn_cluster_ent *node;
SmtpState *SS;
const char *name, *cp;
{
    MD5_CTX CTX;
    int i;
    int bufsize = 0;
    int bufspace = 0;
    char *challenge = NULL;
    char *buf = NULL;
    unsigned char digbuf[16];
    char *port;
    int fd = -1;
    FILE *fpi = NULL, *fpo = NULL;
    
    type(SS,-250,m200,"Attempting ETRN on cluster node: %s", node->nodename);
    typeflush(SS);

    port = strchr(node->nodename,'/');

    if (!port || (port && *port == '/')) {

      struct in_addr naddr;
      struct hostent *hp = NULL, he;
      struct sockaddr_in sad;
      struct servent *serv = NULL;

      int portnum = 174;

      if (port && isdigit(port[1])) {
	portnum = atol(port+1);
      } else if (port == NULL) {
	serv = getservbyname(port ? port : "mailq", "tcp");
	if (serv == NULL) {

	  type(SS,-250,m200,"Cannot find 'mailq' tcp service");
	  typeflush(SS);

	} else

	  portnum = ntohs(serv->s_port);
      }

      if (port) *port = 0;
      hp = gethostbyname(node->nodename);

      if (hp == NULL) {
	if (inet_pton(AF_INET, node->nodename, &naddr.s_addr) == 1) {
	  hp = gethostbyaddr((void*)&naddr, sizeof(naddr), AF_INET);
	  if (hp == NULL){
	    hp = &he;
	    he.h_name = node->nodename;
	    he.h_length = 4;
	  }
	} else if (hp == NULL) {
	  if (port) *port = '/';
	  type(SS,-250,m200,"Cannot find address of %s", node->nodename);
	  goto failure_exit;
	}
      }

      if (port) *port = '/';

      /* try grabbing a port */
      fd = socket(PF_INET, SOCK_STREAM, 0);
      if (fd < 0) {
	type(SS,-250,m200,"Socket creation failed!");
	typeflush(SS);
	return -1;
      }
      sad.sin_family = AF_INET;
      if (hp == &he)
	sad.sin_addr.s_addr = htonl(naddr.s_addr);
      else {
	char *addr;

	hp_init(hp);
	while ((addr = *hp_getaddr()) != NULL) {
	  sad.sin_port = htons(portnum);
	  memcpy((void*)&sad.sin_addr, addr, hp->h_length);
	  if (connect(fd, (void*)&sad, sizeof sad) < 0) {
	    type(SS,-250,m200,"Connect() failed, will try possible next address");
	    typeflush(SS);
	    if ((addr = *hp_nextaddr()) != NULL) {
	      memcpy((char *)&sad.sin_addr, addr, hp->h_length);
	    }
	    close(fd);
	    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
	      type(SS,-250,m200,"Socket creation failed!");
	      goto failure_exit;
	    }
	    continue;
	  }
	  break;
	}
	if (*hp_getaddr() == NULL) {
	  type(SS,-250,m200,"Unable to connect() to scheduler");
	  goto failure_exit;
	}
      }
    }

    fpi = fdopen(fd,"r");

    bufsize = 0;
    if (GETLINE(buf,bufsize,bufspace,fpi))
      return 0;

#define	EQNSTR(a,b)	(!strncmp(a,b,strlen(b)))

    if (!(EQNSTR(buf, MAGIC_PREAMBLE) &&
	  EQNSTR(buf+LEN_MAGIC_PREAMBLE, VERSION_ID2))) {
      
      goto failure_exit;
    }

    /* Authenticate the query - get challenge */
    bufsize = 0;
    if (GETLINE(challenge, bufsize, bufspace, fpi))
      goto failure_exit;

#ifdef HAVE_OPENSSL
    MD5_Init(&CTX);
    MD5_Update(&CTX, challenge, strlen(challenge));
    MD5_Update(&CTX, node->password, strlen(node->password));
    MD5_Final(digbuf, &CTX);
#endif /* - HAVE_OPENSSL */
#ifndef HAVE_OPENSSL
    MD5Init(&CTX);
    MD5Update(&CTX, challenge, strlen(challenge));
    MD5Update(&CTX, node->password, strlen(node->password));
    MD5Final(digbuf, &CTX);
#endif /* --HAVE_OPENSSL */

    fpo = fdopen(fd,"w");

    fprintf(fpo, "AUTH %s ", node->username);
    for (i = 0; i < 16; ++i) fprintf(fpo,"%02x",digbuf[i]);
    fprintf(fpo, "\n");
    if (fflush(fpo) || ferror(fpo)) {
      type(SS,-250,m200,"MQ2-AUTH write failure occurred");
      goto failure_exit;
    }

    bufsize = 0;
    if (GETLINE(buf, bufsize, bufspace, fpi))
      goto failure_exit;
    if (*buf != '+') {
      type(SS,-250,m200,"MQ2-AUTH failure occurred");
      goto failure_exit;
    }

    fprintf(fpo,"ETRN %s\n", cp);
    if (fflush(fpo) || ferror(fpo)) {
      type(SS,-250,m200,"MQ2-ETRN write failure occurred");
      goto failure_exit;
    }

    bufsize = 0;
    if (GETLINE(buf, bufsize, bufspace, fpi))
      goto failure_exit;

    port = strchr(buf, '\n'); if (port) *port = 0;
    type(SS,-250,m200,"%s",buf);

    fclose(fpi);
    fclose(fpo);

    typeflush(SS);
    return 0;

 failure_exit:

    if (fd >= 0) close(fd);
    if (fpi) fclose(fpi);
    if (fpo) fclose(fpo);

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

    type(SS,250,m200,"ETRN-cluster operation(s) complete");
    typeflush(SS);

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
