/*
 *	ZMailer 2.99.53+ Scheduler "mailq2" routines
 *
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1999
 *
 */

#include "scheduler.h"
#include <ctype.h>
#include <unistd.h>
#include "zsyslog.h"
/* #include <stdlib.h> */
#include <errno.h>

#include "ta.h"
#include "libz.h"

#include "prototypes.h"

#ifdef _AIX /* The select.h  defines NFDBITS, etc.. */
# include <sys/types.h>
# include <sys/select.h>
#endif


#if	defined(BSD4_3) || defined(sun)
#include <sys/file.h>
#endif
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifndef	NFDBITS
/*
 * This stuff taken from the 4.3bsd /usr/include/sys/types.h, but on the
 * assumption we are dealing with pre-4.3bsd select().
 */

typedef long	fd_mask;

#ifndef	NBBY
#define	NBBY	8
#endif	/* NBBY */
#define	NFDBITS		((sizeof fd_mask) * NBBY)

/* SunOS 3.x and 4.x>2 BSD already defines this in /usr/include/sys/types.h */
#ifdef	notdef
typedef	struct fd_set { fd_mask	fds_bits[1]; } fd_set;
#endif	/* notdef */

#ifndef	_Z_FD_SET
#define	_Z_FD_SET(n, p)   ((p)->fds_bits[0] |= (1 << (n)))
#define	_Z_FD_CLR(n, p)   ((p)->fds_bits[0] &= ~(1 << (n)))
#define	_Z_FD_ISSET(n, p) ((p)->fds_bits[0] & (1 << (n)))
#define _Z_FD_ZERO(p)	  memset((char *)(p), 0, sizeof(*(p)))
#endif	/* !FD_SET */
#endif	/* !NFDBITS */

#ifdef FD_SET
#define _Z_FD_SET(sock,var) FD_SET(sock,&var)
#define _Z_FD_CLR(sock,var) FD_CLR(sock,&var)
#define _Z_FD_ZERO(var) FD_ZERO(&var)
#define _Z_FD_ISSET(i,var) FD_ISSET(i,&var)
#else
#define _Z_FD_SET(sock,var) var |= (1 << sock)
#define _Z_FD_CLR(sock,var) var &= ~(1 << sock)
#define _Z_FD_ZERO(var) var = 0
#define _Z_FD_ISSET(i,var) ((var & (1 << i)) != 0)
#endif



static void mq2interpret __((struct mailq *, char *));

static struct mailq *mq2root  = NULL;
static int           mq2count = 0;
static int	     mq2max   = 20; /* How many can live simultaneously */
static int           max_mq_life = 90; /* 90 seconds for an action */

int mq2_active __((void))
{
  return (mq2root != NULL);
}

/* INTERNAL */
static void mq2_discard(mq)
     struct mailq *mq;
{
  struct mailq **mqp = &mq2root;
  while (*mqp) {
    if (*mqp == mq) {
      *mqp = mq->nextmailq;
      break;
    }
    mqp = &((*mqp)->nextmailq);
  }

  close(mq->fd);

  if (mq->inbuf)
    free(mq->inbuf);
  if (mq->inpline)
    free(mq->inpline);
  if (mq->outbuf)
    free(mq->outbuf);
  if (mq->challenge)
    free(mq->challenge);

  free(mq);
}

/* EXTERNAL */
int mq2_putc(mq,c)
     struct mailq *mq;
     int c;
{
  if (!mq->outbuf) {
    mq->outbufspace = 500;
    mq->outbuf = emalloc(mq->outbufspace);
  }

  if (mq->outbufsize+2 >= mq->outbufspace) {
    mq->outbufspace *= 2;
    mq->outbuf = erealloc(mq->outbuf, mq->outbufspace);
  }

  if (mq->outbuf == NULL)
    return -2; /* Out of memory :-/ */

  /* SMTP rule: duplicate the dot at the beginning of the line */
  if (c == '.' && mq->outcol == 0)
    mq->outbuf[mq->outbufsize ++] = c;

  mq->outbuf[mq->outbufsize ++] = c;
  if (c == '\n')
    mq->outcol = 0;
  else
    mq->outcol++;

  return 0; /* Implementation ok */
}

/* EXTERNAL */
int mq2_puts(mq,s)
     struct mailq *mq;
     char *s;
{
  int rc;
  if (!mq) return -2; /* D'uh...  FD is not among MQs.. */

  for (;s && *s; ++s)
    if ((rc = mq2_putc(mq,*s)) < 0)
      return rc;

  return 0; /* Ok. */
}

int mq2_puts_(mq,s)
     struct mailq *mq;
     char *s;
{
  int rc;
  if (!mq) return -2; /* D'uh...  FD is not among MQs.. */

  mq->outcol++;

  for (;s && *s; ++s)
    if ((rc = mq2_putc(mq,*s)) < 0)
      return rc;

  return 0; /* Ok. */
}


/*
 * mq2: wflush() - return <0: error detected,
 *                        >0: write pending,
 *                       ==0: flush complete
 */
/* INTERNAL */
int mq2_wflush(mq)
     struct mailq *mq;
{
  if (verbose)
    sfprintf(sfstderr,"mq2_wflush() fd = %d", mq->fd);

  while (mq->outbufcount < mq->outbufsize) {
    int r, i;
    i = mq->outbufsize - mq->outbufcount;
    r = write(mq->fd, mq->outbuf + mq->outbufcount, i);

    if (r > 0) {

      /* Some written! */
      mq->outbufcount += r;

    } else {
      /* Error ??? */
      if (errno == EAGAIN || errno == EINTR)
	break; /* Back latter .. */
      /* Err... what ?? */

      if (verbose)
	sfprintf(sfstderr, " -- failure; errno = %d\n", errno);

      mq2_discard(mq);

      return -1;
    }
  }
  if (mq->outbufcount >= mq->outbufsize)
    mq->outbufcount = mq->outbufsize = 0;

  /* Shrink the outbuf, if you can.. */
  if (mq->outbufcount > 0) {
    int l = mq->outbufsize - mq->outbufcount;
    if (l)
      memcpy(mq->outbuf, mq->outbuf + mq->outbufcount, l);
    mq->outbufcount = 0;
    mq->outbufsize = l;
  }

  if (verbose && (mq->outbufsize - mq->outbufcount))
    sfprintf(sfstderr," -- ok; buf left: %d chars\n",
	    mq->outbufsize - mq->outbufcount);
  else if (verbose)
    sfprintf(sfstderr,"\n");

  return (mq->outbufcount < mq->outbufsize);
}

/* INTERNAL */
static void mq2_iputc(mq,c)
     struct mailq *mq;
     int c;
{
  if (!mq->inpline) {
    mq->inplinespace = 500;
    mq->inplinesize = 0;
    mq->inpline = emalloc(mq->inplinespace);
  }
  if (mq->inplinesize +2 >= mq->inplinespace) {
    mq->inplinespace *= 2;
    mq->inpline = erealloc(mq->inpline, mq->inplinespace);
  }
  if (mq->inpline == NULL)
    return;
  mq->inpline[mq->inplinesize ++] = c;
}


/*
 *  Copies characters from  inbuf[]  to  inpline[], and terminates
 *  when it  1) gets '\n' (appends '\000' to the string, returns
 *  pointer to begining of the string),  2) runs out of the inbuf[],
 *  and returns NULL.
 *
 */
/* INTERNAL */
static char *mq2_gets(mq)
     struct mailq *mq;
{
  int c;
  char *ret = NULL;

  while (mq->inbufcount < mq->inbufsize) {
    c = mq->inbuf[mq->inbufcount++];
    if (c == '\n') {
      /* Got a complete line */
      mq2_iputc(mq,'\000');
      mq->inplinesize = 0;
      ret = mq->inpline;
      break;
    } else if (c != '\r') {
      mq2_iputc(mq,c);
    }
  }
  /* Shrink the input buffer a bit, if you can.. */
  if (mq->inbufcount > 0) {
    c = mq->inbufsize - mq->inbufcount;
    if (c <= 0)
      mq->inbufsize = mq->inbufcount = 0;
    else {
      memcpy(mq->inbuf, mq->inbuf + mq->inbufcount, c);
      mq->inbufcount = 0;
      mq->inbufsize = c;
    }
  }
  return ret;
}



/* INTERNAL */
static void mq2_read(mq)
     struct mailq *mq;
{
  int i, spc;
  char *s;

  if (mq->fd < 0) {
    mq2_discard(mq);
    return;
    /* Zap! */
  }

  if (!mq->inbuf) {
    mq->inbufspace = 500;
    mq->inbuf = emalloc(mq->inbufspace);
  }

  if (mq->inbufsize+80 >= mq->inbufspace) {
    mq->inbufspace *= 2;
    mq->inbuf = erealloc(mq->inbuf, mq->inbufspace);
  }

  if (mq->inbuf == NULL) {
    mq2_discard(mq);  /* Out of memory :-/ */
    return;
  }

  spc = mq->inbufspace - mq->inbufsize;
  i = read(mq->fd, mq->inbuf + mq->inbufsize, spc);

  if (i == 0) {
    mq2_discard(mq);
    return; /* ZAP! */
  }
  if (i > 0) {
    /* GOT SOMETHING! */
    mq->inbufsize += i;
  } else {
    if (errno == EINTR || errno == EAGAIN) {
      /* Ok, come back latter */
    } else {
      mq2_discard(mq); /* ZAP! */
    }
    return;
  }

  /* Do some processing here! */

  while ((s = mq2_gets(mq)) != NULL) {
    mq2interpret(mq, s);
  }

  mq2_wflush(mq);
}


/* EXTERNAL */
void mq2_register(fd, addr)
     int fd;
     Usockaddr *addr;
{
  struct mailq *mq;

  static int cnt = 0;
  char buf[200];
  struct timeval tv;

  if (mq2count > mq2max) {
    close(fd); /* TOO MANY! */
    return;
  }
  
  mq = emalloc(sizeof(*mq));
  if (!mq) {
    close(fd);
    return;
  }
  memset(mq, 0, sizeof(*mq));
  
  mq->fd = fd;
  mq->apopteosis = now + max_mq_life;
  mq->qaddr = *addr;

  mq->nextmailq = mq2root;
  mq2root = mq;

  fd_nonblockingmode(fd);

  /* 
     Scheduler writes following to the interface socket:

	"version zmailer 2.0\n"
	"some magic random gunk used as challenge\n"
  */

  mq2_puts(mq,"version zmailer 2.0\n");
  
  gettimeofday(&tv,NULL);

  sprintf(buf,"MAILQ-V2-CHALLENGE: %ld.%ld.%d",
	  (long)tv.tv_sec, (long)tv.tv_usec, ++cnt);

  mq->challenge = strdup(buf);

  mq2_puts(mq, buf);
  mq2_puts(mq, "\n");
  mq2_wflush(mq);

  mq->auth = 0;
}

/* EXTERNAL */
int mq2add_to_mask(rdmaskp, wrmaskp, maxfd)
     fd_set *rdmaskp, *wrmaskp;
     int maxfd;
{
  struct mailq *mq = mq2root;

  for ( ; mq ; mq = mq->nextmailq ) {
    if (mq->fd < 0)
      continue;

    if (mq->fd > maxfd)
      maxfd = mq->fd;

    _Z_FD_SET(mq->fd, *rdmaskp);

    if (mq->outbufcount < mq->outbufsize)
      _Z_FD_SET(mq->fd, *wrmaskp);
  }

  return maxfd;
}

/* EXTERNAL */
void mq2_areinsets(rdmaskp, wrmaskp)
     fd_set *rdmaskp, *wrmaskp;
{
    struct mailq *mq;

    /* The mq-queue may change while we are going it over,
       thus we *must not* try to do write and read things
       at the same time! and be *very* carefull at following
       the 'next' pointers... */

    mq = mq2root;
    while ( mq ) {
      struct mailq *mq2 = mq->nextmailq;
      if (mq->fd >= 0 && _Z_FD_ISSET(mq->fd, *wrmaskp)) {
	mq2_wflush(mq);
      }

      /* Time of forced death ? */
      if (now > mq->apopteosis)
	mq2_discard(mq);

      mq = mq2;
    }

    mq = mq2root;
    while ( mq ) {
      struct mailq *mq2 = mq->nextmailq;
      if (mq->fd < 0 || _Z_FD_ISSET(mq->fd, *rdmaskp)) {
	mq2_read(mq);
      }
      mq = mq2;
    }
}

/*
 * The  thread_report()  is Sfio_t stream based printout routine,
 * and we want to use special discipline routine which translates
 * the write backend function to 'mq2' buffering mode.
 *
 */

int zsfsetfd(fp, fd)
     Sfio_t *fp;
     int fd;
{
  /* This is *NOT* the SFIO's sfsetfd() -- we do no sfsync() at any point.. */
  fp->file = fd;
  return fd;
}

struct mq2discipline {
  Sfdisc_t D;
  struct mailq *mq;
};

ssize_t mq2_sfwrite(sfp, vp, len, discp)
     Sfio_t *sfp;
     const void * vp;
     size_t len;
     Sfdisc_t *discp;
{
    struct mq2discipline *mqd = (struct mq2discipline *)discp;
    struct mailq *mq = mqd->mq;
    int rc, i;
    char *p = (char *)vp;

    for (i = 0; len > 0; ++p, --len, ++i)
      if ((rc = mq2_putc(mq,*p)) < 0)
	return rc;

    return i;
}

static void mq2_thread_report __((struct mailq *mq, int mode, char *channel, char *host));
static void mq2_thread_report(mq, mode, channel, host)
     struct mailq *mq;
     int mode;
     char *channel, *host;
{
  Sfio_t *fp;
  struct mq2discipline mq2d;

  fp = sfnew(NULL, NULL, 0, 0, SF_LINE|SF_WRITE);
  if (!fp) {
    mq2_puts(mq, " *** FAILURE: sfnew(NULL, NULL, 0, -1, SF_LINE|SF_STRING|SF_WRITE);\n");
    return;
  }

  memset(&mq2d, 0, sizeof(mq2d));
  mq2d.mq = mq;
  mq2d.D.writef  = mq2_sfwrite;

  sfdisc(fp, &mq2d.D);


  if (channel && host)
    thread_detail_report(fp, mode, channel, host);
  else
    thread_report(fp, mode);

  zsfsetfd(fp, -1);
  sfclose(fp);
}


/* INTERNAL */
static int mq2cmd_etrn(mq,s)
     struct mailq *mq;
     char *s;
{
  char *t = s;
  int rc;

  if (!(mq->auth & MQ2MODE_ETRN)) {
    mq2_puts(mq, "-No ETRN allowed for you.\n");
    return 0;
  }

  while (*t && (*t != ' ') && (*t != '\t')) ++t;
  if (*t) *t++ = '\000';
  while (*t == ' ' || *t == '\t') ++t;

  /* 's' points to the first arg, 't' points to string after
     separating white-space has been skipped. */
  sfprintf(sfstdout,"%s MQ2 ETRN: %s %s\n", timestring(), s, t);
  rc = turnme(s);
  if (rc)
    mq2_puts(mq, "+OK; an ETRN started something.\n");
  else
    mq2_puts(mq, "+OK; an ETRN didn't start anything.\n");

  return 0;
}

/* INTERNAL */
static int mq2cmd_show(mq,s)
     struct mailq *mq;
     char *s;
{
  char *t = s, *u;

  while (*t && (*t != ' ') && (*t != '\t')) ++t;
  if (*t) *t++ = '\000';
  while (*t == ' ' || *t == '\t') ++t;
  u = t;
  while (*u && (*u != ' ') && (*u != '\t')) ++u;
  if (*u) *u++ = '\000';
  while (*u == ' ' || *u == '\t') ++u;

  /* 's' points to the first arg, 't' points to string after
     separating white-space has been skipped. */

  if (strcmp(s,"SNMP") == 0) {
    if (! (MQ2MODE_SNMP & mq->auth)) /* If not allowed operation, exit! */
      return -1;
    mq2_puts(mq, "+OK until LF.LF\n");
    mq2_thread_report(mq, MQ2MODE_SNMP, NULL, NULL);
    mq2_puts_(mq, ".\n");
    return 0;
  }

  if (strcmp(s,"QUEUE") == 0) {

    if (strcmp(t,"SHORT") == 0) {

      if (! (MQ2MODE_QQ & mq->auth)) /* If not allowed operation, exit! */
	return -1;
      mq2_puts(mq, "+OK until LF.LF\n");
      mq2_thread_report(mq, MQ2MODE_QQ, NULL, NULL);
      mq2_puts_(mq, ".\n");
      return 0;

    } else if (strcmp(t,"THREADS2") == 0) {

      if (! (MQ2MODE_FULL & mq->auth)) /* If not allowed operation, exit! */
	return -1;
      mq2_puts(mq, "+OK until LF.LF\n");
      mq2_thread_report(mq, MQ2MODE_FULL2, NULL, NULL);
      mq2_puts_(mq, ".\n");
      return 0;

    } else if (strcmp(t,"THREADS") == 0) {

      if (! (MQ2MODE_FULL & mq->auth)) /* If not allowed operation, exit! */
	return -1;
      mq2_puts(mq, "+OK until LF.LF\n");
      mq2_thread_report(mq, MQ2MODE_FULL, NULL, NULL);
      mq2_puts_(mq, ".\n");
      return 0;

    }
    /* Unknown! */
    return -1;
  }

  if (strcmp(s,"THREAD") == 0) {
    /* SHOW THREAD 'channel' 'host' */
    char *channel = t;
    char *host    = u;

    if (! (MQ2MODE_FULL & mq->auth)) /* If not allowed operation, exit! */
      return -1;

    mq2_puts(mq, "+OK until LF.LF\n");
    mq2_thread_report(mq, MQ2MODE_FULL, channel, host);
    mq2_puts_(mq, ".\n");
    return 0;
  }

  return -1;

}


/* INTERNAL */
static void mq2interpret(mq,s)
     struct mailq *mq;
     char *s;
{
  char *t = s;

  while (*t && (*t != ' ') && (*t != '\t')) ++t;
  if (*t) *t++ = '\000';
  while (*t == ' ' || *t == '\t') ++t;

  /* 's' points to the initial verb, 't' points to string after
     separating white-space has been skipped. */

  if (cistrcmp(s,"QUIT")==0 || cistrcmp(s,"EXIT") == 0) {
    mq2_puts(mq, "+Bye bye\n");
    mq2_wflush(mq);
    close(mq->fd);
    mq->fd = -1;
  }

  if (mq->auth == 0 && strcmp(s,"AUTH") == 0) {
    mq2auth(mq,t);
    return;
  }

  if (!mq->auth) {
    mq2_puts(mq,"-BAD; USER MUST AUTHENTICATE\n");
    return;
  }

  if (strcmp(s,"SHOW") == 0) {
    if (mq2cmd_show(mq,t) == 0)
      return;
  }
  if (strcmp(s,"ETRN") == 0) {
    mq2cmd_etrn(mq,t);
    return;
  }

  mq2_puts(mq, "-MAILQ2 Unknown command, or refused by access control; VERB='");
  mq2_puts(mq, s);
  mq2_puts(mq, "' REST='");
  mq2_puts(mq, t);
  mq2_puts(mq, "'\n");
}
