/*
950123: <mea@nic.funet.fi> Fixed things to be more GENERIC -- now it
	compiles also on OSF/1 Alpha...
21/7/92 Fixed SIGPIPE bug in ident_tcpuser3(). <pen@lysator.liu.se>
2/9/92: identuser 4.0. Public domain.
2/9/92: added bunches of zeroing just in case.
2/9/92: added ident_tcpuser3. uses bsd 4.3 select interface.
2/9/92: added ident_tcpsock, ident_sockuser.
2/9/92: added ident_fd2, ident_tcpuser2, simplified some of the code.
12/27/91: fixed up usercmp to deal with restricted tolower XXX
5/6/91 DJB baseline identuser 3.1. Public domain.
*/

/* Tuned to be part of ZMailer -- #include "zmsignal.h" .. */

#define USENONBLOCK 1

#include "hostenv.h"
#include <stdio.h>
#include "zmsignal.h"
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <fcntl.h> /*XXX*/
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
# include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
# include <netinet6/in6.h>
#endif
#ifdef HAVE_LINUX_IN6_H
# include <linux/in6.h>
#endif
#include <ctype.h>
#include <errno.h>
#ifdef	ISC
#include <net/errno.h>
#endif
extern int errno;
#include "identuser.h"

#ifdef _AIX
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <setjmp.h>

#ifndef FNDELAY
#define FNDELAY O_NDELAY
#endif

unsigned int ident_tcpport = 113;

#define SIZ 500 /* various buffers */


#define CLORETS(e) { saveerrno = errno; close(s); errno = saveerrno; return e; }


static jmp_buf jmpalarm;

static int ident_tcpsock5 __((const int, const int, const void *, const void *, int *));

static int ident_tcpsock5(af, len, inlocal, inremote, sockp)
	const int af, len;
	const void *inlocal;
	const void *inremote;
	int *sockp;
{
  union {
    struct sockaddr_in  v4;
#if defined(AF_INET6) && defined(INET6)
    struct sockaddr_in6 v6;
#endif
  } sa;
  register int s;
  register int fl;
  register int saveerrno;

  *sockp = -1;

  if ((s = socket(af, SOCK_STREAM, 0)) == -1)
    return -1;

  memset(&sa,0,sizeof(sa));
  if (af == AF_INET) {
    sa.v4.sin_family = AF_INET;
    sa.v4.sin_port = 0;
    memcpy(&sa.v4.sin_addr, inlocal, len);
    if (sa.v4.sin_addr.s_addr != 0)
      if (bind(s,(struct sockaddr*)&sa,sizeof(sa.v4)) < 0)
	CLORETS(-1);
  }
#if defined(AF_INET6) && defined(INET6)
  else if (af == AF_INET6) {
    sa.v6.sin6_family   = AF_INET6;
    sa.v6.sin6_flowinfo = 0;
    sa.v6.sin6_port     = 0;
    memcpy(&sa.v6.sin6_addr, inlocal, len);

    if (bind(s, (struct sockaddr*)&sa, sizeof(sa.v6)) < 0)
      CLORETS(-1);
  }
#endif
  else {
    CLORETS(-1);
  }

#if USENONBLOCK
  if ((fl = fcntl(s, F_GETFL, 0)) == -1)
    CLORETS(-1);
  if (fcntl(s, F_SETFL, FNDELAY | fl) == -1)
    CLORETS(-1);
#endif

  *sockp = s; /* Following connect may take non-trivial time,
		 and we may be jumping around with SIGALRM,
		 so for now do save the socket number.. */

  memset(&sa,0,sizeof(sa));
  if (af == AF_INET) {
    sa.v4.sin_family  = AF_INET;
    sa.v4.sin_port    = htons(ident_tcpport);
    memcpy(&sa.v4.sin_addr, inremote, len);
    if (connect(s,(struct sockaddr*)&sa,sizeof(sa.v4)) < 0)
      if (errno != EINPROGRESS)
	CLORETS(-1);
  }
#if defined(AF_INET6) && defined(INET6)
  else if (af == AF_INET6) {
    sa.v6.sin6_family   = AF_INET6;
    sa.v6.sin6_flowinfo = 0;
    sa.v6.sin6_port     = htons(ident_tcpport);
    memcpy(&sa.v6.sin6_addr, inremote, len);
    if (connect(s,(struct sockaddr*)&sa,sizeof(sa.v6)) < 0)
      if (errno != EINPROGRESS)
	CLORETS(-1);
  }
#endif
  else {
    CLORETS(-1);
  }
  return s;
}

static volatile const char *ident_sockuser2 __((const int, const int, const int, char *, const int));

static volatile const char *ident_sockuser2(s,local,remote,realbuf,realbuflen)
	const int s;
	const int local;
	const int remote;
	char *realbuf;
	const int realbuflen;
{
  register int buflen;
  register int w;
  register int saveerrno;
  int rlocal;
  int rremote;
  register int fl;
  fd_set wfds;
  void (*old_sig)__((int));
  char *buf, *ebuf;
 
  SIGNAL_HANDLESAVE(SIGPIPE, SIG_IGN, old_sig);
 
  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,(struct timeval *) 0);
  /* now s is writable */
#if USENONBLOCK
  if ((fl = fcntl(s,F_GETFL,0)) == -1) {
    SIGNAL_HANDLE(SIGPIPE, old_sig);
    CLORETS("SOCKFCNTL1");
  }
  if (fcntl(s,F_SETFL,~FNDELAY & fl) == -1) {
    SIGNAL_HANDLE(SIGPIPE, old_sig);
    CLORETS("SOCKFCNTL2");
  }
#endif
  buf = realbuf;
  sprintf(buf,"%u , %u\r\n",(unsigned int) remote,(unsigned int) local);
  /* note the reversed order---the example in RFC 931 is misleading */
  buflen = strlen(buf);
  while ((w = write(s,buf,buflen)) < buflen)
    if (w == -1) /* should we worry about 0 as well? */ {
      SIGNAL_HANDLE(SIGPIPE, old_sig);
      saveerrno = errno;
      close(s);
      if (errno == ECONNREFUSED || errno == EPIPE)
	return "NO-IDENT-SERVICE[2]";
      else {
	sprintf(realbuf,"SOCKWRITE-%d", errno);
	return realbuf;
      }
    } else {
      buf += w;
      buflen -= w;
    }
  buf = realbuf;
  ebuf = realbuf + realbuflen;
  while (1) {
    int spcleft = (ebuf - buf);
    int c;
    char *pp = buf;
    w = read(s, buf, spcleft);
    if (w < 0 && (errno == EINTR))
	continue;
    if (w == 0)
	break; /* EOF */
    while (w > 0 && buf < ebuf) {
      c = *pp;
      if (!(c == ' ' || c == '\t' || c == '\r')) {
	*buf = c;
	++buf;
      }
      ++pp;
      --w;
      if (c == '\n')
	break;
    }
  }
  SIGNAL_HANDLE(SIGPIPE, old_sig);
  if (w == -1)
    CLORETS("SOCKREAD");
  *buf = 0;

  if (sscanf(realbuf,"%d,%d:USERID:%*[^:]:%s",
	     &rremote,&rlocal,realbuf) < 3) {
    close(s);
    errno = EIO;
    /* makes sense, right? well, not when USERID failed to match ERROR */
    /* but there's no good error to return in that case */
    
    return "IDENT-NONSENSE";
  }
  if ((remote != rremote) || (local != rlocal)) {
    close(s);
    errno = EIO;
    return "IDENT-NONSENSE2";
  }
  /* we're not going to do any backslash processing */
  close(s);
  return realbuf;
}


static void sig_alrm __((int));
static void sig_alrm (sig)
	int sig;
{
	SIGNAL_RELEASE(sig);
	SIGNAL_HANDLE(sig, sig_alrm);
	longjmp(jmpalarm,1);
}

volatile const char *ident_tcpuser9(af,len,inlocal,inremote,local,remote,timeout,buf,buflen)
	const int af, len;	/* Address family, and address size */
	const void *inlocal;		/* Addresses */
	const void *inremote;
	const int local;	/* Ports */
	const int remote;
	const int timeout;
	char *buf;
	const int buflen;
{
  int s, r;
  struct timeval tv;
  fd_set wfds;
  int saveerrno;
  void (*old_sig)__((int));
  void (*old_alrm)__((int));
  unsigned int oldival = 0;
  volatile const char *retval;
  
  SIGNAL_HANDLESAVE(SIGPIPE, SIG_IGN, old_sig);
  SIGNAL_HANDLESAVE(SIGALRM, sig_alrm, old_alrm);
  s = -1;

  if (setjmp(jmpalarm) == 0) {
    oldival  = alarm(timeout+5);
    r = ident_tcpsock5(af, len, inlocal, inremote, &s);

    if (r < 0) {
      SIGNAL_HANDLE(SIGPIPE, old_sig);
      SIGNAL_HANDLE(SIGALRM, old_alrm);
      alarm(oldival);
      if (errno == ECONNREFUSED)
	return "NO-IDENT-SERVICE";
      return "SOCKFAULT1";
    }
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    FD_ZERO(&wfds);
    FD_SET(s,&wfds);
    r = select(s + 1, NULL, &wfds, NULL,&tv);
    /* XXX: how to handle EINTR? */
    if (r == -1) {
      SIGNAL_HANDLE(SIGPIPE, old_sig);
      SIGNAL_HANDLE(SIGALRM, old_alrm);
      alarm(oldival);
      CLORETS("SOCKSELERR");
    }
    if (!FD_ISSET(s,&wfds)) {
      close(s);
      SIGNAL_HANDLE(SIGALRM, old_alrm);
      SIGNAL_HANDLE(SIGPIPE, old_sig);
      alarm(oldival);
      errno = ETIMEDOUT;
      return "TIMEDOUT";
    }
    retval = ident_sockuser2(s,local,remote,buf,buflen);
  } else {
    /* We reach here in case of alarm timer chime... */
    retval = "TIMEDOUT2";
  }  
  if (s >= 0) close(s);
  SIGNAL_HANDLE(SIGALRM, old_alrm);
  SIGNAL_HANDLE(SIGPIPE, old_sig);
  alarm(oldival);
  return retval;
}


#if 0
/* ------- various unused things! ---------------*/

int ident_fd2(fd,inlocal,inremote,local,remote)
register int fd;
register struct in_addr *inlocal;
register struct in_addr *inremote;
register unsigned short *local;
register unsigned short *remote;
{
  struct sockaddr_in sa;
  int dummy;

  dummy = sizeof(sa);
  if (getsockname(fd,(struct sockaddr*)&sa,&dummy) == -1)
    return 1;
  if (sa.sin_family != AF_INET) {
    errno = EAFNOSUPPORT;
    return 2;
  }
  *local = ntohs(sa.sin_port);
  *inlocal = sa.sin_addr;
  dummy = sizeof(sa);
  if (getpeername(fd,(struct sockaddr*)&sa,&dummy) == -1)
    return 3;
  *remote = ntohs(sa.sin_port);
  *inremote = sa.sin_addr;
  return 0;
}


static int usercmp(u,v)
register char *u;
register char *v;
{
  register char uc;
  register char vc;
  register char ucvc;
  /* is it correct to consider Foo and fOo the same user? yes */
  /* but the function of this routine may change later */
  while ((uc = *u) && (vc = *v)) {
    ucvc = (isupper(uc) ? tolower(uc) : uc) - (isupper(vc) ? tolower(vc) : vc);
    if (ucvc)
      return ucvc;
    else
      ++u,++v;
  }
  return uc || vc;
}

static char identline[SIZ];

char *ident_infoline(user,fd,in)
register char *user; /* the supposed name of the user, NULL if unknown */
register int fd; /* the file descriptor of the connection */
register struct in_addr *in;
{
  unsigned short local;
  unsigned short remote;
  register char *ruser;

  if (ident_fd(fd,in,&local,&remote) == -1)
    return 0;
  ruser = ident_tcpuser(*in,local,remote);
  if (!ruser)
    return 0;
  if (!user)
    user = ruser; /* forces X-Ident-User */
  sprintf(identline,
	  (usercmp(ruser,user) ? "forgery %s" : "identuser %s"),
	  ruser);
  return identline;
}

int ident_fd(fd,in,local,remote)
register int fd;
register struct in_addr *in;
register unsigned short *local;
register unsigned short *remote;
{
  struct in_addr inlocal;
  return ident_fd2(fd,&inlocal,in,local,remote);
}

static char ruser[SIZ];
static char realbuf[SIZ];
static char *buf;

char *ident_tcpuser(in,local,remote)
register struct in_addr in;
register unsigned short local;
register unsigned short remote;
{
  return ident_tcpuser2(0,in,local,remote);
}


char *ident_tcpuser2(inlocal,inremote,local,remote)
	struct in_addr *inlocal;
	struct in_addr *inremote;
	unsigned short local;
	unsigned short remote;
{
  register int s;

  s = ident_tcpsock(inlocal,inremote);
  if (s == -1)
    return 0;
  return ident_sockuser(s,local,remote);
}

char *ident_tcpuser3(inlocal,inremote,local,remote,timeout)
register struct in_addr *inlocal;
register struct in_addr *inremote;
register unsigned short local;
register unsigned short remote;
register int timeout;
{
  register int s;
  struct timeval tv;
  fd_set wfds;
  register int r;
  register int saveerrno;
  void (*old_sig)__((int));
  char *retval;
 

  SIGNAL_HANDLESAVE(SIGPIPE, SIG_IGN, old_sig);
 
  s = ident_tcpsock(inlocal,inremote);
  if (s == -1) {
    SIGNAL_HANDLE(SIGPIPE, old_sig);
    return "SOCKFAULT1";
  }
  tv.tv_sec = timeout;
  tv.tv_usec = 0;
  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  r = select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv);
  /* XXX: how to handle EINTR? */
  if (r == -1) {
    SIGNAL_HANDLE(SIGPIPE, old_sig);
    CLORETS("SOCKSELERR");
  }
  if (!FD_ISSET(s,&wfds)) {
    close(s);
    errno = ETIMEDOUT;
    SIGNAL_HANDLE(SIGPIPE, old_sig);
    return "TIMEDOUT";
  }
  retval = ident_sockuser(s,local,remote);
  SIGNAL_HANDLE(SIGPIPE, old_sig);

  return retval;
}


char *ident_sockuser(s,local,remote)
register int s;
register unsigned short local;
register unsigned short remote;
{
  register int buflen;
  register int w;
  register int saveerrno;
  char ch;
  unsigned short rlocal;
  unsigned short rremote;
  register int fl;
  fd_set wfds;
  void (*old_sig)__((int));
  char userid[24];
  
  SIGNAL_HANDLESAVE(SIGPIPE, SIG_IGN, old_sig);
  
  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,(struct timeval *) 0);
  /* now s is writable */
#if USENONBLOCK
  if ((fl = fcntl(s,F_GETFL,0)) == -1) {
    SIGNAL_HANDLE(SIGPIPE, old_sig);
    CLORETS("SOCKFCNTL1");
  }
  if (fcntl(s,F_SETFL,~FNDELAY & fl) == -1) {
    SIGNAL_HANDLE(SIGPIPE, old_sig);
    CLORETS("SOCKFCNTL2");
  }
#endif
  buf = realbuf;
  sprintf(buf,"%u , %u\r\n",(unsigned int) remote,(unsigned int) local);
  /* note the reversed order---the example in RFC 931 is misleading */
  buflen = strlen(buf);
  while ((w = write(s,buf,buflen)) < buflen)
    if (w == -1) /* should we worry about 0 as well? */ {
      SIGNAL_HANDLE(SIGPIPE, old_sig);
      saveerrno = errno;
      close(s);
      if (errno = ECONNREFUSED)
	return "NO-IDENT-SERVICE";
      else
	return "SOCKWRITE";
    } else {
      buf += w;
      buflen -= w;
    }
  buf = realbuf;
  while ((w = read(s,&ch,1)) == 1) {
    *buf = ch;
    if ((ch != ' ') && (ch != '\t') && (ch != '\r'))
      ++buf;
    if ((buf - realbuf == sizeof(realbuf) - 1) || (ch == '\n'))
      break;
  }
  SIGNAL_HANDLE(SIGPIPE, old_sig);
  if (w == -1)
    CLORETS("SOCKREAD");
  *buf = 0;

  if ((sscanf(realbuf,"%hd,%hd:%20s:%*[^:]:%s",
	      &rremote,&rlocal,userid,ruser) < 3) ||
      cistrcmp(userid,"userid") != 0                 ) {
    close(s);
    errno = EIO;
    /* makes sense, right? well, not when USERID failed to match ERROR */
    /* but there's no good error to return in that case */

    return "IDENT-NONSENSE";
  }
  if ((remote != rremote) || (local != rlocal)) {
    close(s);
    errno = EIO;
    return "IDENT-NONSENSE2";
  }
  /* we're not going to do any backslash processing */
  close(s);
  return ruser;
}

int ident_tcpsock(inlocal,inremote)
register struct in_addr *inlocal;
register struct in_addr *inremote;
{
  struct sockaddr_in sa;
  register int s;
  register int fl;
  register int saveerrno;

  if ((s = socket(AF_INET,SOCK_STREAM,0)) == -1)
    return -1;
  if (inlocal->s_addr) {
    memset(&sa,0,sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr = *inlocal;
    if (bind(s,(struct sockaddr*)&sa,sizeof(sa)) == -1)
      CLORETS(-1);
  }
  if ((fl = fcntl(s,F_GETFL,0)) == -1)
    CLORETS(-1);
  if (fcntl(s,F_SETFL,FNDELAY | fl) == -1)
    CLORETS(-1);

  memset(&sa,0,sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(ident_tcpport);
  sa.sin_addr = *inremote;
  if (connect(s,(struct sockaddr*)&sa,sizeof(sa)) == -1)
    if (errno != EINPROGRESS)
      CLORETS(-1);
  return s;
}
#endif
