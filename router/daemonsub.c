/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Some functions Copyright 1991-2002 Matti Aarnio.
 */

/*
 *  This file contains "daemon" command callable from configuration
 *  script, along with its support facilities.
 */

#include "mailer.h"
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <sys/file.h>			/* O_RDONLY for run_praliases() */
#include <pwd.h>			/* for run_homedir() */
#include <grp.h>			/* for run_grpmems() */
#include <errno.h>
#ifdef HAVE_SYS_UN_H
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "zsyslog.h"
#include "shmmib.h"
#include "sysexits.h"

extern struct MIB_MtaEntry *MIBMtaEntry;

#ifdef HAVE_DIRENT_H
# include <dirent.h>
#else /* not HAVE_DIRENT_H */
# define dirent direct
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */


#ifdef HAVE_SYS_RESOURCE_H
#ifdef linux
# define _USE_BSD
#endif
#include <sys/resource.h>
#endif

#include "zmsignal.h"

#include "zsyslog.h"
#include "mail.h"
#include "interpret.h"
#include "io.h"
#include "libz.h"
#include "libc.h"

#include "prototypes.h"

#ifndef	_IOFBF
#define	_IOFBF	0
#endif	/* !_IOFBF */


extern const char *traps[];
extern time_t time __((time_t *));
extern int routerdirloops;

#ifndef strchr
extern char *strchr(), *strrchr();
#endif

extern void free_gensym __((void));

static int gothup = 0;

static RETSIGTYPE sig_exit __((int));
static RETSIGTYPE
sig_exit(sig)
int sig;
{
	if (canexit) {
#ifdef	MALLOC_TRACE
		dbfree(); zshfree();
#endif	/* MALLOC_TRACE */
		die(0, "signal");
	}
	mustexit = 1;
	/* no need to reenable signal in USG, once will be enough */
}

RETSIGTYPE
sig_hup(sigarg)
int sigarg;
{
	gothup = 1;
	/* fprintf(stderr,"HUP\n"); */
	SIGNAL_HANDLE(SIGHUP, sig_hup);
}

static void dohup __((int));
static void
dohup(sig)
int sig;
{
	gothup = 0;
	if (traps[SIGHUP] != NULL)
		eval(traps[SIGHUP], "trap", NULL, NULL);
}


/*
 * Run the Router in Daemon mode.
 */

/* DIRQUEUE structure forward definition */

struct dirqueue;

/*
 * We run in multiple processes mode; much of the same how scheduler
 * does its magic:  Children send log messages, and hunger announcements
 * to the master, and the master feeds jobs to the children.
 * Minimum number of child processes started is 1.
 */

#define MAXROUTERCHILDS 40
struct router_child {
  int   tochild;
  int   fromchild;
  int   childpid;
  int   hungry;

  char *linebuf;
  int   linespace;
  int   linelen;

  char  childline[512];
  int	childsize, childout;

  char  readbuf[512];
  int   readsize, readout;

  int   statloc;
#if defined(HAVE_SYS_RESOURCE_H)
  struct rusage r;
#endif

  struct dirqueue  *dq;
  u_long task_ino;
};

struct router_child routerchilds[MAXROUTERCHILDS];

extern int nrouters;
extern const char *logfn;

/* ../scheduler/pipes.c */
extern int  pipes_create         __((int *tochild, int *fromchild));
extern void pipes_close_parent   __((int *tochild, int *fromchild));
extern void pipes_to_child_fds   __((int *tochild, int *fromchild));
extern void pipes_shutdown_child __((int tochild)); /* At parent, shutdown channel towards child */

/* ../scheduler/resources.c */
extern int  resources_query_nofiles  __((void));
extern void resources_maximize_nofiles __((void));
extern void resources_limit_nofiles __((int nfiles));
extern int  resources_query_pipesize __((int fildes));

static void child_server __((int tofd, int frmfd));
static int  rd_doit __((const char *filename, const char *dirs));
static int  parent_reader __((int waittime));
static void notify_reader __((int sock));


static int notifysocket = -1;
static time_t notifysocket_reinit = 1;


static void notifysock_init()
{
	while (notifysocket < 0) {

	  struct sockaddr_un sad;
	  int on = 1;
	  char *notifysock;
	  int oldumask;

	  notifysock = (char *)getzenv("ROUTERNOTIFY");
	  if (!notifysock) {
	    notifysocket_reinit = 0;
	    return;
	  }

#ifdef  AF_UNIX

	  memset(&sad, 0, sizeof(sad));
	  sad.sun_family = AF_UNIX;
	  strncpy(sad.sun_path, notifysock, sizeof(sad.sun_path));
	  sad.sun_path[ sizeof(sad.sun_path)-1 ] = 0;

	  notifysocket = socket(PF_UNIX, SOCK_DGRAM, 0);
	  if (notifysocket < 0) {
	    perror("notifysocket: socket(PF_UNIX)");
	    break;
	  }

	  setsockopt(notifysocket, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on));

	  /* In case that one already exists.. */
	  unlink(sad.sun_path);

	  oldumask = umask(0555);

	  if (bind(notifysocket, (struct sockaddr *)&sad, sizeof sad) < 0) {
	    perror("bind:UNIX notify socket");
	    umask(oldumask);
	    close(notifysocket);
	    notifysocket = -1;
	    break;
	  }
	  umask(oldumask);

	  fd_nonblockingmode(notifysocket);

#if defined(F_SETFD)
	  fcntl(notifysocket, F_SETFD, 1); /* close-on-exec */
#endif
#endif /* AF_UNIX */
	  break;
	}

	if (notifysocket < 0) {
	  time(&notifysocket_reinit);
	  notifysocket_reinit += 10;
	} else
	  notifysocket_reinit = 0;
}


static int  start_child   __((int idx));
static int  start_child (i)
     const int i;
{
  int pid;
  int tofd[2], frmfd[2];

  if (pipes_create(tofd, frmfd) < 0)
    return -1; /* D'uh :-( */

  pid = fork();
  if (pid == 0) { /* child */

    int idx;

    pipes_to_child_fds(tofd,frmfd);
    for (idx = resources_query_nofiles(); idx >= 3; --idx)
	close(idx);

#if 0
    resources_maximize_nofiles();
#endif

    zcloselog();
    /* Each (sub-)process does openlog() all by themselves */
    zopenlog("router", LOG_PID, LOG_MAIL);

    child_server(0, 1);

    exit(0);

  } else if (pid < 0) { /* fork failed - yell and forget it! */
    close(tofd[0]);  close(tofd[1]);
    close(frmfd[0]); close(frmfd[1]);
    fprintf(stderr, "router: start_child(): Fork failed!\n");
    return -1;
  }
  /* Parent */

  pipes_close_parent(tofd,frmfd);

  fd_nonblockingmode(tofd[1]);
  fd_nonblockingmode(frmfd[0]);

  routerchilds[i].tochild   = tofd[1];
  routerchilds[i].fromchild = frmfd[0];
  routerchilds[i].childpid  = pid;
  routerchilds[i].hungry    = 0;
  routerchilds[i].childsize = 0;
  routerchilds[i].childout  = 0;
  return 0;
}

/*
 *	Catch each child-process death, and reap them..
 */
RETSIGTYPE sig_chld(signum)
int signum;
{
	int pid;
	int i;
	int statloc;
#ifdef HAVE_SYS_RESOURCE_H
	struct rusage r;
#endif

	for (;;) {

#ifdef HAVE_SYS_RESOURCE_H
	  memset(&r, 0, sizeof(r));
#endif

#ifdef  HAVE_WAIT4
#ifdef HAVE_SYS_RESOURCE_H
	  pid = wait4(-1, &statloc, WNOHANG, &r);
#else
	  pid = wait4(-1, &statloc, WNOHANG, NULL);
#endif
#else
#ifdef  HAVE_WAIT3
#ifdef HAVE_SYS_RESOURCE_H
	  pid = wait3(&statloc, WNOHANG, &r);
#else
	  pid = wait3(&statloc, WNOHANG, NULL);
#endif
#else
#ifdef	HAVE_WAITPID
	  pid = waitpid(-1, &statloc, WNOHANG);
#else
	  pid = wait(&statloc);
#endif
#endif
#endif
	  if (pid <= 0) break;

	  for (i = 0; i < MAXROUTERCHILDS; ++i)
	    if (pid == routerchilds[i].childpid) {
	      routerchilds[i].childpid = -pid;
	      routerchilds[i].statloc = statloc;
#if defined(HAVE_SYS_RESOURCE_H)
	      routerchilds[i].r = r;
#endif
	    }
	}

	/* re-instantiate the signal handler.. */
#ifdef SIGCLD
	SIGNAL_HANDLE(SIGCLD,  sig_chld);
#else
	SIGNAL_HANDLE(SIGCHLD, sig_chld);
#endif
}

/*
 *  Read whatever there is, detect "#hungry\n" line, and return
 *  status of the hunger flag..
 */

static int reader_getc __((struct router_child *));
static int reader_getc(rc)
     struct router_child *rc;
{
  unsigned char c;

  /* Child exited but 'tochild' still set ? close it! */
  if (rc->childpid < 0 && rc->tochild >= 0) {
    pipes_shutdown_child(rc->tochild);
    rc->tochild = -1;

    /* Back to positive value */
    rc->childpid = - rc->childpid;

    if (logfn) {
      loginit(SIGHUP); /* Reinit/rotate the log every at line .. */
      fprintf(stdout, "[%d] ROUTER CHILD PROCESS TERMINATED; wait() status = ", rc->childpid);
      if (WIFSIGNALED(rc->statloc))
	fprintf(stdout, "SIGNAL %d", WSIGNALSTATUS(rc->statloc));
      else if (WIFEXITED(rc->statloc))
	fprintf(stdout, "EXIT %d", WEXITSTATUS(rc->statloc));
      else
	fprintf(stdout, "0x%04X ??", WEXITSTATUS(rc->statloc));

#if (defined(HAVE_WAIT3) || defined(HAVE_WAIT4))  && \
    defined(HAVE_SYS_RESOURCE_H)

      fprintf(stdout, "; time = %ld.%06ld usr %ld.%06ld sys",
	      (long)rc->r.ru_utime.tv_sec, (long)rc->r.ru_utime.tv_usec,
	      (long)rc->r.ru_stime.tv_sec, (long)rc->r.ru_stime.tv_usec);
#endif

      fprintf(stdout,"\n");
      fflush(stdout);
    }

  }

  errno = 0;

  if (rc->readout >= rc->readsize)
    rc->readout = rc->readsize = 0;
  if (rc->readsize <= 0)
    rc->readsize = read(rc->fromchild, rc->readbuf, sizeof(rc->readbuf));
  /* Now either we have something, or we don't.. */

  if (rc->readsize < 0) {
    errno = EAGAIN;
    return EOF;
  }
  if (rc->readsize == 0) {
    errno = 0;
    return EOF; /* REAL EOF */
  }

  c = rc->readbuf[rc->readout++];
  return (int)c;
}


/* Single child reader.. */
static int _parent_reader __((struct router_child *rc));
static int _parent_reader(rc)
     struct router_child *rc;
{
  int c;

  if (rc->fromchild < 0) return 0;

  /* The FD is in non-blocking mode */

  for (;;) {
    c = reader_getc(rc);
    if (c == EOF) {
      /* Because the socket/pipe is in NON-BLOCKING mode, we
	 may drop here with an ERROR indication, which can be
	 cleared and thing resume later.. */
      if (errno)
	break;

      /* An EOF ? -- child existed ?? */
      if (rc->tochild >= 0)
	close(rc->tochild);
      rc->tochild   = -1;
      if (rc->fromchild >= 0)
	close(rc->fromchild);
      rc->fromchild = -1;
      rc->hungry    = 0;
      rc->task_ino  = 0;
      rc->childpid  = 0;
      break;

    }
    if (rc->linebuf == NULL) {
      rc->linespace = 120;
      rc->linelen  = 0;
      rc->linebuf = emalloc(rc->linespace+2);
    }
    if (rc->linelen+2 >= rc->linespace) {
      rc->linespace <<= 1; /* Double the size */
      rc->linebuf = erealloc(rc->linebuf, rc->linespace+2);
    }
    rc->linebuf[rc->linelen++] = c;
    if (c == '\n') {
      /* End of line */
      rc->linebuf[rc->linelen] = 0;

      /*fprintf(stderr,"_parent_reader[%d] len=%d buf='%s'\n",rc->childpid,rc->linelen,rc->linebuf);*/

      if (rc->linelen == 1) {
	/* Just a newline.. */
	rc->linelen = 0;
	continue;
      }
      if (rc->linelen == 8 && strcmp(rc->linebuf,"#hungry\n")==0) {
	rc->linelen  = 0;
	rc->hungry   = 1;
	rc->task_ino = 0;
	continue;
      }

      /* LOG THIS LINE! */

      if (logfn) {
	loginit(SIGHUP); /* Reinit/rotate the log every at line .. */
	fprintf(stdout, "[%d] ", rc->childpid);
	fputs(rc->linebuf, stdout);
	fflush(stdout);
      }

      rc->linelen = 0;
    }
  }
  return rc->hungry;
}

/* Single child writer.. */
static void _parent_writer __((struct router_child *rc));
static void _parent_writer(rc)
     struct router_child *rc;
{
  int c, left;

  /* FD for writing ?? */
  if (rc->tochild < 0) return;

  /* Anything to write ? */
  for (;rc->childout < rc->childsize;) {
    left = rc->childsize - rc->childout;
    c = write(rc->tochild, rc->childline + rc->childout, left);
    if (c < 0 && errno == EPIPE) {
      pipes_shutdown_child(rc->tochild);
      rc->tochild = -1;
    }
    if (c <= 0) break;
    rc->childout += c;
  }
  /* All written ?? */
  if (rc->childout >= rc->childsize)
    rc->childout = rc->childsize = 0;
}


#ifdef	HAVE_SELECT

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

/* Return info re has some waiting been done */

static int parent_reader(waittime)
	int waittime;
{
  fd_set rdset, wrset;
  int i, highfd, fd, rc;
  struct timeval tv;

  if (notifysocket_reinit && notifysocket_reinit < now)
    notifysock_init();

 redo_again:;

  _Z_FD_ZERO(rdset);
  _Z_FD_ZERO(wrset);

  highfd = notifysocket;
  if (notifysocket >= 0)
    _Z_FD_SET(notifysocket, rdset);

  for (i = 0; i < MAXROUTERCHILDS; ++i) {
    /* Places to read from ?? */
    fd = routerchilds[i].fromchild;
    if (fd >= 0) {
      _Z_FD_SET(fd, rdset);
      if (highfd < fd)
	highfd = fd;
    }
    /* Something wanting to write ?? */
    fd = routerchilds[i].tochild;
    if (fd >= 0 &&
	routerchilds[i].childout < routerchilds[i].childsize) {
      _Z_FD_SET(fd, wrset);
      if (highfd < fd)
	highfd = fd;
    }
  }
#if 0
  if (highfd < 0) return 0; /* Nothing to do! */
#endif

  tv.tv_sec = waittime;
  tv.tv_usec = 0;
  rc = select(highfd+1, &rdset, &wrset, NULL, &tv);

  if (rc == 0) return 1; /* Nothing to do, leave..
			    Did sleep for a second! */

  if (rc < 0) {
    /* Drat, some error.. */
    if (errno == EINTR)
      goto redo_again;
    /* Hmm.. Do it just blindly (will handle error situations) */
    for (i = 0; i < MAXROUTERCHILDS; ++i) {
      _parent_writer(&routerchilds[i]);
      _parent_reader(&routerchilds[i]);
    }
    return 0;  /* Urgh, an error.. */
  }

  /* Ok, select gave indication of *something* being ready for read */

  if (notifysocket >= 0 && _Z_FD_ISSET(notifysocket, rdset))
    notify_reader(notifysocket);

  for (i = 0; i < MAXROUTERCHILDS; ++i) {
    fd = routerchilds[i].tochild;
    if (fd >= 0 && _Z_FD_ISSET(fd, wrset))
      _parent_writer(&routerchilds[i]);
    fd = routerchilds[i].fromchild;
    if (fd >= 0 && _Z_FD_ISSET(fd, rdset))
      _parent_reader(&routerchilds[i]);
  }
  return 1; /* Did some productive job, don't sleep at the caller.. */
}

#else /* NO HAVE_SELECT */
static int parent_reader(waittime)
	int waittime;
{
  int i;
  /* No select, but can do non-blocking -- we hope.. */
  for (i = 0; i < MAXROUTERCHILDS; ++i)
    _parent_reader(&routerchilds[i], waittime);
  return 0;
}
#endif



/*
 * Actual child-process job feeder.  This just puts the thing
 * into the buffer, and writes (if it can)..
 *
 * Requires:  childsize == 0 (buffer is free),
 *            tochild >= 0 (socket exists (and is ready to receive))
 */

static int _parent_feed_child __(( struct router_child *rc,
				   const char *fname, const char *dir ));
static int _parent_feed_child(rc, fname, dir)
     struct router_child *rc;
     const char *fname, *dir;
{
  int i;

  /* Ok, we are feeding him.. */
  rc->hungry = 0;

  /* What shall we feed ?? */
  sprintf(rc->childline, "%s\n", fname);
  /* DIR information is already included at the fname ! */

  rc->childsize = strlen(rc->childline);
  rc->childout  = 0;

  /* Lets try to write it in one go.. */
  i = write(rc->tochild, rc->childline, rc->childsize);
  if (i > 0)
    rc->childout = i;
  if (rc->childout >= rc->childsize)
    rc->childout = rc->childsize = 0;

  return 0;
}

#if 0 /* !!! NOT USED !!!! */
/* -----------------------------------------------------------------
 *
 * Child-process job feeder - distributes jobs in even round-robin
 * manner to all children.  Might some day do resource control a'la
 * "Priority: xyz" -> process subset 2,3,4
 *
 * This looks for free child, and waits for successfull write.
 * ----------------------------------------------------------------- */

static int parent_feed_child __((const char *fname, const char *dir));
static int parent_feed_child(fname,dir)
     const char *fname, *dir;
{
  static int rridx = -1;
  struct router_child *rc = NULL;
  int i;
  char *s;

  do {

    /* Loop until can feed, our caller shall not need to
       refeed message again! */
    /* FIXME: Real proper way is needed, messages to be queued to sets
       of server processes...  Compare with Scheduler's channels. */

    s = strchr(fname,'-');
    if (s && isdigit(*fname)) {
      long thatpid = atoi(s+1);
      if ((thatpid > 1) &&
	  (thatpid != MYPID) &&
	  (kill(thatpid,0)==0)) {
	/* Process of that PID does exist, and possibly even something
	   we can kick.. (we should be *root* here anyway!) */
	for (i = 0; i < MAXROUTERCHILDS; ++i) {
	  /* Is it one of ours children ?? */
	  if (routerchilds[i].childpid == thatpid)
	    return 0; /* Yes! No refeed! */
	}
      }
      /* Hmm..  perhaps it is safe to feed to a subprocess */
    }

    parent_reader(0);

    rridx = 0;
    rc    = NULL;

    if (rridx >= MAXROUTERCHILDS) rridx = 0;

    for (i = 0; i < MAXROUTERCHILDS; ++i) {
      rc = &routerchilds[rridx];

      /* If no child at this slot, start one!
	 (whatever has been the reason for its death..) */
      if (rc->childpid == 0) {
	start_child(rridx);
	sleep(2); /* Allow a moment for child startup */
	parent_reader(0);
      }

      /* If we have a hungry child with all faculties intact.. */
      if (rc->tochild >= 0 && rc->fromchild >= 0 && rc->hungry)
	break;

      /* Next index.. */
      ++rridx; if (rridx >= MAXROUTERCHILDS) rridx = 0;
    }
    /* Failed to find a hungry child!?
       We should not have been called in the first place..  */

  } while (!rc || !rc->hungry || rc->tochild < 0 || rc->fromchild < 0);


  _parent_feed_child(rc, fname, dir);

#if 0 /* NO sync waiting here! */
  /* .. or if not, we wait here until it has been fed.. */
  while (rc->childout < rc->childsize)
    parent_reader(0);
#endif

  return 1; /* Did feed successfully ?? */
}
#endif /* NOT USED!!! */


/*
 * child_server()
 *    The real workhorse at the child, receives work, reports status
 *
 */
static void child_server(tofd,frmfd)
     int tofd, frmfd;
{
  FILE *fromfp = fdopen(tofd,  "r");
  FILE *tofp   = fdopen(frmfd, "w");
  char linebuf[8000];
  char *s, *fn;

  setvbuf(fromfp, NULL, _IOLBF, 0);
  setvbuf(tofp,   NULL, _IOFBF, 0);

  fprintf(tofp, "ROUTER CHILD PROCESS STARTED\n");
  fflush(tofp);

  linebuf[sizeof(linebuf)-1] = 0;

  while (!feof(fromfp) && !ferror(fromfp)) {
    fprintf(tofp, "\n#hungry\n");
    fflush(tofp);

    if (gothup)
      dohup(SIGHUP);

    if (fgets(linebuf, sizeof(linebuf)-1, fromfp) == NULL)
      break; /* EOF ?? */

    s = strchr(linebuf,'\n');
    if (s) *s = 0;
    if (*linebuf == 0)
      break; /* A newline -> exit */

    /* Input is either:  "file.name" or "../path/file.name" */

    fn = strrchr(linebuf,'/');
    if (fn) {
      *fn++ = 0;
      s = linebuf; /* 'Dirs' */
    } else {
      fn = linebuf;
      s = linebuf + strlen(linebuf);
    }
    rd_doit(fn, s);
  }
  /* Loop ends for some reason, perhaps parent died and
     pipe got an EOF ?  We leave... Our caller exits. */

  fprintf(tofp, "ROUTER CHILD PROCESS TERMINATING\n");
  fflush(tofp);
}


/* -----------------------------------------------------------------
 *         Directory Input Queue subsystem
 *
 *         Copied from the Scheduler
 *
 * ----------------------------------------------------------------- */


struct dirstatname {
	struct stat st;
	long ino;
	char *dir; /* Points to stable strings.. */
	char name[1]; /* Allocate enough size */
};
struct dirqueue {
	int	wrksum;
	int	sorted;
	int	wrkcount;
	int	wrkspace;
	struct sptree *mesh;
	struct dirstatname **stats;
};

static int dirqueuescan __((const char *dir,struct dirqueue *dq, int subdirs));

#define ROUTERDIR_CNT 30

struct dirqueue dirqb[ROUTERDIR_CNT];
struct dirqueue *dirq[ROUTERDIR_CNT];

/* Following is filled at  run_daemon(), and cleared also.. */
static char     *routerdirs[ROUTERDIR_CNT];
static char	*routerdirs2[ROUTERDIR_CNT];

/*
 * Absorb any new files that showed up in our directory.
 */

int
dq_insert(DQ, ino, file, dir)
	void *DQ;
	long ino;
	const char *file, *dir;
{
	struct stat stbuf;
	struct dirstatname *dsn;
	struct dirqueue *dq = DQ;
	int i;

	if (!ino) return 1; /* Well, actually it isn't, but we "makebelieve" */

	time(&now);

	if (dq == NULL)
	  dq = dirq[0];

	if (lstat(file,&stbuf) != 0 ||
	    !S_ISREG(stbuf.st_mode)) {
	  /* Not a regular file.. Let it be there for the manager
	     to wonder.. */
	  return -1;
	}

#if 0
	loginit(SIGHUP); /* Reinit/rotate the log every at line .. */
	fprintf(stdout,"dqinsert: ino=%ld file='%s' dir='%s'\n",ino,file,dir);
#endif

	/* Is it already in the database ? */
	if (sp_lookup((u_long)ino,dq->mesh) != NULL) {
#if 0
	  fprintf(stderr,"daemonsub: tried to dq_insert(ino=%ld, file='%s') already in queue\n",ino, file);
#endif
	  return 1; /* It is! */
	}

	for (i = 0; i < MAXROUTERCHILDS; ++i)
	  if (ino == routerchilds[i].task_ino)
	    return 1; /* In active processing! */

	/* Now store the entry */
	dsn = (struct dirstatname*)emalloc(sizeof(*dsn)+strlen(file)+1);
	memcpy(&(dsn->st),&stbuf,sizeof(stbuf));
	dsn->ino = ino;
	dsn->dir = strdup(dir);
	strcpy(dsn->name,file);

	sp_install(ino, (void *)dsn, 0, dq->mesh);

	/* Into the normal queue */
	if (dq->wrkspace <= dq->wrkcount) {
	  /* Increase the space */
	  dq->wrkspace = dq->wrkspace ? dq->wrkspace << 1 : 8;

	  /* malloc(size) == realloc(NULL,size) */
	  dq->stats = (struct dirstatname**)erealloc(dq->stats,
						     sizeof(void*) *
						     dq->wrkspace);
	}

	dq->stats[dq->wrkcount] = dsn;
	dq->wrkcount += 1;
	dq->wrksum   += 1;
	dq->sorted    = 0;

	++MIBMtaEntry->mtaReceivedMessagesRt;

	return 0;
}

int in_dirscanqueue(DQ,ino)
	void *DQ;
	long ino;
{
	struct dirqueue *dq = DQ;

	if (dq == NULL)
	  dq = dirq[0];

	/* Return 1, if can find the "ino" in the queue */

	if (dq->wrksum == 0 || dq->mesh == NULL) return 0;
	if (sp_lookup((u_long)ino, dq->mesh) != NULL) return 1;
	return 0;
}

static int dq_ctimecompare __((const void *, const void *));
static int dq_ctimecompare(b,a) /* we want oldest entry LAST */
const void *a; const void *b;
{
	const struct dirstatname **A = (const struct dirstatname **)a;
	const struct dirstatname **B = (const struct dirstatname **)b;
	int rc;

	rc = ((*B)->st.st_mtime - (*A)->st.st_mtime);
	return rc;
}


static int dirqueuescan(dir, dq, subdirs)
	const char *dir;
	struct dirqueue *dq;
	int subdirs;
{
	DIR *dirp;
	struct dirent *dp;
	struct stat stbuf;
	char file[MAXNAMLEN+1];
	int newents = 0;

#if 0
	static time_t modtime = 0;

	/* Any changes lately ? */
	if (estat(dir, &stbuf) < 0)
	  return -1;	/* Could not stat.. */
	if (stbuf.st_mtime == modtime)
	  return 0;	/* any changes lately ? */
	modtime = stbuf.st_mtime;
#endif

	/* Some changes lately, open the dir and read it */

	dirp = opendir(dir);
	if (!dirp) return 0;

	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
	  /* Scan filenames into memory */

	  if (subdirs &&
	      dp->d_name[0] >= 'A' &&
	      dp->d_name[0] <= 'Z' &&
	      dp->d_name[1] ==  0 ) {
	    /* We do this recursively.. */
	    if (dir[0] == '.' && dir[1] == 0)
	      strcpy(file, dp->d_name);
	    else
	      sprintf(file, "%s/%s", dir, dp->d_name);

	    if (lstat(file,&stbuf) != 0 ||
		!S_ISDIR(stbuf.st_mode)) {
	      /* Not a directory.. Let it be there for the manager
		 to wonder.. */
	      continue;
	    }
	    /* Recurse into levels below.. */
	    newents += dirqueuescan(file, dq, subdirs);
	    continue;
	  } /* End of directories of names "A" .. "Z" */

	  if (dp->d_name[0] >= '0' &&
	      dp->d_name[0] <= '9') {
	    /* A file whose name STARTS with a number (digit) */

	    long ino = atol(dp->d_name);
	    if (in_dirscanqueue(dq,ino))
	      /* Already in pre-schedule-queue */
	      continue;

	    if (dir[0] == '.' && dir[1] == 0)
	      strcpy(file, dp->d_name);
	    else
	      sprintf(file, "%s/%s", dir, dp->d_name);

	    if (dq_insert(dq, ino, file, dir))
	      continue;

	    ++newents;
	    dq->sorted = 0;
	  } /* ... end of "filename starts with a [0-9]" */
	}

#ifdef	BUGGY_CLOSEDIR
	/*
	 * Major serious bug time here;  some closedir()'s
	 * free dirp before referring to dirp->dd_fd. GRRR.
	 * XX: remove this when bug is eradicated from System V's.
	 */
	close(dirp->dd_fd);
#endif
	closedir(dirp);

	return newents;
}


int syncweb(rc)
	struct router_child *rc;
{
	struct stat *stbuf;
	char *file, *ddir;
	struct dirstatname *dqstats;
	struct spblk *spl;
	int wrkcnt = 0;
	long ino;
	struct dirqueue *dq = rc->dq;
	int wrkidx = dq->wrkcount -1;

	/* Any work to do ? */
	if (dq->wrksum == 0) return 0;

	time(&now);

	if (stability && !dq->sorted && dq->wrkcount > 1) {

	  /* Sort the dq->stats[] per file ctime -- LATEST on slot 0.
	     (we drain this queue from the END) */

	  qsort( (void*)dq->stats,
		 dq->wrkcount,
		 sizeof(void*),
		 dq_ctimecompare );

	  dq->sorted = 1;

	}

	/* Ok some, decrement the count to change it to index */

	dqstats = dq->stats[wrkidx];
	file  =   dqstats->name;
	ddir  =   dqstats->dir;
	stbuf = &(dqstats->st);
	ino   =   dqstats->ino;

	rc->task_ino = ino; /* Mark this INO into processing */
	_parent_feed_child(rc, file, ddir);

	dq->wrkcount -= 1;
	dq->wrksum   -= 1;

	if (dq->wrkcount > wrkidx) {
	  /* Skipped some ! Compact the array ! */
	  memcpy( &dq->stats[wrkidx], &dq->stats[wrkidx+1],
		  sizeof(dq->stats[0]) * (dq->wrkcount - wrkidx));
	}
	dq->stats[dq->wrkcount] = NULL;

	/* Now we have pointers */

	/* Deletion from the  dq->mesh  should ALWAYS succeed.. */
	spl = sp_lookup((u_long)ino, dq->mesh);
	if (spl != NULL)
	  sp_delete(spl, dq->mesh);

	/* Free the pre-schedule queue entry */
	free(dqstats);
	free(ddir);

	return wrkcnt;
}

/*
 *  The  notify_reader()  receives messages from message submitters,
 *  and uses them to find (most of the) new jobs.
 *
 *  The messages are of SPACE separated string:  'NEW dirname X/Y/filename'
 *
 */

static void notify_reader(sock)
	int sock;
{
	char buf[1000], *r, *p, *s;
	int i, ok, cnt;
	long ino;

	/* Pick at most 10 in a row */
	for (cnt=10; cnt!=0; --cnt) {

	  i = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
	  if (i <= 0 && errno != EINTR) return;
	  if (i < 0) continue;

	  if (i >= sizeof(buf)) i = sizeof(buf)-1;
	  buf[i] = 0;

	  /* The only supported notify is:
	       "NEW router X/Y/file-name"
	     message */

#if 0 /* DEBUG IT! */
	  if (logfn) {
	    loginit(SIGHUP); /* Reinit/rotate the log every at line .. */
	    fprintf(stdout, "NOTIFY got: i=%d '%s'\n", i, buf);
	    fflush(stdout);
	  }
#endif

	  if (strncmp(buf,"NEW ",4) != 0) continue;

	  r = s = p = buf+4;
	  while (*s != 0 && *s != ' ') ++s;
	  if (*s == ' ') *s++ = 0;
	  p = s;
	  ok = 0;

	  if ('1' <= s[0] && s[0] <= '9' && strchr(s, '/') == NULL) {
	    ok = 1;
	  } else  if ('A' <= s[0] && s[0] <= 'Z' && s[1] == '/') {
	    s += 2;
	    if ('1' <= s[0] && s[0] <= '9' && strchr(s, '/') == NULL) {
	      ok = 1;
	    } else  if ('A' <= s[0] && s[0] <= 'Z' && s[1] == '/') {
	      s += 2;
	      if ('1' <= s[0] && s[0] <= '9' && strchr(s, '/') == NULL) {
		ok = 1;
	      }
	    }
	  }
	  if (!ok) continue;

	  ino = atol(p);

	  for (i = 0; i < ROUTERDIR_CNT; ++i) {
	    if (routerdirs[i] && strcmp(routerdirs[i],r) == 0) {
#if 0
	      if (lstat(p,&stbuf) != 0) continue;
	      if (!S_ISFILE(stbuf.st_mode)) continue;

	      if (in_dirscanqueue(dirq[i],stbuf.st_ino)) continue;
#endif
#if 0 /* DEBUG IT! */
	      if (logfn) {
		loginit(SIGHUP); /* Reinit/rotate the log every at line .. */
		fprintf(stdout, " ... routerdirs[%d] == '%s', ino=%ld, file='%s'\n",
			i, routerdirs[i], ino, p);
		fflush(stdout);
	      }
	      zsyslog((LOG_INFO, "notify dir='%s' ino=%ld file='%s'",
		       r, ino, p));
#endif

	      dq_insert(dirq[i], ino, p, routerdirs2[i]);
	      break;
	    }
	  }

	}
}




/* "rd_doit()" at the feeding parent server */


/*
 * STABILITY option will make the router process incoming messages in
 * arrival (modtime) order, instead of randomly determined by position
 * in the router directory.  The scheme is to read in all the names,
 * and stat the files.  It would be possible to reuse the stat information
 * later, but I'm not convinced it is worthwhile since the later stat is
 * an fstat().  On the other hand, if we used splay tree insertion to
 * sort the entries, then the stat buffer could easily be reused in
 * makeLetter().
 *
 * SECURITY WARNING: iff makeLetter does not stat again, then there is
 * a window of opportunity for a Bad Guy to remove a file after it has
 * been stat'ed (with root privs), and before it has been processed.
 * This can be avoided partially by sticky-bitting the router directory,
 * and entirely by NOT saving the stat information we get here.
 */

int
run_doit(argc, argv)
	int argc;
	const char *argv[];
{
	const char *filename;
	char *sh_memlevel = getlevel(MEM_SHCMD);
	int r;
	const char *av[3];

	if (argc != 2) {
	  fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
	  return 1;
	}

	filename = argv[1];

	/* Do one file, return value is 0 or 1,
	   depending on actually doing something
	   on a file */

	gensym = 1;
	av[0] = "process"; /* I think this needs to be here */
	av[1] = filename;
	av[2] = NULL;
	r = s_apply(2, av); /* "process" filename (within  rd_doit() ) */
	free_gensym();

	setlevel(MEM_SHCMD,sh_memlevel);

	return r;
}

static int
rd_doit(filename, dirs)
	const char *filename, *dirs;
{
	/* Do one file, return value is 0 or 1,
	   depending on actually doing something
	   on a file */

#ifdef	USE_ALLOCA
	char *buf;
#else
	static char *buf = NULL;
	static u_int blen = 0;
#endif
	const char *av[3];
	char *p;
	int len;
	char pathbuf[512];
	char *sh_memlevel = getlevel(MEM_SHCMD);
	int thatpid;
	struct stat stbuf;

	router_id = getpid();

	*pathbuf = 0;
	if (*dirs) {	/* If it is in alternate dir, move to primary one,
			   and process there! */
	  strcpy(pathbuf,dirs);
	  strcat(pathbuf,"/");
	}
	strcat(pathbuf,filename);

	len = strlen(filename);
	thatpid = 0;
	p = strchr(filename, '-');
	if (p != NULL) {
	  /* message file is "inode-pid" */
	  thatpid = atoi(p+1);

#if 0 /* very old thing, may harm at Solaris 2.6 ! */
	  if (thatpid < 10) {	/* old-style locking.. */
	    thatpid = 0;
	  }
#endif
	  /* Probe it!
	     Does the process exist ? */
	  if (thatpid && (kill(thatpid,0)==0) && (thatpid != router_id)) {
	    /*
	     * an already locked message file,
	     * belonging to another process
	     */
	    if (*dirs) {
	      fprintf(stderr,
		      "** BUG **: %s%s not in primary router directory!\n",
		      dirs,filename);
	    }
	    return 0;
	    /*
	     * This should not happen anywhere but at
	     * primary router directory.  If  xxxx-nn
	     * format file exists anywhere else, it is
	     * a bug time!
	     */
	  }
	}
	if (strncmp(filename,"core",4) != 0 &&
	    ((p == NULL) || (thatpid != router_id))) {
	  /* Not a core file, and ...
	     not already in format of 'inode-pid' */
	  /* If the pid did exist, we do not touch on that file,
	     on the other hand, we need to rename the file now.. */
#ifdef	USE_ALLOCA
	  buf = (char*)alloca(len+16);
#else
	  if (blen == 0) {
	    blen = len+16;
	    buf = (char *)malloc(len+16);
	  }
	  while (len + 12 > blen) {
	    blen = 2 * blen;
	    buf = (char *)realloc(buf, blen);
	  }
#endif
	  /* Figure out its inode number */
	  if (lstat(pathbuf,&stbuf) != 0) return 0; /* Failed ?  Well, skip it */
	  if (!S_ISREG(stbuf.st_mode))   return 0; /* Not a regular file ??   */

	  sprintf(buf, "%ld-%d", (long)stbuf.st_ino, router_id);

	  if (eqrename(pathbuf, buf) < 0)
	    return 0;		/* something is wrong, erename() complains.
				   (some other process picked it ?) */
	  filename = buf;
	  /* message file is now "file-#" and belongs to this process */
	}

#ifdef	MALLOC_TRACE
	mal_contents(stdout);
#endif

	gensym = 1;
	av[0] = "process"; /* I think this needs to be here */
	av[1] = filename;
	av[2] = NULL;
	s_apply(2, av); /* "process" filename (within  rd_doit() ) */
	free_gensym();

	setlevel(MEM_SHCMD,sh_memlevel);

#ifdef MALLOC_TRACE
	mal_contents(stdout);
#endif

	return 1;
}


int
run_stability(argc, argv)
	int argc;
	const char *argv[];
{
	switch (argc) {
	case 1:
		printf("%s %s\n", argv[0], stability ? "on" : "off");
		break;
	case 2:
		if (strcmp(argv[1], "on") == 0) {
			real_stability = 1;
			break;
		} else if (strcmp(argv[1], "off") == 0) {
			real_stability = 0;
			break;
		}
	default:
		fprintf(stderr, "Usage: %s [ on | off ]\n", argv[0]);
		return EX_USAGE;
	}
	return 0;
}

int
run_daemon(argc, argv)
	int argc;
	const char *argv[];
{
	DIR *dirp[ROUTERDIR_CNT];  /* Lets say we have max 30 router dirs.. */
	int i, ii;
	const char *s, *rd;
	const char *routerdir_s = getzenv("ROUTERDIRS");
	char pathbuf[256];
	memtypes oval = stickymem;

	time_t nextdirscan = 0;

	if (nrouters > MAXROUTERCHILDS)
	  nrouters = MAXROUTERCHILDS;


	memset(routerchilds, 0, sizeof(routerchilds));

	for (i = 0; i < MAXROUTERCHILDS; ++i)
	  routerchilds[i].fromchild = 
	    routerchilds[i].tochild = -1;

	/* instantiate the signal handler.. */
#ifdef SIGCLD
	SIGNAL_HANDLE(SIGCLD,  sig_chld);
#else
	SIGNAL_HANDLE(SIGCHLD, sig_chld);
#endif

	SIGNAL_HANDLE(SIGTERM, sig_exit);	/* mustexit = 1 */

	memset(&dirqb, 0, sizeof(dirqb));
	for (i=0; i<ROUTERDIR_CNT; ++i) {
	  dirq[i] = &dirqb[i];
	  dirqb[i].mesh = sp_init();
	  dirp[i] = NULL;
	  routerdirs[i] = NULL;
	  routerdirs2[i] = NULL;
	}
	/* dirp[0] = opendir("."); */	/* assert dirp != NULL ... */

#if 0
#ifdef BSD
	dirp[0]->dd_size = 0;	/* stupid Berkeley bug workaround */
#endif
#endif

	for (ii = 0; ii < nrouters; ++ii)
	  routerchilds[ii].dq = dirq[0];

	ii = MAXROUTERCHILDS;

	stickymem = MEM_MALLOC;
	routerdirs[0]  = strnsave("router",6);
	routerdirs2[0] = strnsave(".",2);
	if (routerdir_s) {
	  /* Store up secondary router dirs! */
	  rd = routerdir_s;
	  for (i = 1; i < ROUTERDIR_CNT && *rd; ) {

	    s = strchr(rd,':');
	    if (s)  *(char*)s = 0;
	    sprintf(pathbuf,"../%s",rd);
	    /* strcat(pathbuf,"/"); */

	    routerdirs[i] = strdup(rd);
	    routerdirs2[i] = strdup(pathbuf);

	    if (ii > 2)
	      routerchilds[ --ii ].dq = dirq[i];

	    ++i;

	    if (s) *(char*)s = ':';
	    if (s)
	      rd = s+1;
	    else
	      break;
	  }
	}


	setfreefd();
	stickymem = oval;

	/* Do initial synchronous queue scan now */

	for (i = 0; i < ROUTERDIR_CNT; ++i) {
	  if (routerdirs2[i])
	    dirqueuescan(routerdirs2[i], dirq[i], 1);
	}

	for (i = 0; i < MAXROUTERCHILDS; ++i) {
	  if ( routerchilds[i].dq &&
	       routerchilds[i].dq->wrkcount )
	    if (start_child(i))
	      break; /* fork failed.. */
	}

	sleep(5); /* Wait a bit before continuting so that
		     child processes have change to boot */

	/* Collect start reports (initial "#hungry\n" lines) */
	parent_reader(0);

	for (; !mustexit ;) {

	    time(&now);
	    if (now > nextdirscan) {
	      nextdirscan = now + 10;

	      for (i = 0; i < ROUTERDIR_CNT; ++i) {
		if (routerdirs2[i])
		  dirqueuescan(routerdirs2[i], dirq[i], 1);
	      }
	    }

	    for (i = 0; i < MAXROUTERCHILDS; ++i) {
	      if ( routerchilds[i].tochild < 0 &&
		   routerchilds[i].dq &&
		   routerchilds[i].dq->wrkcount )
		start_child(i);

	      if ( routerchilds[i].tochild >= 0 &&
		   routerchilds[i].childsize == 0 &&
		   routerchilds[i].hungry &&
		   routerchilds[i].dq &&
		   routerchilds[i].dq->wrkcount > 0 ) {
		/* Feed this ! */
		syncweb(&routerchilds[i]);
	      }
	    }

	    parent_reader(1);
	}

	for (i=0; i < ROUTERDIR_CNT; ++i) {
	  if (routerdirs2[i])
	    free(routerdirs2[i]);
	  routerdirs2[i] = NULL;
	  if (routerdirs[i])
	    free(routerdirs[i]);
	  routerdirs[i] = NULL;
	}

	return 0;
}

/*
 * Based on the name of a message file, figure out what to do with it.
 */

struct protosw {
	const char *pattern;
	const char *function;
} psw[] = {
/*{	"[0-9]*.x400",		"x400"		}, */
/*{	"[0-9]*.fax",		"fax"		}, */
/*{	"[0-9]*.uucp",		"uucp"		}, */
{	"[0-9]*",		"rfc822"	},
};


int
run_process(argc, argv)
	int argc;
	const char *argv[];
{
	struct protosw *pswp;
	char *file;
	int r;
	char *sh_memlevel = getlevel(MEM_SHCMD);

	if (argc != 2 || argv[1][0] == '\0') {
		fprintf(stderr, "Usage: %s messagefile\n", argv[0]);
		return PERR_USAGE;
	}
#ifdef	USE_ALLOCA
	file = (char*)alloca(strlen(argv[1])+1);
#else
	file = (char*)emalloc(strlen(argv[1])+1);
#endif
	strcpy(file, argv[1]);

	r = 0;	/* by default, ignore it */
	for (pswp = &psw[0]; pswp < &psw[(sizeof psw / sizeof psw[0])]; ++pswp)
		if (strmatch(pswp->pattern, file)) {
			printf("process %s %s\n", pswp->function, file);
			argv[0] = pswp->function;
			r = s_apply(argc, argv); /* process-by-FUNC filename */
			printf("done with %s\n", file);
			if (r)
				printf("status %d\n", r);
			break;
		}

#ifndef	USE_ALLOCA
	free(file);
#endif
	setlevel(MEM_SHCMD,sh_memlevel);

	return r;
}
