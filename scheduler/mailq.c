/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1999
 */

/*
 * This program must be installed suid to the uid the scheduler runs as
 * (usually root).  Unfortunately.
 */


#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <sysexits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <pwd.h>
#include <stdlib.h>
#include "mail.h"
#include "scheduler.h"
#include "zmalloc.h"
#include "mailer.h"

#include "md5.h"

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


#if	defined(HAVE_SOCKET) && (defined(HAVE_RESOLVER) || defined(HAVE_YP))
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/file.h>
#endif	/* HAVE_SOCKET */
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef	MALLOC_TRACE
struct conshell *envarlist = NULL;
#endif	/* MALLOC_TRACE */
int	D_alloc = 0;


#include "prototypes.h"
#include "memtypes.h"
#include "token.h"
#include "libz.h"
#include "libc.h"

extern char *qoutputfile;
extern int errno, pokedaemon();

#ifndef strchr
extern char *strchr(), *strrchr();
#endif

const char	*progname;
const char	*postoffice;

static char *port = NULL;

char * v2username = "nobody";
char * v2password = "nobody";

int	debug, verbose, summary, user, status, onlyuser, nonlocal, schedq;
int	sawcore, othern;

time_t	now;

extern char *optarg;
extern int   optind;
char	path[MAXPATHLEN];

char *host = NULL;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int fd, c, errflg, eval;
	struct passwd *pw;
#ifndef	AF_INET
	char *rendezvous = NULL;
	FILE *fp;
	struct stat stbuf;
	int r, pid, dsflag;
#endif	/* AF_INET */

	progname = argv[0];
	verbose = debug = errflg = status = user = onlyuser = summary = 0;
	while (1) {
	  c = getopt(argc, argv, "dip:r:stu:vVSQ");
	  if (c == EOF)
	    break;
	  switch (c) {
	  case 'd':
	    ++debug;
	    break;
	  case 'i':
	    user = getuid();
	    onlyuser = 1;
	    if (verbose == 0)
	      ++verbose;
	    break;
#if defined(AF_INET) || defined(AF_UNIX)
	  case 'p':
	    port = optarg;
	    break;
#else  /* !AF_INET */
	  case 'r':
	    rendezvous = optarg;
	    break;
#endif /* AF_INET */
	  case 's':
	    ++status;
	    break;
	  case 't':
	    verbose = 0;
	    break;
	  case 'u':
	    if (optarg == NULL) {
	      ++errflg;
	      break;
	    }
	    if ((pw = getpwnam(optarg)) == NULL) {
	      fprintf(stderr, "%s: unknown user '%s'\n", progname, optarg);
	      ++errflg;
	      break;
	    }
	    user = pw->pw_uid;
	    onlyuser = 1;
	    if (verbose == 0)
	      ++verbose;
	    break;
	  case 'v':
	    ++verbose;
	    break;
	  case 'S':
	    ++summary;
	    break;
	  case 'Q':
	    ++schedq;
	    break;
	  case 'V':
	    prversion("mailq");
	    exit(0);
	    break;
	  default:
	    ++errflg;
	    break;
	  }
	}
	time(&now);
	if (optind < argc) {
#ifdef	AF_INET
	  if (optind != argc - 1) {
	    fprintf(stderr, "%s: too many hosts\n", progname);
	    ++errflg;
	  } else
	    host = argv[optind];
#else  /* !AF_INET */
	  fprintf(stderr, "%s: not compiled with AF_INET\n", progname);
	  ++errflg;
#endif /* AF_INET */
	}
	if (errflg) {
#ifdef	AF_INET
	  fprintf(stderr, "Usage: %s [-isSvt] [-p#] [host]\n", progname);
#else  /* !AF_INET */
	  fprintf(stderr, "Usage: %s [-isSvt]\n", progname);
#endif /* AF_INET */
	  exit(EX_USAGE);
	}
	if ((postoffice = getzenv("POSTOFFICE")) == NULL)
	  postoffice = POSTOFFICE;

	sprintf(path, "%s/%s", postoffice, PID_SCHEDULER);

	errno = 0;

#if defined(AF_UNIX) && defined(HAVE_SYS_UN_H)
	if (port && *port == '/') {
	  struct sockaddr_un sad;

	  if (status) {
	    checkrouter();
	    checkscheduler();
	    if (status > 1 && !summary)
	      exit(0);
	  }

	  /* try grabbing a port */
	  fd = socket(PF_UNIX, SOCK_STREAM, 0);
	  if (fd < 0) {
	    fprintf(stderr, "%s: ", progname);
	    perror("socket");
	    exit(EX_UNAVAILABLE);
	  }

	  sad.sun_family = AF_UNIX;
	  strncpy(sad.sun_path, port, sizeof(sad.sun_path));
	  sad.sun_path[ sizeof(sad.sun_path) ] = 0;

	  if (connect(fd, (void*)&sad, sizeof sad) < 0) {
	    fprintf(stderr,"%s: connect failed to path: '%s'\n",progname,sad.sun_path);
	    exit(EX_UNAVAILABLE);
	  }

	  docat((char *)NULL, fd);
	}
#endif
#ifdef	AF_INET
	if (!port || (port && *port != '/')) {

	  struct in_addr naddr;
	  struct hostent *hp = NULL, he;
	  struct sockaddr_in sad;
	  struct servent *serv = NULL;

	  int portnum = 174;
	  nonlocal = 0; /* Claim it to be: "localhost" */

	  if (status < 2 || summary) {

	    if (port && isdigit(*port)) {
	      portnum = atol(port);
	    } else if (port == NULL &&
		       (serv = getservbyname(port ? port : "mailq", "tcp")) == NULL) {

	      fprintf(stderr,"%s: cannot find 'mailq' tcp service\n",progname);

	    } else if (port == 0)
	      
	      portnum = ntohs(serv->s_port);

	    if (host == NULL) {
	      host = getzenv("MAILSERVER");
	      if ((host == NULL || *host == '\n')
		  && (host = whathost(path)) == NULL) {
		if (status > 0) {
		  host = "127.0.0.1"; /* "localhost" */
		  nonlocal = 0;
		} else {
		  if (whathost(postoffice)) {
		    fprintf(stderr, "%s: %s is not active", progname, postoffice);
		    fprintf(stderr, " (\"%s\" does not exist)\n", path);
		  } else
		    fprintf(stderr, "%s: cannot find postoffice host\n", progname);
		  exit(EX_OSFILE);
		}
	      }
	    }
	    hp = gethostbyname(host);
	    if (hp == NULL) {
	      if (inet_pton(AF_INET, host, &naddr.s_addr) == 1) {
		hp = gethostbyaddr((void*)&naddr, sizeof(naddr), AF_INET);
		if (hp == NULL){
		  hp = &he;
		  he.h_name = host;
		  he.h_length = 4;
		}
	      } else if (hp == NULL) {
		fprintf(stderr, "%s: cannot find address of %s\n", progname, host);
		exit(EX_UNAVAILABLE);
	      }
	    }
	    if (strcmp(host, "localhost") != 0 &&
		strcmp(host, "127.0.0.1") != 0) {
	      fprintf(stdout,"[%s]\n", hp->h_name);
	      nonlocal = 1;
	    } else
	      nonlocal = 0;	/* "localhost" is per default a "local" */
	  }
	  if (status) {
	    checkrouter();
	    checkscheduler();
	    if (status > 1 && !summary)
	      exit(0);
	  }
	  /* try grabbing a port */
	  fd = socket(PF_INET, SOCK_STREAM, 0);
	  if (fd < 0) {
	    fprintf(stderr, "%s: ", progname);
	    perror("socket");
	    exit(EX_UNAVAILABLE);
	  }
	  sad.sin_family = AF_INET;
	  if (hp == &he)
	    sad.sin_addr.s_addr = htonl(naddr.s_addr);
	  else {
	    char *addr;

	    eval = EFAULT;
	    hp_init(hp);
	    while ((addr = *hp_getaddr()) != NULL) {
	      sad.sin_addr.s_addr = 0;
	      sad.sin_port = htons((short)0);
	      if (bind(fd, (void*)&sad, sizeof sad) < 0) {
		fprintf(stderr, "%s: ", progname);
		perror("bind");
		exit(EX_UNAVAILABLE);
	      }
	      sad.sin_port = htons(portnum);
	      memcpy((void*)&sad.sin_addr, addr, hp->h_length);
	      if (connect(fd, (void*)&sad, sizeof sad) < 0) {
		eval = errno;
		fprintf(stderr, "%s: connect failed to %s", progname,
			dottedquad(&sad.sin_addr));
		if ((addr = *hp_nextaddr()) != NULL) {
		  memcpy((char *)&sad.sin_addr, addr, hp->h_length);
		  fprintf(stderr, ", trying %s...\n", dottedquad(&sad.sin_addr));
		} else
		  putc('\n', stderr);
		close(fd);
		if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
		  fprintf(stderr, "%s: ", progname);
		  perror("socket");
		  exit(EX_UNAVAILABLE);
		}
		continue;
	      }
	      break;
	    }
	    if (*hp_getaddr() == NULL) {
	      fprintf(stderr, "%s: ", progname);
	      errno = eval;
	      perror("connect");
	      fprintf(stderr, "%s: unable to contact scheduler on %s\n",
		      progname, hp->h_name);
	      exit(EX_UNAVAILABLE);
	    }
	  }
	  docat((char *)NULL, fd);
	}
#else	/* !AF_INET */
	if (strcmp(host, "localhost") == 0 ||
	    strcmp(host, "127.0.0.1") == 0) {
	  nonlocal = 0;	/* "localhost" is per default a "local" */
	if (status) {
	  checkrouter();
	  checkscheduler();
	  if (status > 1 && !summary)
	    exit(0);
	}
	r = isalive(PID_SCHEDULER, &pid, &fp);
	if (r == EX_OSFILE)
	  exit(r);
	else if (r == EX_UNAVAILABLE) {
	  fprintf(stderr, "%s: no active scheduler process\n", progname);
	  exit(r);
	} else if (fp != NULL)
	  fclose(fp);
	if (rendezvous == NULL && (rendezvous=getzenv("RENDEZVOUS")) == NULL) {
	  rendezvous = qoutputfile;
	}
#ifdef	S_IFIFO
	if (stat(rendezvous, &stbuf) < 0) {
	  unlink(rendezvous);
	  if (mknod(rendezvous, S_IFIFO|0666, 0) < 0) {
	    fprintf(stderr, "%s: mknod: %s\n", progname, strerror(errno));
	    exit(EX_UNAVAILABLE);
	  }
	  stbuf.st_mode |= S_IFIFO; /* cheat on the next test... */
	}
	if (stbuf.st_mode & S_IFIFO) {
	  if ((fd = open(rendezvous, O_RDONLY|O_NDELAY, 0)) < 0) {
	    fprintf(stderr, "%s: %s: %s\n", progname, rendezvous, strerror(errno));
	    exit(EX_OSFILE);
	  }
	  dsflag = fcntl(fd, F_GETFL, 0);
	  dsflag &= ~O_NDELAY;
	  fcntl(fd, F_SETFL, dsflag);
	  pokedaemon(pid);
	  /* XX: reset uid in case we are suid - we need to play games */
	  sleep(1);		/* this makes it work reliably. WHY ?! */
	  docat((char *)NULL, fd);
	} else
#endif	/* S_IFIFO */
	{
	  pokedaemon(pid);
	  /* XX: reset uid in case we are suid */
	  /* sleep until mtime < ctime */
	  do {
	    sleep(1);
	    if (stat(rendezvous, &stbuf) < 0)
	      continue;
	    if (stbuf.st_mtime < stbuf.st_ctime)
	      break;
	  } while (1);
	  docat(rendezvous, -1);
	}
#endif	/* AF_INET */
	exit(EX_OK);
	/* NOTREACHED */
	return 0;
}

void
docat(file, fd)
	const char *file;
	int fd;
{
	char buf[BUFSIZ];
	int n;
	FILE *fpi = NULL, *fpo = NULL;

	if (fd < 0 && (fpi = fopen(file, "r")) == NULL) {
	  fprintf(stderr, "%s: %s: %s\n", progname, file, strerror(errno));
	  exit(EX_OSFILE);
	  /* NOTREACHED */
	} else if (fd >= 0) {
	  fpi = fdopen(fd, "r");
	  fpo = fdopen(fd, "w");
	}
	if (debug && fpi)
	  while ((n = fread(buf, sizeof buf[0], sizeof buf, fpi)) > 0)
	    fwrite(buf, sizeof buf[0], n, stdout);
	else
	  if (fpi && fpo)
	    report(fpi, fpo);
	if (fpi) fclose(fpi);
	if (fpo) fclose(fpo);
}

/*
 * Determine if the Router is alive, how many entries are in the queue,
 * and whether the router dumped core last time it died.
 */
 
void
checkrouter()
{
	int pid, n, r;
	FILE *fp;
	struct stat pidbuf, corebuf;
	struct dirent *dp;
	DIR *dirp;

	if (postoffice == NULL)
	  return;
	sprintf(path, "%s/%s", postoffice, ROUTERDIR);
	dirp = opendir(path);
	if (dirp == NULL) {
	  fprintf(stderr, "%s: opendir(%s): %s\n",
		  progname, path, strerror(errno));
	  return;
	}
	for (dp = readdir(dirp), n = 0; dp != NULL; dp = readdir(dirp)) {
	  if (isascii(dp->d_name[0]) && isdigit(dp->d_name[0]))
	    ++n;
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
	fprintf(stdout,"%d entr%s in router queue: ", n, n != 1 ? "ies" : "y");

	if (nonlocal)
	  r = -2;
	else
	  r = isalive(PID_ROUTER, &pid, &fp);
	switch (r) {
	case EX_UNAVAILABLE:
	  /* if the .router.pid file is younger than any core file,
	     then the router dumped core... so let'em know about it. */
	  sprintf(path, "%s/%s/core",postoffice,ROUTERDIR);
	  if (fstat(FILENO(fp), &pidbuf) < 0) {
	    fprintf(stderr, "\n%s: fstat: %s", progname, strerror(errno));
	  } else if (stat(path, &corebuf) == 0 && pidbuf.st_mtime < corebuf.st_mtime)
	    fprintf(stdout,"core dumped\n");
	  else
	    fprintf(stdout,"no daemon\n");
	  fclose(fp);
	  break;
	case EX_OK:
	  if (n)
	    fprintf(stdout,"processing\n");
	  else
	    fprintf(stdout,"idle\n");
	  fclose(fp);
	  break;
	case -2:
	  fprintf(stdout,"non-local\n");
	  break;
	default:
	  fprintf(stdout,"never started\n");
	  break;
	}

	sprintf(path, "%s/%s", postoffice, DEFERREDDIR);
	dirp = opendir(path);
	if (dirp == NULL) {
	  fprintf(stderr, "%s: opendir(%s): %s",
		  progname, path, strerror(errno));
	  return;
	}
	for (dp = readdir(dirp), n = 0; dp != NULL; dp = readdir(dirp)) {
	  if (isascii(dp->d_name[0]) && isdigit(dp->d_name[0]))
	    ++n;
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
	if (n)
	  fprintf(stdout,"%d message%s deferred\n", n, n != 1 ? "s" : "");
}

int countfiles __((const char *));
int countfiles(dirpath)
const char *dirpath;
{
	char dpath[512];

	struct dirent *dp;
	DIR *dirp;
	int n = 0;

	dirp = opendir(dirpath);
	if (dirp == NULL) {
	  fprintf(stderr, "%s: opendir(%s): %s\n",
		  progname, dpath, strerror(errno));
	  return -1;
	}
	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
	  if (dp->d_name[0] == '.' &&
	      (dp->d_name[1] == 0 || (dp->d_name[1] == '.' &&
				      dp->d_name[2] == 0)))
	    continue; /* . and .. */
	  if (isascii(dp->d_name[0]) && isdigit(dp->d_name[0]))
	    ++n;
	  else if (strcmp("core",dp->d_name)==0)
	    sawcore = 1, ++othern;
	  else {
	    if (dp->d_name[0] >= 'A' && dp->d_name[0] <= 'Z' &&
		dp->d_name[1] == 0) {
	      struct stat stbuf;
	      sprintf(dpath, "%s/%s", dirpath, dp->d_name);
	      if (lstat(dpath,&stbuf) != 0 ||
		  !S_ISDIR(stbuf.st_mode)) {
		++othern;
	      } else {
		n += countfiles(dpath);
	      }
	    } else {
	      ++othern;
	    }
	  }
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
	return n;
}


void
checkscheduler()
{
	int pid, n, r;
	FILE *fp;

	if (postoffice == NULL)
	  return;

	sawcore = 0;
	othern  = 0;

	sprintf(path, "%s/%s", postoffice, TRANSPORTDIR);

	n = countfiles(path);

	fprintf(stdout,"%d message%s in transport queue: ",
	       n, n != 1 ? "s" : "");

	if (nonlocal)
	  r = -2;
	else
	  r = isalive(PID_SCHEDULER, &pid, &fp);

	switch (r) {
	case EX_UNAVAILABLE:
	  fprintf(stdout,"no scheduler daemon");
	  fclose(fp);
	  break;
	case EX_OK:
	  if (n == 0)
	    fprintf(stdout,"idle");
	  else
	    fprintf(stdout,"working");
	  break;
	case -2:
	  fprintf(stdout,"non-local");
	  break;
	default:
	  fprintf(stdout,"never started");
	  if (n > 0)
	    fprintf(stdout," \"%s/%s\" polluted", postoffice, TRANSPORTDIR);
	  break;
	}
	if (sawcore)
	  fprintf(stdout," (core exists)");
	fprintf(stdout,"\n");

}

int
isalive(pidfil, pidp, fpp)
	const char *pidfil;
	int *pidp;
	FILE **fpp;
{
	if (postoffice == NULL)
		return 0;
	sprintf(path, "%s/%s", postoffice, pidfil);
	
	if ((*fpp = fopen(path, "r")) == NULL) {
	  /* fprintf(stderr, "%s: cannot open %s (%s)\n",
	     progname, path, strerror(errno)); */
	  return EX_OSFILE;
	}
	if (fscanf(*fpp, "%d", pidp) != 1) {
	  fprintf(stderr, "%s: cannot read process id\n", progname);
	  fclose(*fpp);
	  *fpp = NULL;
	  return EX_OSFILE;
	}
	if (kill(*pidp, 0) < 0 && errno == ESRCH)
	  return EX_UNAVAILABLE;
	return EX_OK;
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
  while ((c = fgetc(fp)) != EOF) {
    if (c == '\n')
      break;

    if (!*buf) {
      *bufsize = 0;
      *bufspace = 110;
      *buf = malloc(*bufspace+3);
    }
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
    fprintf(stderr, "%s\n",*buf);

  return 0; /* Got something */
}


#define GETLINE(buf, bufsize, bufspace, fp) _getline(&buf, &bufsize, &bufspace, fp)


const char *names[SIZE_L+2];

#define	L_VERTEX	SIZE_L
#define L_END		SIZE_L+1
struct sptree *spt_ids[SIZE_L+2];

#define	EQNSTR(a,b)	(!strncmp(a,b,strlen(b)))

extern int parse __((FILE *));
int
parse(fp)
	FILE *fp;
{
	register char *cp;
	register struct vertex *v;
	register struct web *w;
	register struct ctlfile *cfp;
	register int	i;
	u_long	list, key;
	struct spblk *spl;
	int bufsize, bufspace;
	char  *buf = NULL, *ocp;

	names[L_CTLFILE] = "Vertices:";
	names[L_HOST]    = "Hosts:";
	names[L_CHANNEL] = "Channels:";
	names[L_END]     = "End:";

	bufsize = 0;
	if (GETLINE(buf,bufsize,bufspace,fp))
	  return 0;

	if (EQNSTR(buf, MAGIC_PREAMBLE) &&
	    EQNSTR(buf+LEN_MAGIC_PREAMBLE, VERSION_ID2))
	  return 2; /* We have version 2 scheduler! */

	if (!(EQNSTR(buf, MAGIC_PREAMBLE)
	      && EQNSTR(buf+LEN_MAGIC_PREAMBLE, VERSION_ID))) {
	  fprintf(stderr, "%s: version mismatch, input is \"%s\".\n", progname, buf);
	  return 0;
	}

	if (schedq) {
	  /* We ignore the classical mailq data, just read it fast */
	  while (1) {
	    bufsize = 0;
	    if (GETLINE(buf, bufsize, bufspace, fp))
	      return 1; /* EOF ? */
	    if (memcmp(buf,"End:",4) == 0)
	      return 1;
	  }
	  /* NOT REACHED */
	}

	bufsize = 0;
	if (GETLINE(buf,bufsize,bufspace,fp))
	  return 0;
	if (!EQNSTR(buf, names[L_CTLFILE]))
	  return 0;
	list = L_CTLFILE;
	spt_ids[L_CTLFILE] = sp_init();
	spt_ids[L_VERTEX ] = sp_init();
	spt_ids[L_CHANNEL] = sp_init();
	spt_ids[L_HOST   ] = sp_init();
	while (1) {

	  bufsize = 0;
	  if (GETLINE(buf, bufsize, bufspace, fp))
	    break;

	  switch ((int)list) {
	  case L_CTLFILE:
	    /* decid:\tfile\tnaddr; off1[,off2,...][\t#message] */
	    if (!isdigit(buf[0])) {
	      if (EQNSTR(buf, names[L_CHANNEL])) {
		list = L_CHANNEL;
		break;
	      }
	      if (EQNSTR(buf, names[L_END])) {
		return 1;
	      }
	    }
	    if (!isdigit(buf[0]) ||
		(cp = strchr(buf, ':')) == NULL) {
	      fprintf(stderr, "%s: %s: orphaned pending recovery\n", progname, buf);
	      break;
	    }
	    *cp++ = '\0';
	    key = atol(buf);
	    while (isascii(*cp) && isspace(*cp))
	      ++cp;
	    ocp = cp;
	    while (isascii(*cp) && !isspace(*cp))
	      ++cp;
	    *cp++ = '\0';
	    spl = sp_lookup(symbol(ocp), spt_ids[L_CTLFILE]);
	    if (spl == NULL || (cfp = (struct ctlfile *)spl->data) == NULL) {
	      cfp = (struct ctlfile *)emalloc(sizeof (struct ctlfile));
	      memset((void*)cfp,0,sizeof(struct ctlfile));
	      cfp->fd = -1;
	      cfp->haderror = 0;
	      cfp->head = NULL;
	      cfp->nlines = 0;
	      cfp->contents = NULL;
	      cfp->logident = NULL;
	      cfp->id = 0;
	      cfp->mid = strsave(ocp);
	      cfp->mark = 0;
	      sp_install(symbol(ocp), (void *)cfp, 0, spt_ids[L_CTLFILE]);
	    }
	    while (*cp == ' ' || *cp == '\t')
	      ++cp;
	    ocp = cp;
	    while ('0' <= *cp && *cp <= '9')
	      ++cp;
	    *cp++ = '\0';
	    if ((i = atoi(ocp)) < 1) {
	      fprintf(stderr, "%s: bad number of addresses: '%s'\n", progname, ocp);
	      break;
	    }
	    v = (struct vertex *)emalloc(sizeof(struct vertex)+((i-1)*sizeof(long)));
	    memset((void*)v,0,sizeof (struct vertex)+(i-1)*sizeof(long));
	    v->ngroup = i;
	    v->cfp = cfp;
	    while (isascii(*cp) && isspace(*cp))
	      ++cp;
	    for (i = 0; isascii(*cp) && isdigit(*cp); ++cp) {
	      ocp = cp;
	      while (isascii(*cp) && isdigit(*cp))
		++cp;
	      *cp = '\0';
	      v->index[i++] = atol(ocp);
	    }
	    while (*cp != '\0' && *cp != '\n' && *cp != '#')
	      ++cp;
	    if (*cp == '#') {
	      ocp = ++cp;
	      while (*cp != '\0' && *cp != '\n')
		++cp;
	      *cp = '\0';
	      v->message = strsave(ocp);
	    } else
	      v->message = NULL;
	    v->next[L_CTLFILE] = cfp->head;
	    if (cfp->head == NULL)
	      cfp->head = v;
	    else
	      cfp->head->prev[L_CTLFILE] = v;
	    v->prev[L_CTLFILE] = NULL;
	    cfp->head = v;
	    v->orig[L_CTLFILE] = v->orig[L_CHANNEL] = v->orig[L_HOST] = NULL;
	    v->next[L_CHANNEL] = v->next[L_HOST] = NULL;
	    v->prev[L_CHANNEL] = v->prev[L_HOST] = NULL;
	    sp_install(key, (void *)v, 0, spt_ids[L_VERTEX]);
	    break;
	  case L_CHANNEL:
	    /* (channel|host):\tdecid[>decid...] */
	    if (EQNSTR(buf, names[L_HOST])) {
	      list = L_HOST;
	      break;
	    }
	    if (EQNSTR(buf, names[L_END])) {
	      return 1;
	    }
	    /* FALL THROUGH */
	  case L_HOST:
	    if (EQNSTR(buf, names[L_END])) {
	      return 1;
	    }
	    cp = buf-1;
	    do {
	      cp = strchr(cp+1, ':');
	    } while (cp != 0 && (*(cp+1) != '\t' || *(cp+2) != '>'));

	    if (cp == NULL) {
	      fprintf(stderr, "%s: %s: orphaned pending recovery\n", progname, buf);
	      break;
	    }
	    *cp++ = '\0';

	    /* Look for channel/host identifier splay-tree */
	    spl = sp_lookup(symbol(buf), spt_ids[list]);
	    if (spl == NULL || (w = (struct web *)spl->data) == NULL) {
	      w = (struct web *)emalloc(sizeof (struct web));
	      memset((void*)w,0,sizeof(struct web));
	      w->name = strsave(buf);
	      w->kids = 0;
	      w->link = w->lastlink = NULL;
	      sp_install(symbol(buf), (void *)w, 0, spt_ids[list]);
	    }
	    while (*cp == ' ' || *cp == '\t')
	      ++cp;

	    /* Pick each vertex reference */

	    ++cp;		/* skip the first '>' */
	    while (*cp != '\0' && isascii(*cp) && isdigit(*cp)) {
	      ocp = cp;
	      while (isascii(*cp) && isdigit(*cp))
		++cp;
	      *cp++ = '\0';
	      spl = sp_lookup((u_long)atol(ocp), spt_ids[L_VERTEX]);
	      if (spl == NULL || (v = (struct vertex *)spl->data)==NULL) {
		fprintf(stderr, "%s: unknown key %s\n", progname, ocp);
	      } else {
		if (w->link)
		  w->link->prev[list] = v;
		else
		  w->lastlink = v;
		v->next[list] = w->link;
		w->link = v;
		if (v->orig[list] == NULL)
		  v->orig[list] = w;
	      }
	    }
	    break;
	default:
	    break;
	  }
	}
	return 1;
}

static int r_i;

extern int repscan __((struct spblk *));
int
repscan(spl)
	struct spblk *spl;
{
	register struct vertex *v, *vv;
	struct web *w;
	int fd, flag = 0;
	struct stat stbuf;
	long filecnt, filesizesum;

	w = (struct web *)spl->data;
	/* assert w != NULL */
	for (vv = w->link; vv != NULL; vv = vv->next[L_CHANNEL]) {
	  if (vv->ngroup == 0)
	    continue;
	  if (!onlyuser)
	    fprintf(stdout,"%s/%s:\n", w->name, vv->orig[L_HOST]->name);
	  else
	    flag = 0;
	  filecnt = 0;
	  filesizesum = 0;
	  for (v = vv; v != NULL; v = v->next[L_HOST]) {
	    if (v->ngroup == 0)
	      continue;
	    if (onlyuser && status < 2) {
	      sprintf(path, "%s/%s/%s", postoffice, TRANSPORTDIR, v->cfp->mid);
	      if ((fd = open(path, O_RDONLY, 0)) < 0) {
		continue;
	      }
	      if (fstat(fd, &stbuf) < 0 || stbuf.st_uid != user) {
		close(fd);
		continue;
	      }
	      close(fd);
	      if (flag == 0)
		fprintf(stdout,"%s/%s:\n", w->name, vv->orig[L_HOST]->name);
	    }
	    if (!summary) {
	      flag = 1;
	      fprintf(stdout,"\t%s", v->cfp->mid);
	      if (v->ngroup > 1)
		fprintf(stdout,"/%d", v->ngroup);
	      fprintf(stdout,":");
	      if (v->message)
		fprintf(stdout,"\t%s\n", v->message);
	      else
		fprintf(stdout,"\n");
	      if (verbose)
		printaddrs(v);
	    } else {
	      verbose = 2;
	      if (summary < 2)
		printaddrs(v);	/* summary does not print a thing! */
	      ++filecnt;	/* however it counts many things.. */
	      if (summary < 2)
		filesizesum += v->cfp->offset[0];
	    }
	    for (r_i = 0; r_i < SIZE_L; ++r_i) {
	      if (v->next[r_i] != NULL)
		v->next[r_i]->prev[r_i] = v->prev[r_i];
	      if (v->prev[r_i] != NULL)
		v->prev[r_i]->next[r_i] = v->next[r_i];
	    }
	    /* if we are verbose, space becomes important */
	    if (v->next[L_CTLFILE] == NULL && v->prev[L_CTLFILE] == NULL) {
	      /* we can free the control file */
	      if (v->cfp->contents != NULL)
		free(v->cfp->contents);
	      free((char *)v->cfp);
	    }
	    /* we can't free v! so mark it instead */
	    v->ngroup = 0;
	  }
	  if (summary == 1 && !onlyuser) {
	    fprintf(stdout,"\t  %d file%s, ", (int)filecnt, filecnt>1 ? "s":"");
	    if (filesizesum == 0)
	      fprintf(stdout,"no file size info available\n");
	    else
	      fprintf(stdout,"%ld bytes total, %d bytes average\n",
		      filesizesum, (int)(filesizesum/filecnt));
	  }
	  if (summary > 1 && !onlyuser) {
	    fprintf(stdout,"\t  %d file%s\n", (int)filecnt, filecnt>1 ? "s":"");
	  }
	}
	return 0;
}

void query2 __((FILE *, FILE*));
void query2(fpi, fpo)
	FILE *fpi, *fpo;
{
	int  len, i;
	int bufsize = 0;
	int bufspace = 0;
	char *challenge = NULL;
	char *buf = NULL;
	MD5_CTX CTX;
	unsigned char digbuf[16];

	/* XX: Authenticate the query - get challenge */
	bufsize = 0;
	if (GETLINE(challenge, bufsize, bufspace, fpi))
	  return;

	MD5Init(&CTX);
	MD5Update(&CTX, challenge, strlen(challenge));
	MD5Update(&CTX, v2password, strlen(v2password));
	MD5Final(digbuf, &CTX);
	
	fprintf(fpo, "AUTH %s ", v2username);
	for (i = 0; i < 16; ++i) fprintf(fpo,"%02x",digbuf[i]);
	fprintf(fpo, "\n");
	if (fflush(fpo) || ferror(fpo)) {
	    perror("login to scheduler command interface failed");
	    return;
	}

	bufsize = 0;
	if (GETLINE(buf, bufsize, bufspace, fpi))
	    return;

	if (*buf != '+') {
	  fprintf(stdout,"User '%s' not accepted to server '%s'; err='%s'\n",
		  v2username, host ? host : "<NO-HOST-?>", buf+1);
	  return;
	}

	if (schedq) {

	  if (schedq > 2)
	    strcpy(buf,"SHOW SNMP\n");
	  else if (schedq > 1)
	    strcpy(buf,"SHOW QUEUE SHORT\n");
	  else
	    strcpy(buf,"SHOW QUEUE THREADS\n");

	  len = strlen(buf);

	  if (fwrite(buf,1,len,fpo) != len || fflush(fpo)) {
	    perror("write to scheduler command interface failed");
	    return;
	  }

	  bufsize = 0;
	  if (GETLINE(buf, bufsize, bufspace, fpi))
	    return;

	  if (*buf != '+') {

	    fprintf(stdout,"Scheduler response: '%s'\n",buf);

	  } else {

	    for (;;) {
	      bufsize = 0;
	      if (GETLINE(buf, bufsize, bufspace, fpi))
		break;
	      if (buf[0] == '.' && buf[1] == 0)
		break;
	      /* Do leading dot duplication suppression */
	      fprintf(stdout,"%s\n",((*buf == '.') ? buf+1 : buf));
	    }

	  }
	} else {
	  fprintf(stdout,"Sorry, scheduler with protocol version 2 can't give results without -Q option\n");
	}
}

void
report(fpi,fpo)
	FILE *fpi, *fpo;
{
	int rc = parse(fpi);
	if (rc == 0)
	  return;
	if (rc == 2) {
	  query2(fpi,fpo);
	  return;
	}
	if (schedq) {
	  /* Old-style processing */
	  int prevc = -1;
	  int linesuppress = 0;
	  while (!ferror(fpi)) {
	    int c = getc(fpi);
	    if (c == EOF)
	      break;
	    if (prevc == '\n') {
	      linesuppress = 0;
	      if (c == ' ' && schedq > 1)
		linesuppress = 1;
	      fflush(stdout);
	    }
	    if (!linesuppress)
	      putc(c,stdout);
	    prevc = c;
	  }
	  fflush(stdout);
	  return;
	}

	r_i = 0;
	sp_scan(repscan, (struct spblk *)NULL, spt_ids[L_CHANNEL]);
	if (!r_i) {
	  if (onlyuser)
	    fprintf(stdout,"No user messages found\n");
	  else
	    if (schedq == 0)
	      fprintf(stdout,"Transport queue is empty -- or scheduler uses -Q -mode\n");
	    else
	      fprintf(stdout,"Transport queue is empty\n");
	}
}

void
printaddrs(v)
	struct vertex *v;
{
	register char *cp;
	int	i, fd;
	struct stat stbuf;
	char *ocp;

	if (v->cfp->contents == NULL) {
	  sprintf(path, "%s/%s/%s", postoffice, TRANSPORTDIR, v->cfp->mid);
	  if ((fd = open(path, O_RDONLY, 0)) < 0) {
#if 0
	    fprintf(stdout,"\t\t%s: %s\n", path, strerror(errno));
#endif
	    return;
	  }
	  if (fstat(fd, &stbuf) < 0) {
	    fprintf(stdout,"\t\tfstat(%s): %s\n", path, strerror(errno));
	    close(fd);
	    return;
	  }
	  v->cfp->contents = malloc((u_int)stbuf.st_size);
	  if (v->cfp->contents == NULL) {
	    fprintf(stdout,"\t\tmalloc(%d): out of memory!\n", (int)stbuf.st_size);
	    close(fd);
	    return;
	  }
	  errno = 0;
	  if (read(fd, v->cfp->contents, stbuf.st_size) < stbuf.st_size){
	    fprintf(stdout,"\t\tread(%d): %s\n", (int)stbuf.st_size,
		   errno == 0 ? "failed" : strerror(errno));
	    close(fd);
	    return;
	  }
	  close(fd);
	  for (cp = v->cfp->contents, i = 0;
	       cp < v->cfp->contents + stbuf.st_size - 1; ++cp) {
	    if (*cp == '\n') {
	      *cp = '\0';
	      if (*++cp == _CF_SENDER)
		break;
	      switch (*cp) {
	      case _CF_LOGIDENT:
		v->cfp->logident = cp + 2;
		break;
	      case _CF_ERRORADDR:
		/* overload cfp->mark to be from addr*/
		v->cfp->mark = cp+2 - v->cfp->contents;
		break;
	      }
	    }
	  }
	  if (verbose > 1 && status < 2) {
	    sprintf(path, "%s/%s/%s", postoffice, QUEUEDIR, v->cfp->mid);
	    if (stat(path, &stbuf) == 0) {
	      /* overload offset[] to be size of message */
	      v->cfp->offset[0] = stbuf.st_size;
	      v->cfp->mtime     = stbuf.st_mtime;
	    } else {
	      v->cfp->offset[0] = 0;
	      v->cfp->mtime     = 0;
	    }
	  }
	}
	if (summary)
	  return;
	if (v->cfp->logident)
	  fprintf(stdout,"\t  id\t%s", v->cfp->logident);
	if (verbose > 1 && v->cfp->offset[0] > 0) {
	  long dt = now - v->cfp->mtime;
	  int fields = 3;
	  fprintf(stdout,", %ld bytes, age ", (long)v->cfp->offset[0]);
	  /* age (now-mtime) printout */
	  if (dt > (24*3600)) {	/* Days */
	    fprintf(stdout,"%dd", (int)(dt /(24*3600)));
	    dt %= (24*3600);
	    --fields;
	  }
	  if (dt > 3600) {
	    fprintf(stdout,"%dh",(int)(dt/3600));
	    dt %= 3600;
	    --fields;
	  }
	  if (dt > 60 && fields > 0) {
	    fprintf(stdout,"%dm",(int)(dt/60));
	    dt %= 60;
	    --fields;
	  }
	  if (fields > 0) {
	    fprintf(stdout,"%ds",(int)dt);
	  }
	}
	fprintf(stdout,"\n");
	if (v->cfp->mark > 0)
	  fprintf(stdout,"\t  from\t%s\n", v->cfp->contents + v->cfp->mark);
	for (i = 0; i < v->ngroup; ++i) {
	  cp = v->cfp->contents + v->index[i] + 2;
	  if (*cp == ' ' || (*cp >= '0' && *cp <= '9'))
	    cp += _CFTAG_RCPTPIDSIZE;
	  while (isascii(*cp) && !isspace(*cp))
	    ++cp;
	  while (isascii(*cp) && isspace(*cp))
	    ++cp;
	  while (isascii(*cp) && !isspace(*cp))
	    ++cp;
	  while (isascii(*cp) && isspace(*cp))
	    ++cp;
	  ocp = cp;
	  while (*cp != '\0' && *cp != '\n')
	    ++cp;
	  if (*cp-- == '\n') {
	    while (isascii(*cp) && !isspace(*cp))
	      --cp;
	    while (isascii(*cp) && isspace(*cp))
	      --cp;
	    if (cp >= ocp)
	      *++cp = '\0';
	    else {
	      cp = ocp;
	      while (*cp != '\0' && *cp != '\n')
		++cp;
	      *cp = '\0';
	    }
	  }
	  fprintf(stdout,"\t");
	  if (i == 0)
	    fprintf(stdout,"  to");
	  fprintf(stdout,"\t%s",ocp);
	}
}
