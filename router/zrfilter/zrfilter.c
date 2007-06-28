/****************************************************************************/

/*
 * "zrfilter" tool.
 *
 * Version: 1.0.1
 *
 * Written by Daniel Kiper.
 *
 * E-mail: dkiper@netspace.com.pl
 *
 * DONE:
 *   - 07/02/2006 - version 1.0.0 - first release,
 *   - 13/07/2006 - version 1.0.1 - removed small bug
 *		    from do_nonblock() function.
 *
 * TODO:
 *   - ???
 */

/****************************************************************************/

#define _GNU_SOURCE

#include "mailer.h"
#include "libc.h"
#include "libz.h"
#include "mail.h"
#include "vis.h"
#include "zsyslog.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

/****************************************************************************/

#define BUFF_SIZE	PIPE_BUF

#define EXIT_SIGNAL	60
#define EXIT_FATAL	61

#define ZROPENLOG	openlog(progname, LOG_PID, LOG_MAIL)
#define ZRCLOSELOG	closelog()

/****************************************************************************/

#ifndef HAVE_SIGHANDLER_T
typedef void (*sighandler_t)(int);
#endif

/****************************************************************************/

const char *VersionNumb = "1.0.1";
const char *progname = "zrfilter";
int D_alloc = 0, D_assign = 0, D_compare = 0, D_functions = 0;
int D_matched = 0, D_regnarrate = 0, funclevel = 0;
conscell **return_valuep;
struct sptree *spt_eheaders, *spt_headers;

/****************************************************************************/

static char file[MAXPATHLEN + 1];
static int opt_l = 0, opt_q = 0, opt_v = 0;
static int pstd[3][2] = {{-1, -1}, {-1, -1}, {-1, -1}};
static FILE *fp = NULL;
static pid_t pid = 0;

/****************************************************************************/

extern void init_header(void);
extern struct headerinfo *find_header(struct sptree *hdb, const char *name);

/****************************************************************************/

static void parent(char *const argv[]);
static void child(char *const argv[]);

static int std_copy(int std, fd_set *fds);
static int cpin(void);
static int cpoe(int std);

static int set_signals(sighandler_t handler);
static void cleanup(int sig);

static void usage(int status);

#ifdef __STDC__
static void do_log(Sfio_t *output, const char *format, ...);
#else
static void do_log(va_dcl va_alist);
#endif

static int do_pipe(int filedes[2]);
static void do_dup2(int std);
static int do_nonblock(int fd);
static int do_fd_set(int fd, fd_set *fds, int nfds);
static int do_close(int *fd);
static int do_fclose(void);
static pid_t do_waitpid(pid_t pid, int *status, int options);
static void do_exit(int status);

/****************************************************************************/

int main(argc, argv)
	int argc;
	char *const argv[];
{
	const char *opt_e = NULL, *opt_m = NULL;
	char cwd[MAXPATHLEN + 1];
	register int i;
	int c, m, n;
	struct headerinfo *hlp;

	zopterr = 0;

	while ((c = zgetopt(argc, argv, "e:hlm:qv")) != EOF)
		switch (c) {
			case 'e':
				opt_e = zoptarg;
				break;
			case 'h':
				usage(EXIT_SUCCESS);
			case 'l':
				opt_l = 1;
				break;
			case 'm':
				opt_m = zoptarg;
				break;
			case 'q':
				opt_q = 1;
				break;
			case 'v':
				opt_v = 1;
				break;
			default:
				fprintf(stderr, "Unknown option: %c\n", zoptopt);
				usage(EXIT_FATAL);
		}

	if (opt_e == NULL || opt_m == NULL)
		usage(EXIT_FATAL);

	((const char **)argv)[--zoptind] = opt_e;

	ZROPENLOG;

	if (set_signals(cleanup) == -1)
		do_exit(EXIT_FATAL);

#ifdef HAVE_GETCWD
	if (getcwd(cwd, MAXPATHLEN) == NULL) {
#else
	if (getwd(cwd) == NULL) {
#endif
		do_log(sfstderr, "Can't get current working directory !!!\n  Error: %s\n",
		       strerror(errno));
		do_log(NULL, "Can't get current working directory. Error: %s",
		       strerror(errno));
		exit(EXIT_FATAL);
	}

	snprintf(file, MAXPATHLEN, "%s/%s", cwd, opt_m);

	if ((fp = fopen(file, "r")) == NULL) {
		do_log(sfstderr, "Can't open file !!!\n  File: %s\n  Error: %s\n",
		       file, strerror(errno));
		do_log(NULL, "Can't open file: %s Error: %s", file, strerror(errno));
		exit(EXIT_FATAL);
	}

	stickymem = MEM_TEMP;
	initzline(BUFF_SIZE);
	init_header();

	do_log(NULL, "Parsing E-mail: %s", file);

	while ((m = n = zgetline(fp)) > 0) {
		if (n == 1 && *zlinebuf == '\n') {
			repos_zgetline(fp, zlineoffset(fp) - 1);
			break;
		}
		if (n > 1 && zlinebuf[n - 2] == '\r' && zlinebuf[n - 1] == '\n') {
			zlinebuf[--n - 1] = '\n';
			if (n <= 1) {
				repos_zgetline(fp, zlineoffset(fp) - n);
				break;
			}
		}
		if ((i = hdr_status(zlinebuf, zlinebuf, n, 0)) > 0) {
			repos_zgetline(fp, zlineoffset(fp) - m);
			break;
		}
		if (i < 0 &&
		    (hlp = find_header(spt_eheaders, strnsave(zlinebuf, -i))) != NULL &&
		    hlp->class == eEnvEnd) {
			repos_zgetline(fp, zlineoffset(fp));
			break;
		}
	}

	tfree(MEM_TEMP);

	if (set_signals(SIG_IGN) == -1 || do_pipe(pstd[STDIN_FILENO]) == -1
	    || do_pipe(pstd[STDOUT_FILENO]) == -1
	    || do_pipe(pstd[STDERR_FILENO]) == -1)
		do_exit(EXIT_FATAL);

	if ((pid = fork()) == -1) {
		do_log(sfstderr, "Can't fork !!!\n  Error: %s\n", strerror(errno));
		do_log(NULL, "Can't fork. Error: %s", strerror(errno));
		do_exit(EXIT_FATAL);
	}

	if (pid)
		parent(&argv[zoptind]);
	else
		child(&argv[zoptind]);
}

/****************************************************************************/

static void parent(argv)
	char *const argv[];
{
	int cstatus, nfds, pstatus = 0;
	fd_set rfds, wfds;
	pid_t cpid = 0;

	do_log(NULL, "Feeding filter... Command: %..*s PID: %d", ' ', argv, pid);

	if (set_signals(cleanup) == -1 || do_close(&pstd[STDIN_FILENO][0]) == -1
	    || do_close(&pstd[STDOUT_FILENO][1]) == -1
	    || do_close(&pstd[STDERR_FILENO][1]) == -1)
		pstatus = EXIT_FATAL;

	if (do_nonblock(pstd[STDIN_FILENO][1]) == -1
	    || do_nonblock(pstd[STDOUT_FILENO][0]) == -1
	    || do_nonblock(pstd[STDERR_FILENO][0]) == -1)
		pstatus = EXIT_FATAL;

	while (!pstatus && !cpid) {
		if ((cpid = do_waitpid(pid, &cstatus, WNOHANG)) == -1)
			do_exit(EXIT_FATAL);
		nfds = 0;
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		nfds = do_fd_set(pstd[STDIN_FILENO][1], &wfds, nfds);
		nfds = do_fd_set(pstd[STDOUT_FILENO][0], &rfds, nfds);
		nfds = do_fd_set(pstd[STDERR_FILENO][0], &rfds, nfds);
		if (select(++nfds, &rfds, &wfds, NULL, NULL) == -1) {
			do_log(sfstderr, "\"select\" function failed !!!\n  Error: %s\n",
			       strerror(errno));
			do_log(NULL, "\"select\" function failed. Error: %s", strerror(errno));
			pstatus = EXIT_FATAL;
			break;
		}
		if (std_copy(STDIN_FILENO, &wfds) == -1
		    || std_copy(STDOUT_FILENO, &rfds) == -1
		    || std_copy(STDERR_FILENO, &rfds) == -1)
			pstatus = EXIT_FATAL;
	}

	if (do_close(&pstd[STDIN_FILENO][1]) == -1)
		pstatus = EXIT_FATAL;
	if (do_close(&pstd[STDOUT_FILENO][0]) == -1)
		pstatus = EXIT_FATAL;
	if (do_close(&pstd[STDERR_FILENO][0]) == -1)
		pstatus = EXIT_FATAL;

	if (!cpid && do_waitpid(pid, &cstatus, 0) == -1)
		do_exit(pstatus);

	pid = 0;

	if (WIFSIGNALED(cstatus)) {
		do_log(sfstderr, "Child process terminated by signal !!!\n  Signal: %d\n",
		       WTERMSIG(cstatus));
		do_log(NULL, "Child process terminated by signal: %d", WTERMSIG(cstatus));
		do_exit(pstatus ? pstatus : EXIT_FATAL);
	}

	if (WIFEXITED(cstatus)) {
		if (!pstatus && WEXITSTATUS(cstatus) != EXIT_FATAL)
			do_log(NULL, "Done...");
		do_exit(pstatus ? pstatus : WEXITSTATUS(cstatus));
	}

	do_log(sfstderr, "Child process terminated by ... ???\n");
	do_log(NULL, "Child process terminated by ... ???");
	do_exit(EXIT_FATAL);
}

/****************************************************************************/

static void child(argv)
	char *const argv[];
{
	ZROPENLOG;
	if (set_signals(SIG_DFL) == -1 || do_fclose() == EOF)
		do_exit(EXIT_FATAL);
	do_dup2(STDIN_FILENO);
	do_dup2(STDOUT_FILENO);
	do_dup2(STDERR_FILENO);
	v_envinit();
	ZRCLOSELOG;
	execvp(*argv, argv);
	ZROPENLOG;
	do_log(sfstderr, "Can't exec !!!\n  File: %s\n  Error: %s\n",
	       *argv, strerror(errno));
	do_log(NULL, "Can't exec: %s Error: %s", *argv, strerror(errno));
	ZRCLOSELOG;
	exit(EXIT_FATAL);
}

/****************************************************************************/

static int std_copy(std, fds)
	int std;
	fd_set *fds;
{
	int fd;

	fd = std == STDIN_FILENO ? pstd[STDIN_FILENO][1] : pstd[std][0];
	if (fd == -1 || !FD_ISSET(fd, fds))
		return 0;
	return std == STDIN_FILENO ? cpin() : cpoe(std);
}

/****************************************************************************/

static int cpin()
{
	static char buff[BUFF_SIZE];
	static size_t br = 0;

	if (!br) {
		if (feof(fp)) {
			if (do_fclose() == EOF
			    || do_close(&pstd[STDIN_FILENO][1]) == -1)
				return -1;
			return 0;
		}
		br = fread(buff, sizeof(char), BUFF_SIZE, fp);
		if (ferror(fp)) {
			do_log(sfstderr, "Can't read file !!!\n  File: %s\n  Error: %s\n",
			       file, strerror(errno));
			do_log(NULL, "Can't read file: %s Error: %s", file, strerror(errno));
			return -1;
		}
	}
	if (br) {
		if (write(pstd[STDIN_FILENO][1], buff, br) == -1) {
			if (errno == EAGAIN)
				return 0;
			do_log(sfstderr, "Can't write to a pipe !!!\n  Error: %s\n",
			       strerror(errno));
			do_log(NULL, "Can't write to a pipe. Error: %s", strerror(errno));
			return -1;
		}
		br = 0;
	}
	return 0;
}

/****************************************************************************/

static int cpoe(std)
	int std;
{
	static char buff[2][BUFF_SIZE], vbuff[2][BUFF_SIZE * 4 + 1];
	const char *stdname[] = {"stdout", "stderr"};
	Sfio_t *stdoe[] = {sfstdout, sfstderr};
	static ssize_t br[] = {0, 0};

	if (!br[std - 1]) {
		if ((br[std - 1] = read(pstd[std][0], buff[std - 1], BUFF_SIZE)) == -1) {
			br[std - 1] = 0;
			if (errno == EAGAIN)
				return 0;
			do_log(sfstderr, "Can't read pipe !!!\n  Error: %s\n",
			       strerror(errno));
			do_log(NULL, "Can't read pipe. Error: %s", strerror(errno));
			return -1;
		}
		if (opt_v)
			br[std - 1] = strvisx(vbuff[std - 1], buff[std - 1],
					      br[std - 1], VIS_OCTAL | VIS_GLOB | VIS_WHITE);
	}
	if (br[std - 1]) {
		if (opt_v)
			sfwrite(stdoe[std - 1], vbuff[std - 1], br[std - 1]);
		else
			sfwrite(stdoe[std - 1], buff[std - 1], br[std - 1]);
		if (sferror(stdoe[std - 1])) {
			do_log(sfstderr, "Can't write to %s !!!\n  Error: %s\n",
			       stdname[std - 1], strerror(errno));
			do_log(NULL, "Can't write to %s. Error: %s",
			       stdname[std - 1], strerror(errno));
			return -1;
		}
		br[std - 1] = 0;
	}
	return 0;
}

/****************************************************************************/

static int set_signals(handler)
	sighandler_t handler;
{
	int i, signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM}, status = 0;

	for (i = 0; i < sizeof(signals) / sizeof(int); ++i)
		if (signal(signals[i], handler) == SIG_ERR) {
			do_log(sfstderr, "\"signal\" function failed !!!\n  Error: %s\n",
			       strerror(errno));
			do_log(NULL, "\"signal\" function failed. Error: %s", strerror(errno));
			status = -1;
		}
	return status;
}

/****************************************************************************/

static void cleanup(sig)
	int sig;
{
	const char *sig_name;

	switch (sig) {
		case SIGHUP:
			sig_name = "SIGHUP";
			break;
		case SIGINT:
			sig_name = "SIGINT";
			break;
		case SIGQUIT:
			sig_name = "SIGQUIT";
			break;
		case SIGPIPE:
			sig_name = "SIGPIPE";
			break;
		case SIGTERM:
			sig_name = "SIGTERM";
			break;
		default:
			sig_name = "UNKNOWN";
	}

	do_log(sfstderr, "\"%s\" signal received !!!\nExiting...\n", sig_name);
	do_log(NULL, "\"%s\" signal received. Exiting...", sig_name);

	while (waitpid(-1, NULL, WNOHANG) > 0);

	if (pid && !kill(pid, SIGTERM)) {
		sleep(3);
		while (waitpid(-1, NULL, WNOHANG) > 0);
		kill(pid, SIGKILL);
		while (waitpid(-1, NULL, WNOHANG) > 0);
	}

	do_exit(EXIT_SIGNAL);
}

/****************************************************************************/

static void usage(status)
	int status;
{
	fprintf(stderr, "\n%s Ver. %s\n\n"
		"Usage: %s [<option> [<option> [...]]]\n\n"
		"Options:\n"
		"  -e <exec> - specify filter program (required),\n"
		"  -h - display this help,\n"
		"  -l - log messages to syslog,\n"
		"  -m <file> - specify E-mail file (required),\n"
		"  -q - be quiet,\n"
		"  -v - visually encode special characters,\n"
		"  -- - all arguments given after that one will be\n"
		"       passed unmodified to the filter program.\n\n",
		progname, VersionNumb, progname);
	exit(status);
}

/****************************************************************************/

#ifdef __STDC__
static void do_log(Sfio_t *output, const char *format, ...)
{
#else
static void do_log(va_alist)
	va_dcl va_alist;
{
	const char *format;
	Sfio_t *output;
#endif
	char buff[BUFF_SIZE + 1];
	va_list ap;

#ifdef __STDC__
	va_start(ap, format);
#else
	va_start(ap);
	output = va_arg(ap, Sfio_t *);
	format = va_arg(ap, const char *);
#endif

	if (output == NULL) {
		if (opt_l && sfvsprintf(buff, BUFF_SIZE, format, ap) != -1)
			syslog(LOG_MAIL | LOG_INFO, buff);
	} else
		if (!opt_q)
			sfvprintf(output, format, ap);

	va_end(ap);
}

/****************************************************************************/

static int do_pipe(filedes)
	int filedes[2];
{
	int status;

	if ((status = pipe(filedes)) == -1) {
		do_log(sfstderr, "Can't create pipe !!!\n  Error: %s\n",
		       strerror(errno));
		do_log(NULL, "Can't create pipe. Error: %s", strerror(errno));
	}
	return status;
}

/****************************************************************************/

static void do_dup2(std)
	int std;
{
	int *fd;

	fd = std == STDIN_FILENO ? &pstd[STDIN_FILENO][0] : &pstd[std][1];
	if (dup2(*fd, std) == -1) {
		do_log(sfstderr, "Can't duplicate a file descriptor !!!\n  Error: %s\n",
		       strerror(errno));
		do_log(NULL, "Can't duplicate a file descriptor. Error: %s",
		       strerror(errno));
		do_exit(EXIT_FATAL);
	}
	if (do_close(fd) == -1)
		do_exit(EXIT_FATAL);
	fd = std == STDIN_FILENO ? &pstd[STDIN_FILENO][1] : &pstd[std][0];
	if (do_close(fd) == -1)
		do_exit(EXIT_FATAL);
}

/****************************************************************************/

static int do_nonblock(fd)
	int fd;
{
	int status;

	if ((status = fcntl(fd, F_GETFL)) == -1) {
		do_log(sfstderr, "Can't get a file descriptor's flag !!!\n  Error: %s\n",
		       strerror(errno));
		do_log(NULL, "Can't get a file descriptor's flag. Error: %s",
		       strerror(errno));
		return -1;
	}
	if ((status = fcntl(fd, F_SETFL, status | O_NONBLOCK)) == -1) {
		do_log(sfstderr, "Can't set a file descriptor's flag !!!\n  Error: %s\n",
		       strerror(errno));
		do_log(NULL, "Can't set a file descriptor's flag. Error: %s",
		       strerror(errno));
	}
	return status;
}

/****************************************************************************/

static int do_fd_set(fd, fds, nfds)
	int fd;
	fd_set *fds;
	int nfds;
{
	if (fd == -1)
		return nfds;
	FD_SET(fd, fds);
	if (nfds > fd) return nfds;
	return fd;
}

/****************************************************************************/

static int do_close(fd)
	int *fd;
{
	int status;

	if (fd == NULL || *fd == -1)
		return 0;
	if ((status = close(*fd)) == -1) {
		do_log(sfstderr, "Can't close a file descriptor !!!\n  Error: %s\n",
		       strerror(errno));
		do_log(NULL, "Can't close a file descriptor. Error: %s",
		       strerror(errno));
	}
	*fd = -1;
	return status;
}

/****************************************************************************/

static int do_fclose()
{
	int status;

	if (fp == NULL)
		return 0;
	if ((status = fclose(fp)) == EOF) {
		do_log(sfstderr, "Can't close file !!!\n  File: %s\n  Error: %s\n",
		       file, strerror(errno));
		do_log(NULL, "Can't close file: %s Error: %s", file, strerror(errno));
	}
	fp = NULL;
	return status;
}

/****************************************************************************/

static pid_t do_waitpid(pid, status, options)
	pid_t pid;
	int *status;
	int options;
{
	pid_t cpid;

	if ((cpid = waitpid(pid, status, options)) == -1) {
		do_log(sfstderr, "\"waitpid\" function failed !!!\n  Error: %s\n",
		       strerror(errno));
		do_log(NULL, "\"waitpid\" function failed. Error: %s", strerror(errno));
	}
	return cpid;
}

/****************************************************************************/

static void do_exit(status)
	int status;
{
	int i;

	if (set_signals(SIG_IGN) == -1 && !status)
		status = EXIT_FATAL;
	if (do_fclose() == EOF && !status)
		status = EXIT_FATAL;
	for (i = 0; i <= 2; ++i) {
		if (do_close(&pstd[i][0]) == -1 && !status)
			status = EXIT_FATAL;
		if (do_close(&pstd[i][1]) == -1 && !status)
			status = EXIT_FATAL;
	}
	ZRCLOSELOG;
	exit(status);
}

/****************************************************************************/
