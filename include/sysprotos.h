/* This file depends on  config.h  having been included -- see hostenv.h */

#include <sys/types.h>

#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif

#include <stdio.h>

#ifdef STDC_HEADERS
#  include <stdlib.h>
#  include <stddef.h>
#  include <string.h>
#  include <unistd.h>
#  include <sys/types.h>
#ifdef HAVE_SYS_FCNTL_H
#  include <sys/fcntl.h>
#endif
#else
/* extern char *malloc ();
   extern char *realloc (); */
#endif

#ifdef USE_SYSPROTOS__xx

extern void _exit();
extern void abort();
extern int abs();
extern int accept();
extern int access();
extern unsigned int alarm();
extern int atoi();
extern long atol();
extern void bcopy();
extern int bind();
extern void bzero();
extern int chdir();
extern int chown();
extern int close();
extern int connect();
extern char *ctime();
extern int dup();
extern int dup2();
extern int execl();
extern int execv();
extern int execve();
extern int execvp();
extern void exit();
extern int fchmod();
extern int fchown();
extern int fclose();
extern int fcntl();
extern int fflush();
extern int flock();
extern int fork();
extern int fprintf();
extern int fputc();
extern int fputs();
extern FREAD_TYPE fread();
extern void free();
extern int fscanf();
extern int fseek();
extern int fstat();
extern int ftruncate();
extern FWRITE_TYPE fwrite();
extern int getdtablesize();
extern char *getenv();
extern GETEUID_TYPE geteuid();
extern int gethostname();
extern char *getlogin();
extern int getopt();
extern int getpeername();
extern int getpid();
extern int getppid();
extern int gettimeofday();
extern GETUID_TYPE getuid();
extern unsigned long inet_addr();
extern int ioctl();
extern int isatty();
extern int kill();
extern int link();
extern int listen();
extern long lseek();
extern int lstat();
#ifdef	__STDC__
extern void *malloc();
#else
extern char *malloc();
#endif
extern int mkdir();
extern int mknod();
extern char *mktemp();
extern int open();
extern int openlog();
extern int pause();
extern void perror();
extern int pipe();
extern int printf();
extern int puts();
extern void qsort();
extern int read();
extern int rename();
extern void rewind();
extern int rmdir();
extern int select();
extern int sendto();
extern int setgid();
extern void setgrent();
extern int setpgrp();
extern SETPWENT_TYPE setpwent();
extern int setreuid();
extern int setrlimit();
extern int setsockopt();
extern int setuid();
extern int setvbuf();
extern int sigvec();
extern unsigned int sleep();
extern int socket();
extern SPRINTF_TYPE sprintf();
extern int sscanf();
extern int stat();
extern char *strcat();
extern char *strchr();
extern int strcmp();
extern char *strcpy();
extern STRLEN_TYPE strlen();
extern char *strncat();
extern int strncmp();
extern char *strncpy();
extern char *strrchr();
extern time_t time();
extern TIMES_TYPE times();
extern UMASK_TYPE umask();
extern int unlink();
extern int utime();
extern int utimes();
extern int vfprintf();
extern SPRINTF_TYPE vsprintf();
extern int wait();
extern int wait3();
extern int write();
extern int ungetc();
#endif /* USE_SYSPROTOS */

#ifdef DEBUG_FOPEN
#if defined(FILE) /* <stdio.h> is included.. */ || defined(EOF)
	/* OSF/1 has the STDIO's "FILE" as a Typedef!  Not as a Macro! */

#define fopen(path,rw) __fopen(path,rw)
#define freopen(path,rw,fp) __freopen(path,rw,fp)
#define fdopen(fd,rw) __fdopen(fd,rw)
#define fclose(fp) __fclose(fp)

extern FILE *__fopen();
extern FILE *__freopen();
extern FILE *__fdopen();
extern int   __fclose();
#endif /* FILE defined */
#endif /* DEBUG_FOPEN defined */
