/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "zmalloc.h"
#define	STATIC static

/* configurable language-independent stuff */
#define	MAILCHECK_INTERVAL	600	/* 10 minute mail check interval */
#define	MAILPATH_MSG_SEPARATOR	'%'	/* MAILPATH=/foo%message:/bar */
#define	CHARSETSIZE		256	/* 8-bit ASCII/EBCDIC */
#define	DEFAULT_OPEN_MASK	0644	/* 3rd parameter to open() */
#define	MAXNFILE		128	/* max # file descriptors dealt with */
#define	MAXNPROC		128	/* max # outstanding child processes */
#define	ENVIRONMENT		":env"	/* magic name for environment */
#define	MAXNSCOPES		32	/* max # of scopes (optimizer limit) */
#define	MAXNCOMMANDS		32	/* max # nested command descriptors */
#define	DEFAULT_PS1		"$ "
#define	DEFAULT_PS2		"> "
#define	DEFAULT_ROOT_PS1	"# "
#define	DEFAULT_IFS		" \t\n"
#define	DEFAULT_PATH		"/usr/ucb:/bin:/usr/bin:"
#define	LOGIN_SCRIPT "\
if [ -f /etc/profile ]; then\n\
	. /etc/profile;\n\
fi;\n\
if [ -f $HOME/.profile ]; then\n\
	. $HOME/.profile;\n\
fi\n"

/* standard variables */
#define	CDPATH			"CDPATH"
#define	HOME			"HOME"
#define	IFS			"IFS"
#define	MAIL			"MAIL"
#define	MAILPATH		"MAILPATH"
#define	MAILCHECK		"MAILCHECK"
#define	OPTARG			"OPTARG"
#define	OPTIND			"OPTIND"
#define	PATH			"PATH"
#define	PS1			"PS1"
#define	PS2			"PS2"

/* messages */

/* mail.c */
#define	YOU_HAVE_MAIL		"you have mail"
#define	ILLEGAL_MAILCHECK_VALUE	"illegal MAILCHECK value"
/* trap.c */
#define	BAD_TRAP		"bad trap"
/* test.c */
#define	TEST_SYNTAX_ERROR	"syntax error at"
/* builtins.c */
#define	USAGE_RETURN		"Usage: %s [ # | (...) ]\n"
#define	NO_HOME_DIRECTORY	"no home directory"
#define	USAGE_CD		"Usage: %s [ directory ]\n"
#define	NO_HASHING_INFORMATION	"no hashing information\n"
#define	USAGE_READ		"Usage: %s [ variable ... ]\n"
#define	USAGE_INCLUDE		"Usage: %s script\n"
#define	NOT_FOUND		"not found"
#define	USAGE_BCE		"Usage: %s [ # ]\n"
#define	NEGATIVE_VALUE		"negative value"
#define	EXPORT			"export"
#define	USAGE_GETOPTS		"Usage: %s optstring name [ arguments ... ]\n"
#define	USAGE_SHIFT		"Usage: %s [ # ]\n"
#define	USAGE_UMASK		"Usage: %s [ #o ]\n"
#define	BAD_OPTIONS		"bad option(s)"
#define	USAGE_UNSET		"Usage: %s [ variable ... ]\n"
#define	CANNOT_UNSET		"cannot unset"
#define	CORE_DUMPED		" - core dumped"
#define	USAGE_WAIT		"Usage: %s [ pid ]\n"
#define	USAGE_TIMES		"Usage: %s\n"
#define	USAGE_SLEEP		"Usage: %s #seconds\n"
#define	NULL_NAME		"null name\n"
#define	IS_A_SHELL_BUILTIN	"is a shell builtin"
#define	IS_A_SHELL_FUNCTION	"is a shell function"
#define	IS			"is"
#define USAGE_EXPR		"Usage: %s str ':' REGEXPR\n"
/* execute.c */
#define	CANNOT_FORK		"cannot fork"
#define	EXISTS_BUT_NOT_FIFO	"exists but is not a fifo"
#define	CANNOT_MKNOD		"cannot mknod"
#define	CANNOT_OPEN		"cannot open"
#define	PIPE			"pipe"
/* sh.c */
#define	USAGE	"Usage: %s [ -isaefhkntuvx[CGILMOPRSY] ] [ -c command ] [ argument ... ]\n"
