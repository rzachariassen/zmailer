/* Formatter for user's mailbox path */

/* Public domain; written by Eugene G. Crosser <crosser@average.org> */

/*
   this is developed for Zmailer (http://www.zmailer.org/) but do not
   inlcude Zmailer's headers so the same file may be used with other
   products (notably IMAP/POP servers)
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define STDC_HEADERS   /* assume we are in sane environment... */
#endif

#include <sys/types.h>
#ifdef STDC_HEADERS
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif
#include <pwd.h>
#ifdef TEST
#include <stdio.h>
#include <errno.h>
#endif

#ifdef __STDC__
#define __(x) x
#else
#define __(x) /* */
#endif

#define DEFAULTDOMAIN "defaultdomain"

/********
int fmtmbox (char *buf, int size, const char *format,
            const char *userid, const struct passwd *pwd);

format specifiers:

%% - '%' alone
%a - address as is
%u - userid
%U - long user name (userid if not supported)
%d - first element of domain name
%D - full domain name
%x - next character derived from PJW hash of userid
%X - next character derived from crc32 hash of userid
%h - userid's home directory
%n - least number guaranteening unique filename (for MH style boxes) *UNIMPL*
%N - the same padded by leading zeroes to fixed length *UNIMPL*
%(any other character) - substitute with "_bad_%_subst_"

Examples:
"/var/mail/%u"                  - standard mail directory
"/var/mail/%x/%x/%u             - hashed directory
"%h/Mail/INBOX"                 - mailbox in user's home
"/var/virtual/%D/mail/%X/%X/%u" - hashed spool with virtual domain
********/

extern int pjwhash32 __((const char *));
extern int crc32 __((const char *));

static int put_c __((char **, char *, char));
static int put_c(q,ebuf,c)
char **q;
char *ebuf;
char c;
{
	if (*q >= ebuf) return 1;
	*((*q)++)=(c);
	return 0;
}

static int put_s __((char **, char *, char *));
static int put_s(q,ebuf,s)
char **q;
char *ebuf;
char *s;
{
	char c;

	for (c=*s;c;c=*(++s)) {
		if (*q >= ebuf) return 1;
		*((*q)++)=c;
	}
	return 0;
}

int fmtmbox __((char *, int, const char *, const char *, const struct passwd *));
int fmtmbox (buf, size, format, address, pwd)
char *buf;
int size;
const char *format;
const char *address;
const struct passwd *pwd;
{
	char *p,*q,*at,*dom,*dot;
	char c;
	enum {norm,percentseen} state;
	int overflow=0;
	int phash=0, chash=0;
	char *ebuf=buf+size;

	if ((at=strrchr(address,'@'))) {
		*at='\0';
		dom=at+1;
	} else dom=DEFAULTDOMAIN;

	state=norm;
	p=format;
	q=buf;
	for (c=*p;c;c=*(++p)) switch (state) {
	case norm:
		if (c == '%') state=percentseen;
		else overflow |= put_c(&q,ebuf,*p);
		break;
	case percentseen:
		switch (c) {
		case '%':
			overflow |= put_c(&q,ebuf,*p);
			break;
		case 'a':
			overflow |= put_s(&q,ebuf,address);
			if (at) {
				overflow |= put_c(&q,ebuf,'@');
				overflow |= put_s(&q,ebuf,dom);
			}
			break;
		case 'u':
			overflow |= put_s(&q,ebuf,pwd->pw_name);
			break;
		case 'U':
			overflow |= put_s(&q,ebuf,pwd->pw_gecos);
			break;
		case 'd':
			if ((dot=strchr(dom,'.'))) *dot='\0';
			overflow |= put_s(&q,ebuf,dom);
			if (dot) *dot='.';
			break;
		case 'D':
			overflow |= put_s(&q,ebuf,dom);
			break;
		case 'x':
			if (!phash) phash=pjwhash32(pwd->pw_name);
			overflow |= put_c(&q, ebuf, 'A' + (phash % 26));
			phash /= 26;
			break;
		case 'X':
			if (!chash) chash=crc32(pwd->pw_name);
			overflow |= put_c(&q, ebuf, 'A' + (chash % 26));
			chash /= 26;
			break;
		case 'h':
			overflow |= put_s(&q,ebuf,pwd->pw_dir);
			break;
		case 'n':
			overflow |= put_s(&q,ebuf,"_%n_unimpl_");
			break;
		case 'N':
			overflow |= put_s(&q,ebuf,"_%N_unimpl_");
			break;
		default:
			overflow |= put_s(&q,ebuf,"_bad_%_subst_");
			break;
		}
		state=norm;
		break;
	}
	*q='\0';
	if (at) *at='@';
	return overflow;
}

#ifdef TEST
int main(argc, argv)
int argc;
char *argv[];
{
	struct passwd *pwd;
	char buf[1024];
	int rc;

	if (argc < 3) {
		fprintf(stderr,"usage: fmtmbox format user\n");
		exit(1);
	}

	if ((pwd=getpwnam(argv[2])) == NULL) {
		if (errno) perror("getpwnam");
		else fprintf(stderr,"no such user\n");
		exit(1);
	}

	rc=fmtmbox(buf,sizeof(buf),argv[1],argv[2],pwd);
	printf("rc=%d, result=\"%s\"\n",rc,buf);
	return 0;
}
#endif
