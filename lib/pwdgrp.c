/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */


#include "mailer.h"

#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#if 0 /* Once upon a time ... */

/*
 * We implement getpwnam(), getpwuid(), and getgrnam() using the primitive
 * iteration functions (*ent()), in order to avoid constant allocations and
 * frees of fgets() buffers when the normal *nam() routines clean up after
 * finding what they're looking for.  This will lose if we're using a database
 * with slow iteration, but that can be handled elsewhere.
 */

struct Zpasswd *
zgetpwnam(name)
	char *name;
{
	struct passwd *pw;
	extern struct passwd *getpwent();

	setpwent();
	while ((pw = getpwent()) != NULL) {
		errno = 0;
		if (strcmp(name, pw->pw_name) == 0)
			return pw;
	}
	return NULL;
}

struct Zpasswd *
zgetpwuid(uid)
	int uid;
{
	struct passwd *pw;
	extern struct passwd *getpwent();

	setpwent();
	while ((pw = getpwent()) != NULL)
		if (uid == pw->pw_uid)
			return pw;
	return NULL;
}

struct Zgroup *
zgetgrnam(name)
	char *name;
{
	struct group *gr;
	extern struct group *getgrent();

	setgrent();
	while ((gr = getgrent()) != NULL)
		if (strcmp(name, gr->gr_name) == 0)
			return gr;
	return NULL;
}
#endif /* ... once upona time ... */

extern struct passwd *getpwnam();
extern struct passwd *getpwuid();

struct Zpasswd *
zgetpwnam(name)
	char *name;
{
	struct passwd *pw;
	static struct Zpasswd zpw;

	errno = 0;

	pw = getpwnam(name);

	if (pw) {
	  memset(&zpw, 0, sizeof(zpw));
	  zpw.pw_name   = pw->pw_name;
	  zpw.pw_passwd = pw->pw_passwd;
	  zpw.pw_uid    = pw->pw_uid;
	  zpw.pw_gid    = pw->pw_gid;
	  zpw.pw_gecos	= pw->pw_gecos;
	  zpw.pw_dir	= pw->pw_dir;
	  zpw.pw_shell	= pw->pw_shell;

	  return &zpw;
	}

	switch (errno) {
	case ENOENT:
#ifdef __osf__
	case EINVAL:
#endif
	  errno = 0;
	  break;
	default:
	  break;
	}
	return NULL;
}

struct Zpasswd *
zgetpwuid(uid)
	int uid;
{
	struct passwd *pw;
	static struct Zpasswd zpw;

	errno = 0;

	pw = getpwuid(uid);

	if (pw) {
	  memset(&zpw, 0, sizeof(zpw));
	  zpw.pw_name   = pw->pw_name;
	  zpw.pw_passwd = pw->pw_passwd;
	  zpw.pw_uid    = pw->pw_uid;
	  zpw.pw_gid    = pw->pw_gid;
	  zpw.pw_gecos	= pw->pw_gecos;
	  zpw.pw_dir	= pw->pw_dir;
	  zpw.pw_shell	= pw->pw_shell;

	  return &zpw;
	}

	switch (errno) {
	case ENOENT:
#ifdef __osf__
	case EINVAL:
#endif
	  errno = 0;
	  break;
	default:
	  break;
	}
	return NULL;
}

struct Zgroup *
zgetgrnam(name)
	char *name;
{
	struct group *gr;
	static struct Zgroup zgr;

	errno = 0;

	gr = getgrnam(name);

	if (gr) {

	  memset(&zgr, 0, sizeof(zgr));

	  zgr.gr_name   = gr->gr_name;
	  zgr.gr_passwd = gr->gr_passwd;
	  zgr.gr_gid    = gr->gr_gid;
	  zgr.gr_mem    = gr->gr_mem; /* FIXME: This is wrong way to COPY
					 the thing, we really should copy
					 the array of pointers, AND the
					 buffer.. */
	  return &zgr;
	}

	switch (errno) {
	case ENOENT:
#ifdef __osf__
	case EINVAL:
#endif
	  errno = 0;
	  break;
	default:
	  break;
	}
	return NULL;
}
