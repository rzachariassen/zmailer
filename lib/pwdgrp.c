/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * We implement getpwnam(), getpwuid(), and getgrnam() using the primitive
 * iteration functions (*ent()), in order to avoid constant allocations and
 * frees of fgets() buffers when the normal *nam() routines clean up after
 * finding what they're looking for.  This will lose if we're using a database
 * with slow iteration, but that can be handled elsewhere.
 */

#include "hostenv.h"
#ifdef	USE_ZGETPWNAM
#include <stdio.h>
#include <pwd.h>
#include <grp.h>

struct passwd *
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

struct passwd *
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

struct group *
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
#endif	/* !USE_GETPWNAM */
