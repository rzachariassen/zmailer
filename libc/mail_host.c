/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Support routine for the mail submission interface.  This file gets linked
 * in if the application doesn't define its own mail_host() routine.
 */

char *
mail_host()
{
	static char hostname[128];
	extern int getmyhostname();

	if (getmyhostname(hostname, sizeof hostname) < 0)
		return "unknown";
	return hostname;
}
