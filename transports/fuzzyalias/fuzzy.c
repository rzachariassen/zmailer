#include "hostenv.h"

#include <stdio.h>
#include <string.h>
#include <pwd.h>

#include "db.h"
#include "fuzzy.h"


void
free_namelist ( nl )
NAMELIST	*nl;
{
	NAMELIST	*ptr;

	while (nl != NULL) {
		ptr = nl->next;
		if (nl->name != NULL) free(nl->name);
		free(nl);
		nl = ptr;
	}
}

NAMELIST *
fuzzy ( alias, thresh, pw, old_dbm, files )
char	*alias;
int	thresh, pw, old_dbm;
char	*files[];
{
	int		max, match;
	NAMELIST	*answer, *ptr;

	answer = NULL;
	max = 0;

	/*
	 *  Scan passwd file for user names
	 */
	if (pw) {
		struct passwd	*pw;

		while ( (pw = getpwent()) != NULL ) {
			match = simil(alias, pw->pw_name);
			if (match <= thresh)
				continue;

			if (match == max) {
				for (ptr=answer; ptr!=NULL; ptr=ptr->next) {
					if (strcmp(ptr->name, pw->pw_name) == 0)
						break;
				}
				if (ptr != NULL)
					continue;

				ptr = (NAMELIST *) malloc(sizeof(NAMELIST));
				if (ptr == NULL) {
					fprintf(stderr, "Not enough memory!\n");
					exit(1);
				}
				ptr->name = strdup(pw->pw_name);
				ptr->next = answer;
				answer = ptr;
			}
			else if (match > max) {
				max = match;
				if (answer != NULL) free_namelist(answer);
				answer = (NAMELIST *) malloc(sizeof(NAMELIST));
				answer->name = strdup(pw->pw_name);
				answer->next = NULL;
			}
		}

		endpwent();
	}

	/*
	 *  Scan {,n}dbm data bases for user names
	 */
	for (; *files != NULL; *++files) {
		datum		key;

		if (open_db(*files, old_dbm) == 0)
			continue;

		for (key=first_key(); key.dptr!=NULL; key=next_key()) {
			match = simil(alias, key.dptr);
			if (match <= thresh)
				continue;

			if (match == max) {
				for (ptr=answer; ptr!=NULL; ptr=ptr->next) {
					if (strcmp(ptr->name, key.dptr) == 0)
						break;
				}
				if (ptr != NULL)
					continue;

				ptr = (NAMELIST *) malloc(sizeof(NAMELIST));
				if (ptr == NULL) {
					fprintf(stderr, "Not enough memory!\n");
					exit(1);
				}
				ptr->name = strdup(key.dptr);
				ptr->next = answer;
				answer = ptr;
			}
			else if (match > max) {
				max = match;
				if (answer != NULL) free_namelist(answer);
				answer = (NAMELIST *) malloc(sizeof(NAMELIST));
				answer->name = strdup(key.dptr);
				answer->next = NULL;
			}
		}

		close_db();
	}

	if (max == 0) {
		if (answer != NULL) free_namelist(answer);
		answer = NULL;
	}

	return (answer);
}
