#include <ctype.h>

char *strlower(s)
char *s;
{
	char *cp;
	for (cp = s; *cp != '\0'; ++cp) {
	  int c = (*cp) & 0xFF;
	  if (isascii(c) && isupper(c))
	    *cp = tolower(c);
	}
	return s;
}
