#include <ctype.h>

char *strupper(s)
char *s;
{
	char *cp;
	for (cp = s; *cp != '\0'; ++cp) {
	  int c = (*cp) & 0xFF;
	  if (isascii(c) && islower(c))
	    *cp = toupper(c);
	}
	return s;
}
