#include <stdio.h>


/* Shell-GLOB-style matching */
static int globmatch(pattern, string)
	register const char	*pattern;
	register const char	*string;
{
	while (1) {
	  switch (*pattern) {
	  case '{':
	    {
	      const char *p = pattern+1;
	      const char *s = string;

	      /* This matches at the END of the pattern:  '*.{fii,foo,faa}' */

	      for ( ; *p != 0 && *p != '}'; ++p) {
		if (*p == ',') {
		  if (*s == '\0')
		    return 1; /* We have MATCH! */
		  s = string;
		  continue;
		}
		if (*s != *p) {
		  /* Not the same .. */
		  s = string;
		  /* Ok, perhaps next pattern segment ? */
		  while (*p != '\0' && *p != '}' && *p != ',')
		    ++p;
		  if (*p != ',')
		    return 0; /* No next pattern ?
				 We definitely have no match! */
		  continue;
		}
		if (*s != 0)
		  ++s;
	      }
	      if (*p == '\0' || *p == '}')
		if (*s == 0)
		  return 1;
	      return 0;
	    }
	    break;
	  case '*':
	    ++pattern;
	    if (*pattern == 0) {
	      /* pattern ended with '*', we can accept any string trail.. */
	      return 1;
	    }
	    /* We do 'common case' optimization here, but will loose some
	       performance, if somebody gives '*foo*' as a pattern.. */
	    {
	      const char *p = pattern;
	      int i = 0, c;
	      while ((c = *p++) != 0) {
		/* Scan for special chars in pattern.. */
		if (c == '*' || c == '[' || c == '{' || c == '\\' || c == '?') {
		  i = 1; /* Found! */
		  break;
		}
	      }
	      if (!i) { /* No specials, match from end of string */
		int len = strlen(string);
		i = strlen(pattern);
		if (i > len) return 0; /* Tough.. pattern longer than string */
		if (strcmp(string +(len-i),pattern) == 0)
		  return 1; /* MATCH! */
	      }
	    }
	    do {
	      if (globmatch(pattern, string))
		return 1;
	    } while (*string++ != '\0');
	    return 0;
	  case '\\':
	    ++pattern;
	    if (*pattern == 0 ||
		*pattern != *string)
	      return 0;
	    break;
	  case '[':
	    if (*string == '\0')
	      return 0;
	    if (*(pattern+1) == '^') {
	      ++pattern;
	      while ((*++pattern != ']')
		     && (*pattern != *string))
		if (*pattern == '\0')
		  return 0;
	      if (*pattern != ']')
		return 0;
	      string++;
	      break;
	    }
	    while ((*++pattern != ']') && (*pattern != *string))
	      if (*pattern == '\0')
		return 0;
	    if (*pattern == ']')
	      return 0;
	    while (*pattern++ != ']')
	      if (*pattern == '\0')
		return 0;
	    string++;
	    break;
	  case '?':
	    ++pattern;
	    if (*string++ == '\0')
	      return 0;
	    break;
	  case '\0':
	    return (*string == '\0');
	  default:
	    if (*pattern++ != *string++)
	      return 0;
	  }
	}
}

int main(argc,argv)
char *argv[];
int argc;
{
  if (argc != 3) {
    printf("globtest: pattern string\n");
    return 64;
  }
  return globmatch(argv[1],argv[2]);
}

