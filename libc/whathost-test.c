#include <stdio.h>

extern char *whathost();

int main(argc,argv)
     int argc;
     char *argv[];
{
	char *what;
	int i;

	if (argc != 2) {
	  fprintf(stderr,"whathost-test: missing param: name of a file somewhere\n");
	  exit(64); /* EX_USAGE */
	}

	for (i=0; i < 20; ++i) {
	  what = whathost(argv[1]);
	  printf("argv[1] = '%s'  what = '%s'\n", argv[1], what ? what : "<NULL>");
	}

	return 0;
}
