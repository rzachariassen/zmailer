#include <stdio.h>
#include <strings.h>

#ifndef BITNETNAMEFILE
#define BITNETNAMEFILE	"/usr/local/lib/urep/BITNETNAME"
#endif

char *bitnetnamefiles[] = {	"/etc/name.bitnet", BITNETNAMEFILE, NULL };

#ifdef MAIN
main()
{
	char Myname[100];
	bitnetname(Myname);
	printf("%s\n", Myname);
}
#endif

bitnetname(name)
char *name;
{
	char *s, bitnetname[20];
	FILE *bitnetf;
	int i;
	extern char *strchr();

	s = NULL;
	bitnetf = NULL;
	for (i = 0; bitnetnamefiles[i] != NULL; ++i) {
		if ((bitnetf = fopen(bitnetnamefiles[i], "r")) != NULL)
			break;
	}
	if (bitnetf != NULL) {
		if (fgets(bitnetname, sizeof bitnetname, bitnetf) == NULL) {
			fclose(bitnetf);
			printf("no name found\n");
			return NULL;
		}
		fclose(bitnetf);
		bitnetname[sizeof bitnetname - 1] = '\0';
	} else {
		printf("no bitnet name file found\n");
		return NULL;
	}
	if ((s = strchr(bitnetname, '\n')) != NULL)
		*s = '\0';
	(void) strcpy(name, bitnetname);
}
