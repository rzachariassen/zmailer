#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>

main(argc, argv)
	char **argv;
{
	char *p, s[10];
	int o;

	setbuf(stdout, 0);
	while (gets(s)) {
		o = 0;
		for (p = s; *p; p++) switch (*p) {
		case 's': o |= LOCK_SH; break;
		case 'e': o |= LOCK_EX; break;
		case 'n': o |= LOCK_NB; break;
		case 'u': o |= LOCK_UN; break;
		}
		printf("nfslock %s %x", argv[1], o);
		if (nfslock(argv[1], o) < 0)
			perror("lock"), exit(1);
		printf(" ok\n");
	}
}
