#include <stdio.h>

extern int fd_statfs (int, long *,long *,long *,long *);

int main(argc, argv)
int argc;
char *argv[];
{
    FILE *fp;
    long bavail, bused, iavail, iused;
    int rc;

    if (argc != 2) {
      usage:
	printf("fdstatfs-test: required parameter missing: path to some readable file\n");
	exit(64);
    }
    fp = fopen(argv[1], "r");
    if (!fp)
	goto usage;

    rc = fd_statfs(fileno(fp), &bavail, &bused, &iavail, &iused);
    printf("result: free %9ld  %9ld\n", bavail, iavail);
    printf("result: used %9ld  %9ld\n", bused,  iused);

    return 0;
}
