#include <stdio.h>

extern long fd_statfs();

int main(argc, argv)
int argc;
char *argv[];
{
    FILE *fp;
    long st;

    if (argc != 2) {
      usage:
	printf("fdstatfs-test: required parameter missing: path to some readable file\n");
	exit(64);
    }
    fp = fopen(argv[1], "r");
    if (!fp)
	goto usage;

    st = fd_statfs(fileno(fp));

    printf("result: %ld\n", st);

    return 0;
}
