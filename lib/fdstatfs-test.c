#include <stdio.h>

extern long free_fd_statfs();
extern long used_fd_statfs();

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

    st = free_fd_statfs(fileno(fp));
    printf("result: free %ld\n", st);

    st = used_fd_statfs(fileno(fp));
    printf("result: used %ld\n", st);

    return 0;
}
