/* To clear some doubts about signal handling with GNU autoconfig,
   we test a couple things -- exiting, and signal-deaths */

#include <stdio.h>

extern int wait();
extern int fork();

main()
{
  int status;
  int pid;
  pid = fork();
  if (pid == 0) {
    /* Child */
    exit (63);
  }
  pid = wait(&status);
  printf("exit(63) did yield status: 0x%x\n",status);
  fflush(stdout);

  pid = fork();
  if (pid == 0) {
    char *pp = NULL;
    *pp = 0; /* SIGSEGV.. */
  }
  pid = wait(&status);
  printf("SIGSEGV did yield status: 0x%x\n",status);

  return 0;
}
