/*
 *  Hashtest -- a small utility to test how  CRC32() and PJWHASH32()
 *  functions work with real-world user input.
 *
 *  Part of ZMailer -- test which mailbox hash function is best for you.
 *
 *  This should show to you, that 'hashtest -XX' produces best two-
 *  level subdirectory hash with max 676 sub-buckets, and likely all
 *  bucket abundances are within 20-30 % of each other.
 *
 *  My test material (189438 userids from several systems pulled together)
 *  did show that  pjwhash32() suffers from some odd thing which always
 *  looses two low bits, and thus produces only 169 different hash buckets,
 *  while crc32() produces all 676 buckets.
 *
 *  Old "Pick two first letters of the username for subdir" approach
 *  produced 565 buckets, but the distribution was absolutely terribly
 *  scewed - 20 top-abundant buckets had over 50% of all hits.
 *  The 5 top-abundant buckets all had more than 7000 hits.
 *
 *  Runtime comparisons show that:
 *     -PP:  0.598 sec user space
 *     -XX:  0.592 sec user space
 *     -DD:  0.443 sec user space
 *
 *  from which we can probably safely say that  crc32() and pjwhash32()
 *  are absolutely equal in execution time, and likely present only
 *  0.150 seconds of the test runtime.  ( Or 790 nanoseconds per user
 *  name -- yeah, Alpha rules ;) Guestimate says each hash took some
 *  680 instruction cycles -- HOT caches! )
 *
 *  Matti Aarnio <mea@nic.funet.fi> 9-Sep-1999
 *
 */


#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

extern long pjwhash32 (const void *);
extern long crc32     (const void *);

static void
usage()
{
      printf("hashtest -({P|D|X}+) < usernamefile\n");
      exit(64);
}


int main(argc, argv)
     int argc;
     char *argv[];
{
  int c;
  int pjwhashes = 0, dirhashes = 0, crchashes = 0;
  char buf[2000];

  while ((c = getopt(argc, argv, "?PDX")) != EOF) {
    switch (c) {
    case 'P':
      ++pjwhashes;
      break;
    case 'D':
      ++dirhashes;
      break;
    case 'X':
      ++crchashes;
      break;
    default:
      usage();
    }
  }
  if (!pjwhashes && !dirhashes && !crchashes)
    usage();


  while (!feof(stdin) && !ferror(stdin)) {

    char *s;
    int hash, i;

    if (fgets(buf, sizeof(buf), stdin) == NULL)
      break;
    s = strchr(buf,'\n');
    if (s) *s = 0;
    hash = 0;
    if (dirhashes) {

      s = buf;
      for (i = 0; i < dirhashes; ++i,++s)
	putc(*s, stdout);

    } else if (pjwhashes) {

      hash = pjwhash32(buf);
      for (i = 0; i < pjwhashes; ++i) {
	putc('A' + (hash % 26), stdout);
	hash /= 26;
      }

    } else { /* CRChashes */

      hash = crc32(buf);
      for (i = 0; i < crchashes; ++i) {
	putc('A' + (hash % 26), stdout);
	hash /= 26;
      }

    }
    printf("\n");
  }

  return 0;
}
