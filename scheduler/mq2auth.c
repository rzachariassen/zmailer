/*
 *	ZMailer 2.99.53+ Scheduler "mailq2" routines
 *
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1999
 *
 */

#include "scheduler.h"
#include "prototypes.h"
#include <ctype.h>
#include <unistd.h>
#include "zsyslog.h"
/* #include <stdlib.h> */
#include <errno.h>

#include "ta.h"

/*
 *  MAILQv2 autentication database info content:
 *
 *  - username (search key)
 *  - cleartext password (for AUTH hash to work)
 *  - controlling attributes
 *
 *
 *  Field separator classical double-colon, meaning that
 *  the cleartext password shall *not* contain that character.
 */



void mq2auth(mq,str)
     struct mailq *mq;
     char *str;
{
  char *p = str;

  while (*p && (*p != ' ') && (*p != '\t')) ++p;
  if (*p) *p++ = '\000';
  while (*p == ' ' || *p == '\t') ++p;

  /* Now 'str' points to username, and from 'p' onwards
     there is the HEX-encoded MD5 authenticator.. */




  mq2_puts(mq, "-MAILQ2 AUTH lacking...\n");
}
