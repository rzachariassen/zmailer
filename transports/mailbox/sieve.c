/*
 *  Hooks to do user-/system-specified SIEVE filtering
 *
 *  Part of ZMailer by Matti Aarnio <mea@nic.funet.fi> 1998
 *
 */

#include "hostenv.h"
#include "sieve.h"



#define SIEVE_STATE_END   0
#define SIEVE_STATE_START 1

int sieve_start(svp)
     struct sieve *svp;
{
  svp->state = SIEVE_STATE_START;
  return 0;
}

void sieve_iterate(svp)
     struct sieve *svp;
{
  svp->state = SIEVE_STATE_END;
}

void sieve_end(svp)
     struct sieve *svp;
{
}

int sieve_command(svp)
     struct sieve *svp;
{
  /* Rather dummy tools for now.. */
  return SIEVE_NOOP;
}

