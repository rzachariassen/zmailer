/*
 *  contentpolicy.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 1998
 *
 *  This is the ugly one, we run SENSOR program on each
 *  accepted message -- if 
 *
 */

#include "smtpserver.h"

#define _POLICYTEST_INTERNAL_
#include "policytest.h"

int
contentpolicy(rel, state, fname)
struct policytest *rel;
struct policystate *state;
const char *fname;
{
  return 0; /* Until we have implementation */
}
