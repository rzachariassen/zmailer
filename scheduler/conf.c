/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1996
 */

/* stdout and stderr end up in qlogdir/progname when scheduler is a daemon */
const char * qlogdir = "/usr/spool/log"; /* overridden by LOGDIR zenvariable */

/* suffix of scheduler configuration file, i.e. MAILSHARE/progname.qcf_suffix */
const char * qcf_suffix = "conf";

/* default directory for transport agent commands, as in MAILBIN/qdefaultdir */
/* This value is duplicated in several Makefiles in the distribution */
const char * qdefaultdir = "ta";

/* output file for queue status command */
const char * qoutputfile = "/usr/tmp/.mailq.text";

/* command parameter that is replaced with a host name */
const char * replhost = "$host";

/* command parameter that is replaced with a channel name */
const char * replchannel = "$channel";

/* unprivileged user id */
int	nobody = -2;

/* directory scanning interval in seconds */
int	sweepinterval = 10;

/* At most 30 new childs per second -- The 'R'-option can be used to increase this */
int	forkrate_limit = 30;

/* Set to what you want RET=xxx default to be when no RET is given. 0="HDRS" */
int	default_full_content = 1;

/* If we use ZMailer malloc library in debug mode, BAD-PTR looks like
   following value.. */
void *BADPTR = (void*) (unsigned long)0x5555555555555555L;

/* Push reports regarding recipients out this often, unless
   parametrized to do differently */
int global_report_interval = 900; /* 15min */
