/* code fragment used at  mq2.c  and at  mailq.c */

/*
 * NOTE:  HERE ARE INLINED SPECIAL COMMENTS THAT ARE USED WHEN
 *        GENERATING  mailq-m(5)  MAN-PAGE, AND (IN FUTURE) RELEVANT
 *        PART OF THE ZMAILER MANUAL
 *
 */

#define M  (*MIBMtaEntry)

/*<VAR><HEAD>SHM segment header</HEAD><DESC>
Basic SHM segment identifier, and references.
</DESC></VAR>*/


  sfprintf(fp,"ZMailer SHM segment dump; Magic=0x%08X\n", M.magic);
/*<VAR><NAME>SHM segment Magic</NAME><DESC>
Magic value used to ensure that active segment,
and programs have matching view of the world.
</DESC></VAR>*/
  sfprintf(fp,"Time_now                        %10lu\n",
	 (unsigned long)time(NULL));
/*<VAR><NAME>Time_now</NAME><DESC>
Lookup program prints local time(2) value in decimal.
</DESC></VAR>*/
  sfprintf(fp,"Block_creation_time             %10lu\n",
	 (unsigned long)M.BlockCreationTimestamp);
/*<VAR><NAME>Block_creation_time</NAME><DESC>
When this current shared memory object was created.

Do note that it may well be from before last system boot,
as this is backed on mmap(2)ed file.
</DESC></VAR>*/

#ifdef HAVE_GETLOADAVG
{
  double loadavg[3];
  int rc = getloadavg(loadavg, 3);
  if (rc > 0)
    sfprintf(fp,"SYS.Load-Avg-1-min-G                %6.2f\n",
	     loadavg[0]);
/*<VAR><NAME>SYS.Load_Avg-1-min-G</NAME><DESC>
At systems with  getloadavg(3) API, shows 1 minute load-average
as a fixed point fractional number.
</DESC></VAR>*/
  if (rc > 1)
    sfprintf(fp,"SYS.Load-Avg-5-min-G                %6.2f\n",
	     loadavg[1]);
/*<VAR><NAME>SYS.Load_Avg-5-min-G</NAME><DESC>
At systems with  getloadavg(3) API, shows 5 minute load-average
as a fixed point fractional number.
</DESC></VAR>*/
}
#endif

#ifdef SCHEDULER_MAILQ_EXTRA
SCHEDULER_MAILQ_EXTRA
#endif

  sfprintf(fp,"\n");


/*<VAR><HEAD>SYS.*</HEAD><DESC>
Various top-level things, e.g. process group leader PIDs et.al.
</DESC></VAR>*/


#define PIDTEST(varname, var2)  \
  i = (M.varname != 0 &&				\
       (kill(M.varname, 0) < 0 && errno == ESRCH));	\

#define PIDTEST1(varname)  \
  i = (M.varname != 0 &&				\
       (kill(M.varname, 0) < 0 && errno == ESRCH));	\
  if (i && r) M.varname = i = 0;

  PIDTEST(sys.RouterMasterPID, sys.RouterMasterStartTime)
  sfprintf(fp,"SYS.RouterMasterPID             %10u",
	   (u_int) M.sys.RouterMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SYS.RouterMasterPID</NAME><DESC>
Process-id of Router processes group leader, which is also
the queue manager of the router subsystem.
</DESC></VAR>*/
  sfprintf(fp,"SYS.RouterMasterStartTime       %10lu\n",
	   (unsigned long)M.sys.RouterMasterStartTime);
/*<VAR><NAME>SYS.RouterMasterStartTime</NAME><DESC>
When the Router process group leader was started.
</DESC></VAR>*/
  sfprintf(fp,"SYS.RouterMasterStarts          %10u\n",
	   M.sys.RouterMasterStarts);
/*<VAR><NAME>SYS.RouterMasterStarts</NAME><DESC>
How many times the Router process group leader has been started
in the lifetime of this shared memory block.
</DESC></VAR>*/


  PIDTEST(sys.SchedulerMasterPID, sys.SchedulerMasterStartTime)
  sfprintf(fp,"SYS.SchedulerMasterPID          %10u",
	   (u_int) M.sys.SchedulerMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SYS.SchedulerMasterPID</NAME><DESC>
Process-id of Scheduler processes group leader, which is also
the queue manager of the router subsystem.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SchedulerMasterStartTime    %10lu\n",
	   (unsigned long)M.sys.SchedulerMasterStartTime);
/*<VAR><NAME>SYS.SchedulerMasterStartTime</NAME><DESC>
When the Scheduler process group leader was started.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SchedulerMasterStarts       %10u\n",
	   M.sys.SchedulerMasterStarts);
/*<VAR><NAME>SYS.SchedulerMasterStarts</NAME><DESC>
How many times the Scheduler process group leader has been started
in the lifetime of this shared memory block.
</DESC></VAR>*/

  PIDTEST(ts.pid, ts.pid)
  sfprintf(fp,"SC.SchedulerTimeserverPID       %10u",
	   M.ts.pid);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SC.SchedulerTimeserverPID</NAME><DESC>
Separate fork of the Scheduler, which maintains a shared variable
with local time in 1 second resolution.

Originally this was created, when system profiling did show, how
absolutely apalling amounts of time(2) syscalls the scheduler does.
</DESC></VAR>*/
  sfprintf(fp,"SC.SchedulerTimeserverTime      %10lu\n",
	   (unsigned long)
#ifdef HAVE_SELECT
	   M.ts.tv.tv_sec
#else
	   M.ts.time_sec
#endif
	   );
/*<VAR><NAME>SC.SchedulerTimeserverTime</NAME><DESC>
Scheduler's timeserver's idea of present time.
If this disagrees with "time now" above, something is seriously wrong
(when the scheduler does not run, this isn't running either, of course.)
</DESC></VAR>*/

  sfprintf(fp,"SC.SchedulerTimeserverStarts    %10u\n",
	   M.sc.schedulerTimeserverStarts);
/*<VAR><NAME>SC.SchedulerTimeserverStarts</NAME><DESC>
How many times the Scheduler's Timeserver has been started.

This should match with SYS.SchedulerMasterStarts count.
</DESC></VAR>*/

  sfprintf(fp,"SC.SchedulerTimeserverStartTime %10u\n",
	   M.sc.schedulerTimeserverStartTime);
/*<VAR><NAME>SC.SchedulerTimeserverStartTime</NAME><DESC>
When the Scheduler's Timeserver was started last time.

This should match with  SYS.SchedulerMasterStartTime.
</DESC></VAR>*/

  PIDTEST(sys.SmtpServerMasterPID, sys.SmtpServerMasterStartTime)
  sfprintf(fp,"SYS.SmtpServerMasterPID         %10u",
	   (u_int) M.sys.SmtpServerMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SYS.SmtpServerMasterPID</NAME><DESC>
PID of SMTP-server's master instance.
This process does listen(2) on defined inbound sockets,
and forks actual receiver instances.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SmtpServerMasterStartTime   %10lu\n",
	   (unsigned long)M.sys.SmtpServerMasterStartTime);
/*<VAR><NAME>SYS.SmtpServerMasterStartTime</NAME><DESC>
When the SMTP-server's master instance was started the lattest time.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SmtpServerMasterStarts      %10u\n",
	   M.sys.SmtpServerMasterStarts);
/*<VAR><NAME>SYS.SmtpServerMasterStarts</NAME><DESC>
How many times the SMTP-server's master instance has been started
during the existence of this SHM segment.
</DESC></VAR>*/


  PIDTEST1(ss.SubsysRateTrackerPID)
  sfprintf(fp,"SS.SubsysRateTrackerPID         %10u",
	   (u_int) M.ss.SubsysRateTrackerPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SS.SubsysRateTrackerPID</NAME><DESC>
Process-id of smtpserver's realtime incoming message rate tracker.
</DESC></VAR>*/

  PIDTEST1(ss.SubsysRouterMasterPID)
  sfprintf(fp,"SS.SubsysRouterMasterPID        %10u",
	   (u_int) M.ss.SubsysRouterMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SS.SubsysRouterMasterPID</NAME><DESC>
Process-id of smtpserver's interactive router processes group leader.
</DESC></VAR>*/

  PIDTEST1(ss.SubsysContentfilterMasterPID)
  sfprintf(fp,"SS.SubsysContentfilterMasterPID %10u",
	   (u_int) M.ss.SubsysContentfilterMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SS.SubsysContentfilterMasterPID</NAME><DESC>
Process-id of smtpserver's contentfilter subserver process group leader.
</DESC></VAR>*/

  sfprintf(fp,"SS.Irouter-reply-delay-G         %9d\n",
	   M.ss.Irouter_reply_delay_G);
/*<VAR><NAME>SS.Irouter-reply-delay-G</NAME><DESC>
Delay (in secs) of lattest interactive router reply from arrival of
the question.
</DESC></VAR>*/
  sfprintf(fp,"SS.Irouter-queue-G               %9d\n",
	   M.ss.Irouter_queue_G);
/*<VAR><NAME>SS.Irouter-queue-G</NAME><DESC>
Number of requests in smtpserver's i-router interface queue.
</DESC></VAR>*/

  sfprintf(fp,"SS.Cfilter-reply-delay-G         %9d\n",
	   M.ss.Cfilter_reply_delay_G);
/*<VAR><NAME>SS.Irouter-reply-delay-G</NAME><DESC>
Delay (in secs) of lattest interactive router reply from arrival of
the question.
</DESC></VAR>*/
  sfprintf(fp,"SS.Cfilter-queue-G               %9d\n",
	   M.ss.Cfilter_queue_G);
/*<VAR><NAME>SS.Irouter-queue-G</NAME><DESC>
Number of requests in the smtpserver's content-filter interface queue.
</DESC></VAR>*/

  sfprintf(fp,"SYS.SpoolFreeSpace-kB-G          %9d\n",
	   M.sys.SpoolFreeSpace);
/*<VAR><NAME>SYS.SpoolFreeSpace-kB-G</NAME><DESC>
Amount of free POSTOFFICE filesystem space in the system in kilobytes.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SpoolUsedSpace-kB-G          %9d\n",
	   M.sys.SpoolUsedSpace);
/*<VAR><NAME>SYS.SpoolUsedSpace-kB-G</NAME><DESC>
Amount of used POSTOFFICE filesystem space in the system in kilobytes.
</DESC></VAR>*/

  sfprintf(fp,"SYS.SpoolFreeFiles-G             %9d\n",
	   M.sys.SpoolFreeFiles);
/*<VAR><NAME>SYS.SpoolFreeFiles-G</NAME><DESC>
Amount of free POSTOFFICE filesystem i-node space in the system.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SpoolUsedFiles-G             %9d\n",
	   M.sys.SpoolUsedFiles);
/*<VAR><NAME>SYS.SpoolUsedFiles-G</NAME><DESC>
Amount of used POSTOFFICE filesystem i-node space in the system.
</DESC></VAR>*/


  sfprintf(fp,"SYS.TportSpoolFreeSpace-kB-G     %9d\n",
	   M.sys.TportSpoolFreeSpace);
/*<VAR><NAME>SYS.TportSpoolFreeSpace-kB-G</NAME><DESC>
Amount of free POSTOFFICE Tport filesystem space in the system in kilobytes.
</DESC></VAR>*/
  sfprintf(fp,"SYS.TportSpoolUsedSpace-kB-G     %9d\n",
	   M.sys.TportSpoolUsedSpace);
/*<VAR><NAME>SYS.TportSpoolUsedSpace-kB-G</NAME><DESC>
Amount of used POSTOFFICE Tport filesystem space in the system in kilobytes.
</DESC></VAR>*/

  sfprintf(fp,"SYS.TportSpoolFreeFiles-G        %9d\n",
	   M.sys.TportSpoolFreeFiles);
/*<VAR><NAME>SYS.TportSpoolFreeFiles-G</NAME><DESC>
Amount of free POSTOFFICE Tport filesystem i-node space in the system.
</DESC></VAR>*/
  sfprintf(fp,"SYS.TportSpoolUsedFiles-G        %9d\n",
	   M.sys.TportSpoolUsedFiles);
/*<VAR><NAME>SYS.TportSpoolUsedFiles-G</NAME><DESC>
Amount of used POSTOFFICE Tport filesystem i-node space in the system.
</DESC></VAR>*/


  sfprintf(fp,"SYS.LogFreeSpace-kB-G            %9d\n",
	   M.sys.LogFreeSpace);
/*<VAR><NAME>SYS.LogFreeSpace-kB-G</NAME><DESC>
Amount of free LOGDIR filesystem space in the system in kilobytes.
</DESC></VAR>*/
  sfprintf(fp,"SYS.LogUsedSpace-kB-G            %9d\n",
	   M.sys.LogUsedSpace);
/*<VAR><NAME>SYS.LogUsedSpace-kB-G</NAME><DESC>
Amount of used LOGDIR filesystem space in the system in kilobytes.
</DESC></VAR>*/

  sfprintf(fp,"SYS.LogFreeFiles-G               %9d\n",
	   M.sys.LogFreeFiles);
/*<VAR><NAME>SYS.LogFreeFiles-G</NAME><DESC>
Amount of free LOGDIR filesystem i-node space in the system.
</DESC></VAR>*/
  sfprintf(fp,"SYS.LogUsedFiles-G               %9d\n",
	   M.sys.LogUsedFiles);
/*<VAR><NAME>SYS.LogUsedFiles-G</NAME><DESC>
Amount of used LOGDIR filesystem i-node space in the system.
</DESC></VAR>*/


  sfprintf(fp,"\n");

/*<VAR><HEAD>SS.*</HEAD><DESC>
SmtpServer counters and gauges.
</DESC></VAR>*/


  sfprintf(fp,"SS.Processes-G                        %4d\n",
	   M.ss.IncomingSMTPSERVERprocesses);
/*<VAR><NAME>SS.Processes-G</NAME><DESC>
A gauge tracking number of active instances of the smtpserver.
In running system the number one is the master process, all
active inbound sessions add themselves.
</DESC></VAR>*/

  sfprintf(fp,"SS.ParallelSMTPconnects-G             %4d\n",
	   M.ss.IncomingParallelSMTPconnects);
/*<VAR><NAME>SS.ParallelSMTPconnects-G</NAME><DESC>
A gauge tracking number of active incoming SMTP socket connections.
</DESC></VAR>*/
  sfprintf(fp,"SS.ParallelSMTPSconnects-G            %4d\n",
	   M.ss.IncomingParallelSMTPSconnects);
/*<VAR><NAME>SS.ParallelSMTPconnects-G</NAME><DESC>
A gauge tracking number of active incoming SMTPS socket connections.
</DESC></VAR>*/
  sfprintf(fp,"SS.ParallelSUBMITconnects-G           %4d\n",
	   M.ss.IncomingParallelSUBMITconnects);
/*<VAR><NAME>SS.ParallelSMTPconnects-G</NAME><DESC>
A gauge tracking number of active incoming SUBMIT socket connections.
</DESC></VAR>*/

  sfprintf(fp,"SS.ProcessForks                 %10u\n",
	   M.ss.IncomingSMTPSERVERforks); 
/*<VAR><NAME>SS.ProcessForks</NAME><DESC>
Number of started receiving SMTP/SMTPS/SUBMIT socket serving processes
</DESC></VAR>*/
  sfprintf(fp,"SS.ProcessForkFailures          %10u\n",
	   M.ss.ForkFailures); 
/*<VAR><NAME>SS.ProcessForkFailures</NAME><DESC>
Failures to fork(2) another process - e.g. system badly out of resources ?
</DESC></VAR>*/
  sfprintf(fp,"SS.ContentPolicyForkFailures    %10u\n",
	   M.ss.ForkFailures); 
/*<VAR><NAME>SS.ContentPolicyForkFailures</NAME><DESC>
Failures to fork(2) a content-policy analysis (interface) process
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTPconnects                 %10u\n",
	   M.ss.IncomingSMTPconnects);
/*<VAR><NAME>SS.SMTPconnects</NAME><DESC>
Number of received SMTP socket connections (also fork attempts to serve it)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTPSconnects                %10u\n",
	   M.ss.IncomingSMTPSconnects);
/*<VAR><NAME>SS.SMTPSconnects</NAME><DESC>
Number of received SMTPS socket connections (also fork attempts to serve it)
</DESC></VAR>*/
  sfprintf(fp,"SS.SUBMITconnects               %10u\n",
	   M.ss.IncomingSUBMITconnects);
/*<VAR><NAME>SS.SUBMITconnects</NAME><DESC>
Number of received SUBMIT socket connections (also fork attempts to serve it)
</DESC></VAR>*/

  sfprintf(fp,"SS.MaxSameIpSourceCloses        %10u\n",
	   M.ss.MaxSameIpSourceCloses);
/*<VAR><NAME>SS.MaxSameIpSourceCloses</NAME><DESC>
Number of times, when there have been more connections from any given
single IP address, than what "PARAM MaxSameIpSource" has been configured
to allow.
</DESC></VAR>*/
  sfprintf(fp,"SS.MaxParallelConnectionCloses  %10u\n",
	   M.ss.MaxParallelConnections);
/*<VAR><NAME>SS.MaxParallelConnectionCloses</NAME><DESC>
Number of times, when there have been more connections into smtpserver,
than the global "PARAM MaxParallelConnections" parameter has been configured
to allow.
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTPcommands                 %10u\n",
	   M.ss.IncomingCommands);
/*<VAR><NAME>SS.SMTPcommands</NAME><DESC>
Total number of received SMTP commands.  All commands before any analysis.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTPcommands-unknown         %10u\n",
	   M.ss.IncomingCommands_unknown);
/*<VAR><NAME>SS.SMTPcommands-unknown</NAME><DESC>
Number of received SMTP commands which for some reason
or other are considered invalid.
</DESC></VAR>*/

  sfprintf(fp,"SS.IncomingClientPipelines      %10u\n",
	   M.ss.IncomingClientPipelines);
/*<VAR><NAME>SS.IncomingClientPipelines</NAME><DESC>
Number of observed cases, where contacing client uses apparent PIPELINING
protocol enhancement, e.g. when (at any commands reception) there are
more data in the input stream right after a command has been read in.

This counts only once per connection in order to see, what share
of incoming sessions are using this feature.
</DESC></VAR>*/
  sfprintf(fp,"SS.IncomingSmtpTarpits          %10u\n",
	   M.ss.IncomingSmtpTarpits);
/*<VAR><NAME>SS.IncomingSmtpTarpits</NAME><DESC>
Number of cases, when the TARPIT functionality has been activated in the session.
This counts all instances, which may mean e.g. a dozen or more counts per
connection.
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_HELO                    %10u\n",
	   M.ss.IncomingSMTP_HELO);
/*<VAR><NAME>SS.SMTP_HELO</NAME><DESC>
Number of received HELO greetings.
Raw number without any analysis.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_HELO_ok                 %10u\n",
	   M.ss.IncomingSMTP_HELO_ok);
/*<VAR><NAME>SS.SMTP_HELO_ok</NAME><DESC>
Number of received HELO greetings which were ok per possibly applied
"strict" rules.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_HELO_bad                %10u\n",
	   M.ss.IncomingSMTP_HELO_bad);
/*<VAR><NAME>SS.SMTP_HELO_bad</NAME><DESC>
Number of received HELO greetings which were bad per possibly applied
"strict" rules.
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_EHLO                    %10u\n",
	   M.ss.IncomingSMTP_EHLO);
/*<VAR><NAME>SS.SMTP_EHLO</NAME><DESC>
Number of received EHLO greetings.
Raw number without any analysis.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_EHLO_ok                 %10u\n",
	   M.ss.IncomingSMTP_EHLO_ok);
/*<VAR><NAME>SS.SMTP_EHLO_ok</NAME><DESC>
Number of received EHLO greetings which were ok per possibly applied
"strict" rules.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_EHLO_bad                %10u\n",
	   M.ss.IncomingSMTP_EHLO_bad);
/*<VAR><NAME>SS.SMTP_EHLO_bad</NAME><DESC>
Number of received EHLO greetings which were bad per possibly applied
"strict" rules.
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_STARTTLS                %10u\n",
	   M.ss.IncomingSMTP_STARTTLS);
/*<VAR><NAME>SS.SMTP_STARTTLS</NAME><DESC>
Number of received STARTTLS commands in SMTP/LMTP/SUBMIT sockets.
(If this has been enabled in the system!)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTPTLSes                    %10u\n",
	   M.ss.IncomingSMTP_STARTTLS);
/*<VAR><NAME>SS.SMTPTLSes</NAME><DESC>
Duplicate name/printout of "SS.SMTP_STARTTLS"
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_STARTTLS_fail           %10u\n",
	   M.ss.IncomingSMTP_STARTTLS_fail);
/*<VAR><NAME>SS.SMTP_STARTTLS_fail</NAME><DESC>
Number of instances, when STARTTLS command has failed for some reason.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_NOOP                    %10u\n",
	   M.ss.IncomingSMTP_NOOP);
/*<VAR><NAME>SS.SMTP_NOOP</NAME><DESC>
Number of received NOOP verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_RSET                    %10u\n",
	   M.ss.IncomingSMTP_RSET);
/*<VAR><NAME>SS.SMTP_RSET</NAME><DESC>
Number of received RSET verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_HELP                    %10u\n",
	   M.ss.IncomingSMTP_HELP);
/*<VAR><NAME>SS.SMTP_HELP</NAME><DESC>
Number of received HELP verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_ETRN                    %10u\n",
	   M.ss.IncomingSMTP_ETRN);
/*<VAR><NAME>SS.SMTP_ETRN</NAME><DESC>
Number of received ETRN verbs.
(If this has been enabled in the system!)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_EXPN                    %10u\n",
	   M.ss.IncomingSMTP_EXPN);
/*<VAR><NAME>SS.SMTP_EXPN</NAME><DESC>
Number of received EXPN verbs.
(If this has been enabled in the system!)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_VRFY                    %10u\n",
	   M.ss.IncomingSMTP_VRFY);
/*<VAR><NAME>SS.SMTP_VRFY</NAME><DESC>
Number of received VRFY verbs.
(If this has been enabled in the system!)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_TICK                    %10u\n",
	   M.ss.IncomingSMTP_TICK);
/*<VAR><NAME>SS.SMTP_TICK</NAME><DESC>
Number of received TICK verbs.
(An BSMTP environement verb, actually doesn't mean much of anything.)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_TURN                    %10u\n",
	   M.ss.IncomingSMTP_TURN);
/*<VAR><NAME>SS.SMTP_TURN</NAME><DESC>
Number of received TURN verbs.
(This isn't actually implemented, and leads to an error..)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_VERBOSE                 %10u\n",
	   M.ss.IncomingSMTP_VERBOSE);
/*<VAR><NAME>SS.SMTP_VERBOSE</NAME><DESC>
Number of received VERBOSE verbs.
(If this has been enabled in the system!)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_DEBUG                   %10u\n",
	   M.ss.IncomingSMTP_DEBUG);
/*<VAR><NAME>SS.SMTP_DEBUG</NAME><DESC>
Number of received DEBUG verbs.
(If this has been enabled in the system!)
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_MAIL                    %10u\n",
	   M.ss.IncomingSMTP_MAIL);
/*<VAR><NAME>SS.SMTP_MAIL</NAME><DESC>
Total number of received MAIL verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_MAIL_ok                 %10u\n",
	   M.ss.IncomingSMTP_MAIL_ok);
/*<VAR><NAME>SS.SMTP_MAIL_ok</NAME><DESC>
Total number of acceptably received MAIL verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_MAIL_bad                %10u\n",
	   M.ss.IncomingSMTP_MAIL_bad);
/*<VAR><NAME>SS.SMTP_MAIL_bad</NAME><DESC>
Total number of non-acceptably received MAIL verbs.
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_RCPT                    %10u\n",
	   M.ss.IncomingSMTP_RCPT);
/*<VAR><NAME>SS.SMTP_RCPT</NAME><DESC>
Total number of received RCPT verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_RCPT_ok                 %10u\n",
	   M.ss.IncomingSMTP_RCPT_ok);
/*<VAR><NAME>SS.SMTP_RCPT_ok</NAME><DESC>
Total number of acceptably received RCPT verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_RCPT_bad                %10u\n",
	   M.ss.IncomingSMTP_RCPT_bad);
/*<VAR><NAME>SS.SMTP_RCPT_bad</NAME><DESC>
Total number of non-acceptably received RCPT verbs.
</DESC></VAR>*/

  sfprintf(fp,"SS.Smtp-Opt-ENVID               %10u\n",
	   M.ss.IncomingSMTP_OPT_ENVID);
/*<VAR><NAME>SS.Smtp-Opt-ENVID</NAME><DESC>
Total number of received ENVID options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-SIZE                %10u\n",
	   M.ss.IncomingSMTP_OPT_SIZE);
/*<VAR><NAME>SS.Smtp-Opt-SIZE</NAME><DESC>
Total number of received SIZE options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-AUTH                %10u\n",
	   M.ss.IncomingSMTP_OPT_AUTH);
/*<VAR><NAME>SS.Smtp-Opt-AUTH</NAME><DESC>
Total number of received AUTH options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-DELIVERBY           %10u\n",
	   M.ss.IncomingSMTP_OPT_DELIVERBY);
/*<VAR><NAME>SS.Smtp-Opt-DELIVERBY</NAME><DESC>
Total number of received DELIVERBY options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-BODY-8BITMIME       %10u\n",
	   M.ss.IncomingSMTP_OPT_BODY_8BITMIME);
/*<VAR><NAME>SS.Smtp-Opt-BODY-8BITMIME</NAME><DESC>
Total number of received BODY=8BITMIME options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-BODY-BINARYMIME     %10u\n",
	   M.ss.IncomingSMTP_OPT_BODY_BINARYMIME);
/*<VAR><NAME>SS.Smtp-Opt-BODY-BINARYMIME</NAME><DESC>
Total number of received BODY=BINARYMIME options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-BODY-7BIT           %10u\n",
	   M.ss.IncomingSMTP_OPT_BODY_7BIT);
/*<VAR><NAME>SS.Smtp-Opt-BODY-7BIT</NAME><DESC>
Total number of received BODY=7BIT options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-RETURN              %10u\n",
	   M.ss.IncomingSMTP_OPT_RET);
/*<VAR><NAME>SS.Smtp-Opt-RETURN</NAME><DESC>
Total number of received RET=.. options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-NOTIFY              %10u\n",
	   M.ss.IncomingSMTP_OPT_NOTIFY);
/*<VAR><NAME>SS.Smtp-Opt-NOTIFY</NAME><DESC>
Total number of received NOTIFY=.. options
</DESC></VAR>*/
  sfprintf(fp,"SS.Smtp-Opt-ORCPT               %10u\n",
	   M.ss.IncomingSMTP_OPT_ORCPT);
/*<VAR><NAME>SS.Smtp-Opt-ORCPT</NAME><DESC>
Total number of received ORCPT=.. options
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_DATA                    %10u\n",
	   M.ss.IncomingSMTP_DATA);
/*<VAR><NAME>SS.SMTP_DATA</NAME><DESC>
Total number of received DATA verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_DATA_ok                 %10u\n",
	   M.ss.IncomingSMTP_DATA_ok);
/*<VAR><NAME>SS.SMTP_DATA_ok</NAME><DESC>
Total number of received messages via DATA verb.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_DATA_bad                %10u\n",
	   M.ss.IncomingSMTP_DATA_bad);
/*<VAR><NAME>SS.SMTP_DATA_bad</NAME><DESC>
Total number of failed receptions of DATA verb, or message content.
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_BDAT                    %10u\n",
	   M.ss.IncomingSMTP_BDAT);
/*<VAR><NAME>SS.SMTP_BDAT</NAME><DESC>
Total number of received BDAT verbs.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_BDAT_ok                 %10u\n",
	   M.ss.IncomingSMTP_BDAT_ok);
/*<VAR><NAME>SS.SMTP_BDAT_ok</NAME><DESC>
Total number of received messages via BDAT verb.

(FIXME: BDAT without LAST parameter ??)
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_BDAT_bad                %10u\n",
	   M.ss.IncomingSMTP_BDAT_bad);
/*<VAR><NAME>SS.SMTP_BDAT_bad</NAME><DESC>
Total number of failed receptions of BDAT verb, or message content.
</DESC></VAR>*/

  sfprintf(fp,"SS.SMTP_DATA-kB                 %10u\n",
	   M.ss.IncomingSMTP_DATA_KBYTES);
/*<VAR><NAME>SS.SMTP_DATA-kB</NAME><DESC>
Received message volume via DATA verb.
Each message size rounded up to next 1024 bytes, and divided by 1024.
Finally summed up into this variable.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_BDAT-kB                 %10u\n",
	   M.ss.IncomingSMTP_BDAT_KBYTES);
/*<VAR><NAME>SS.SMTP_BDAT-kB</NAME><DESC>
Received message volume via BDAT verb.
Each message size rounded up to next 1024 bytes, and divided by 1024.
Finally summed up into this variable.
</DESC></VAR>*/
  sfprintf(fp,"SS.SMTP_input_spool-kB          %10u\n",
	   M.ss.IncomingSMTP_spool_KBYTES);
/*<VAR><NAME>SS.SMTP_input_spool-kB</NAME><DESC>
Sum Received message spool sizes rounded up to next 1024 byte, and
divided by 1024, then summed up into this variable.
</DESC></VAR>*/

  sfprintf(fp,"SS.ReceivedMessages             %10u\n",
	   M.ss.ReceivedMessagesSs);
/*<VAR><NAME>SS.ReceivedMessages</NAME><DESC>
Cumulative count of received messages by DATA and BDAT verbs.

This includes cases of messages that in the end became rejected!
</DESC></VAR>*/
  sfprintf(fp,"SS.ReceivedRecipients           %10u\n",
	   M.ss.ReceivedRecipientsSs);
/*<VAR><NAME>SS.ReceivedRecipients</NAME><DESC>
Cumulative count of received recipients by DATA and BDAT verbs.

This includes cases of messages that in the end became rejected,
but does so with acceptance pre-filtered RCPT addresses.
</DESC></VAR>*/
  sfprintf(fp,"SS.TransmittedMessages          %10u\n",
	   M.ss.TransmittedMessagesSs);
/*<VAR><NAME>SS.TransmittedMessages</NAME><DESC>
Cumulative count of messages that have been successfully sent from
smtpserver onwards to the system proper.
</DESC></VAR>*/
  sfprintf(fp,"SS.TransmittedRecipients        %10u\n",
	   M.ss.TransmittedRecipientsSs);
/*<VAR><NAME>SS.TransmittedRecipients</NAME><DESC>
Cumulative count of recipients that have been successfully sent from
smtpserver onwards to the system proper.
</DESC></VAR>*/

  sfprintf(fp,"\n");

/*<VAR><HEAD>RT.*</HEAD><DESC>
RouTer counters and gauges.
</DESC></VAR>*/


  sfprintf(fp,"RT.RouterProcesses-G             %9d\n",
	   M.rt.RouterProcesses);
/*<VAR><NAME>RT.RouterProcesses-G</NAME><DESC>
Current count of router processes.

The router master (queue-manager) is number one, resource
configuration limits eventually how many there will be, but
there won't be that many running, until there has a burst of high
activity in form of many message to feed to processing.
</DESC></VAR>*/
  sfprintf(fp,"RT.RouterProcessForks           %10u\n",
	   M.rt.RouterProcessForks);
/*<VAR><NAME>RT.RouterProcessForks</NAME><DESC>
Count of started active processing instances.

This is zeroed at queue manager startp, and should max out, when
all configured-to-be-used resources are in use.

It is possible, that there is some problem in the system, and
the processing router processes keep crashing.  Then you will
see this count keep counting up, while the RouterProcesses-G
stays stable, or perhaps jumps up and down a bit.
</DESC></VAR>*/
  sfprintf(fp,"RT.RouterProcessFaults          %10u\n",
	   M.rt.RouterProcessFaults);
/*<VAR><NAME>RT.RouterProcessFaults</NAME><DESC>
Count of active router subprocesses closing by anything else than
"exit(0)".

This should always stay zero!
</DESC></VAR>*/

  sfprintf(fp,"RT.ReceivedMessages             %10u\n",
	   M.rt.ReceivedMessages);
/*<VAR><NAME>RT.ReceivedMessages</NAME><DESC>
Number of messages received into router queue-manager input queue.
</DESC></VAR>*/
  sfprintf(fp,"RT.ReceivedRecipients           %10u\n",
	   M.rt.ReceivedRecipients);
/*<VAR><NAME>RT.ReceivedRecipients</NAME><DESC>
Number of parsed recipients in processed messages.

Where RT.ReceivedMessages is kept with router input queue manager, this
count is known only when a message is actually processed.
Essentially same problem, as with  RT.StoredRecipients-G.
</DESC></VAR>*/
  sfprintf(fp,"RT.TransmittedMessages          %10u\n",
	   M.rt.TransmittedMessages);
/*<VAR><NAME>RT.TransmittedMessages</NAME><DESC>
Number of messages that have completed processing in router, and
have been moved onwards to scheduler.
</DESC></VAR>*/
  sfprintf(fp,"RT.TransmittedRecipients        %10u\n",
	   M.rt.TransmittedRecipients);
/*<VAR><NAME>RT.TransmittedRecipients</NAME><DESC>
Number of recipient addresses (specifications) in the messages
moved onwards to scheduler.  (Router internal alias expansion
shows up with this count being slightly higher, than the received
recipient count.)
</DESC></VAR>*/

  sfprintf(fp,"RT.ReceivedVolume-kB            %10u\n",
	   M.rt.ReceivedVolume);
/*<VAR><NAME>RT.ReceivedVolume-kB</NAME><DESC>
Message volume received into router input queue, counted as kilobytes
after rounding each received message file size up to next 1024 byte level.
</DESC></VAR>*/
  sfprintf(fp,"RT.TransmittedVolume-kB         %10u\n",
	   M.rt.TransmittedVolume);
/*<VAR><NAME>RT.TransmittedVolume-kB</NAME><DESC>
Message volume sent onwards from the router to the scheduler's "queue" directory.
These are the original incoming files! 
(The usual round up to next kilobyte...)
</DESC></VAR>*/
  sfprintf(fp,"RT.TransmittedVolume2-kB        %10u\n",
	   M.rt.TransmittedVolume2);
/*<VAR><NAME>RT.TransmittedVolume2-kB</NAME><DESC>
Message volume sent onwards from the router to the scheduler's "transport" directory.
These are transport-specification entries with rewritten headers, etc.
(The usual round up to next kilobyte...)
</DESC></VAR>*/

  sfprintf(fp,"RT.StoredMessages-G              %9d\n",
	   M.rt.StoredMessages);
/*<VAR><NAME>RT.StoredMessages-G</NAME><DESC>
Number of messages presently in the routing queue, including those
not quite yet sent onwards.
</DESC></VAR>*/
  sfprintf(fp,"RT.StoredVolume-kB-G             %9d\n",
	   M.rt.StoredVolume);
/*<VAR><NAME>RT.StoredVolume-kB-G</NAME><DESC>
Total size of messages in router input queue.
(The usual round up to next kilobyte...)
</DESC></VAR>*/

  sfprintf(fp,"\n");

/*<VAR><HEAD>SC.*</HEAD><DESC>
SCheduler counters and gauges.
</DESC></VAR>*/

  sfprintf(fp,"SC.ReceivedMessages             %10u\n",
	   M.sc.ReceivedMessagesSc);
/*<VAR><NAME>SC.ReceivedMessages</NAME><DESC>
Number of messages inserted in Scheduler's pre-digestion queue.
From there they are assimilated into processing in rate-limited
manner in order to limit the effect of queue assimilation into
system functionality..
</DESC></VAR>*/
  sfprintf(fp,"SC.ReceivedRecipients           %10u\n",
	   M.sc.ReceivedRecipientsSc);
/*<VAR><NAME>SC.ReceivedRecipients</NAME><DESC>
Number of assimilated recipient descriptors.
</DESC></VAR>*/
  sfprintf(fp,"SC.TransmittedMessages          %10u\n",
	   M.sc.TransmittedMessagesSc);
/*<VAR><NAME>SC.TransmittedMessages</NAME><DESC>
Number of messages that have all their recipients completed
(successes and failures together) out from the internal state.
</DESC></VAR>*/
  sfprintf(fp,"SC.TransmittedRecipients        %10u\n",
	   M.sc.TransmittedRecipientsSc);
/*<VAR><NAME>SC.TransmittedRecipients</NAME><DESC>
Number of recipient addresses that have been completed
(successes and failures together) out from the internal state.
</DESC></VAR>*/

  sfprintf(fp,"SC.StoredMessages-G              %9d\n",
	   M.sc.StoredMessagesSc);
/*<VAR><NAME>SC.StoredMessages-G</NAME><DESC>
Gauge of message files in the queue.
</DESC></VAR>*/
  sfprintf(fp,"SC.StoredThreads-G               %9d\n",
	   M.sc.StoredThreadsSc);
/*<VAR><NAME>SC.StoredThreads-G</NAME><DESC>
Gauge  of different  channel/host   pairs total in the queue state.
</DESC></VAR>*/
  sfprintf(fp,"SC.StoredVertices-G              %9d\n",
	   M.sc.StoredVerticesSc);
/*<VAR><NAME>SC.StoredVertices-G</NAME><DESC>
Sum of number of messages in each thread.
</DESC></VAR>*/
  sfprintf(fp,"SC.StoredRecipients-G            %9d\n",
	   M.sc.StoredRecipientsSc);
/*<VAR><NAME>SC.StoredRecipients-G</NAME><DESC>
Sum of actual recipients in each message in each thread.
</DESC></VAR>*/

  sfprintf(fp,"SC.ReceivedVolume-kB            %10u\n",
	   M.sc.ReceivedVolumeSc);
/*<VAR><NAME>SC.ReceivedVolume-kB</NAME><DESC>
Received messages spool file(s) size sum in kilobytes.
</DESC></VAR>*/
  sfprintf(fp,"SC.StoredVolume-kB-G             %9d\n",
	   M.sc.StoredVolumeSc);
/*<VAR><NAME>SC.StoredVolume-kB</NAME><DESC>
Still in queue messages spool file(s) size sum in kilobytes.
</DESC></VAR>*/
  sfprintf(fp,"SC.TransmittedVolume-kB         %10u\n",
	   M.sc.TransmittedVolumeSc);
/*<VAR><NAME>SC.TransmittedVolume-kB</NAME><DESC>
Sum of message spool file(s) sizes completed so far.
</DESC></VAR>*/

  sfprintf(fp,"SC.TransportAgentForks          %10u\n",
	   M.sc.TransportAgentForksSc);
/*<VAR><NAME>SC.TransportAgentForks</NAME><DESC>
Number of times the scheduler has started a new transport-agent process.
</DESC></VAR>*/
  sfprintf(fp,"SC.TransportAgentProcesses-G     %9d\n",
	   M.sc.TransportAgentProcessesSc);
/*<VAR><NAME>SC.TransportAgentProcesses-G</NAME><DESC>
Number of transport agent processes currently running under the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"SC.TransportAgentsActive-G       %9d\n",
	   M.sc.TransportAgentsActiveSc);
/*<VAR><NAME>SC.TransportAgentsActive-G</NAME><DESC>
Number of transport agent processes currently considered actively
working on something.
</DESC></VAR>*/
  sfprintf(fp,"SC.TransportAgentsIdle-G         %9d\n",
	   M.sc.TransportAgentsIdleSc);
/*<VAR><NAME>SC.TransportAgentsIdle-G</NAME><DESC>
Number of transport agent processes currently placed into "idle"
state in toder to be recycled to some other job.
(Forking is so expensive thing...)
</DESC></VAR>*/

  sfprintf(fp,"SC.MQ2Parallel-G                 %9d\n",
	   M.sc.MQ2sockParallel);
/*<VAR><NAME>SC.MQ2Parallel-G</NAME><DESC>
Gauge of currently active "mailq" (in protocol version 2 mode) connections.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2Connects                  %10u\n",
	   M.sc.MQ2sockConnects);
/*<VAR><NAME>SC.MQ2Connects</NAME><DESC>
Count of received connects to "mailq" (in protocol version 2 mode) socket.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2TcpWrapRej                %10u\n",
	   M.sc.MQ2sockTcpWrapRej);
/*<VAR><NAME>SC.MQ2TcpWrapRej</NAME><DESC>
Number of times that tcp-wrapper has rejected the connection to
the mailq-v2 socket.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2AuthRej                   %10u\n",
	   M.sc.MQ2sockAuthRej);
/*<VAR><NAME>SC.MQ2AuthRej</NAME><DESC>
Number of times that mailq-v2 socket authentication has failed.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2TimedOut                  %10u\n",
	   M.sc.MQ2sockTimedOut);
/*<VAR><NAME>SC.MQ2TimedOut</NAME><DESC>
Count of cases, where MQ2 socket has become too old, and has been killed due to it.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2ReadEOF                   %10u\n",
	   M.sc.MQ2sockReadEOF);
/*<VAR><NAME>SC.MQ2ReadEOF</NAME><DESC>
Count of cases, where the MQ2 socket has been closed by the remote end
without doing proper "QUIT" command.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2ReadFails                 %10u\n",
	   M.sc.MQ2sockReadFails);
/*<VAR><NAME>SC.MQ2ReadFails</NAME><DESC>
Very odd internal error in code logic.  Should see "timed out", or
"Read EOF" cases, only.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2WriteFails                %10u\n",
	   M.sc.MQ2sockWriteFails);
/*<VAR><NAME>SC.MQ2WriteFails</NAME><DESC>
Write to MQ2 socket has failed for other than EAGAIN/EINTR reason.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2Commands                  %10u\n",
	   M.sc.MQ2sockCommands);
/*<VAR><NAME>SC.MQ2Commands</NAME><DESC>
Count of command lines received in MQ2 sockets.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandsRej               %10u\n",
	   M.sc.MQ2sockCommandsRej);
/*<VAR><NAME>SC.MQ2CommandsRej</NAME><DESC>
Count of rejected command lines received in MQ2 sockets.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandAUTH               %10u\n",
	   M.sc.MQ2sockCommandAUTH);
/*<VAR><NAME>SC.MQ2CommandAUTH</NAME><DESC>
Count of received AUTH commands.
Should match count of MQ2 sockets (unless somebody tries to break in..)
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandQUIT               %10u\n",
	   M.sc.MQ2sockCommandQUIT);
/*<VAR><NAME>SC.MQ2CommandQUIT</NAME><DESC>
Count of received QUIT commands.
Should match count of MQ2 sockets.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandETRN               %10u\n",
	   M.sc.MQ2sockCommandETRN);
/*<VAR><NAME>SC.MQ2CommandETRN</NAME><DESC>
Count of received ETRN commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandKillThr            %10u\n",
	   M.sc.MQ2sockCommandKillThr);
/*<VAR><NAME>SC.MQ2CommandKillThr</NAME><DESC>
Count of received KILL THR commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandKillMsg            %10u\n",
	   M.sc.MQ2sockCommandKillMsg);
/*<VAR><NAME>SC.MQ2CommandKillMsg</NAME><DESC>
Count of received KILL MSG commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandKillProcess        %10u\n",
	   M.sc.MQ2sockCommandKillProcess);
/*<VAR><NAME>SC.MQ2CommandKillProcess</NAME><DESC>
Count of received KILL PROC commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandRerouteThr         %10u\n",
	   M.sc.MQ2sockCommandRerouteThr);
/*<VAR><NAME>SC.MQ2CommandRerouteThr</NAME><DESC>
Count of received REROUTE THR commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandRerouteMsg         %10u\n",
	   M.sc.MQ2sockCommandRerouteMsg);
/*<VAR><NAME>SC.MQ2CommandRerouteMsg</NAME><DESC>
Count of received REROUTE MSG commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandShowQueueThreads   %10u\n",
	   M.sc.MQ2sockCommandShowQueueThreads);
/*<VAR><NAME>SC.MQ2CommandShowQueueThreads</NAME><DESC>
Count of received SHOW QUEUE THREADS commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandShowQueueThreads2  %10u\n",
	   M.sc.MQ2sockCommandShowQueueThreads2);
/*<VAR><NAME>SC.MQ2CommandShowQueueThreads2</NAME><DESC>
Count of received SHOW QUEUE THREADS2 commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandShowQueueShort     %10u\n",
	   M.sc.MQ2sockCommandShowQueueShort);
/*<VAR><NAME>SC.MQ2CommandShowQueueShort</NAME><DESC>
Count of received SHOW QUEUE SHORT commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandShowQueueVeryShort %10u\n",
	   M.sc.MQ2sockCommandShowQueueVeryShort);
/*<VAR><NAME>SC.MQ2CommandShowQueueVeryShort</NAME><DESC>
Count of received SHOW SNMP commands.
These are merely two last lines of "mailq -Q" output.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandShowThread         %10u\n",
	   M.sc.MQ2sockCommandShowThread);
/*<VAR><NAME>SC.MQ2CommandShowThread</NAME><DESC>
Count of received SHOW THREAD 'channel' 'host' commands.
</DESC></VAR>*/
  sfprintf(fp,"SC.MQ2CommandShowCounters       %10u\n",
	   M.sc.MQ2sockCommandShowCounters);
/*<VAR><NAME>SC.MQ2CommandShowCounters</NAME><DESC>
Count of received SHOW COUNTERS commands.
(e.g. MQ2 way of asking these counters now being described.)
</DESC></VAR>*/


  sfprintf(fp,"\n");

/*<VAR><HEAD>TA-SMTP.*</HEAD><DESC>
SMTP transpor agent counters and gauges.
</DESC></VAR>*/


  sfprintf(fp,"TA-SMTP.TaProcessStarts         %10u\n",
	   M.tasmtp.TaProcessStarts);
/*<VAR><NAME>TA-SMTP.TaProcessStarts</NAME><DESC>
Number of times that this transport agent processes type have been
started in this system during this SHM blocks lifetime.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.TaProcCount-G            %9d\n",
	   M.tasmtp.TaProcCountG);
/*<VAR><NAME>TA-SMTP.TaProcCount-G</NAME><DESC>
Gauge of presently running transport agent processes of this type.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.TaIdleStates            %10u\n",
	   M.tasmtp.TaIdleStates);
/*<VAR><NAME>TA-SMTP.TaIdleStates</NAME><DESC>
Number of times this transport agent process type has been placed
into "idle" state by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.TaMessages              %10u\n",
	   M.tasmtp.TaMessages);
/*<VAR><NAME>TA-SMTP.TaMessages</NAME><DESC>
Number of tasks fed to this transport agent process type by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.TaDeliveryStarts        %10u\n",
	   M.tasmtp.TaDeliveryStarts);
/*<VAR><NAME>TA-SMTP.TaDeliveryStarts</NAME><DESC>
Number of times that this transport agent type has started a delivery on
given tasks.  This might be lower count, than TaMessages.
</DESC></VAR>*/


  sfprintf(fp,"TA-SMTP.SmtpStarts              %10u\n",
	   M.tasmtp.SmtpStarts);
/*<VAR><NAME>TA-SMTP.SmtpStarts</NAME><DESC>
Number of times that the SMTP transport agent is beginning
connecting to remote system.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpConnects            %10u\n",
	   M.tasmtp.SmtpConnects);
/*<VAR><NAME>TA-SMTP.SmtpConnects</NAME><DESC>
Number of times that the SMTP transport agent has successfully
made SMTP connection at the socket level.
This doesn't yet know about possible "500 go away" greeting...
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpConnectFails        %10u\n",
	   M.tasmtp.SmtpConnectFails);
/*<VAR><NAME>TA-SMTP.SmtpConnectFails</NAME><DESC>
Number of times that the connection formation has failed at socket level.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpConnectsCnt-G        %9d\n",
	   M.tasmtp.SmtpConnectsCnt);
/*<VAR><NAME>TA-SMTP.SmtpConnectsCnt-G</NAME><DESC>
Gauge of successfully formed SFIO streams presently talking to SMTP or
LMTP destinations.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.LmtpConnects            %10u\n",
	   M.tasmtp.LmtpConnects);
/*<VAR><NAME>TA-SMTP.LmtpConnects</NAME><DESC>
Number of times that the SMTP transport agent has successfully
made LMTP connection, and remote end has accepted the socket.
This doesn't yet know about possible "500 go away" greeting...
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpPIPELINING          %10u\n",
	   M.tasmtp.SmtpPIPELINING);
/*<VAR><NAME>TA-SMTP.SmtpPIPELINING</NAME><DESC>
Number of sessions, where remote end has published PIPELINING
capability, and we are taking advantage of it.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpSTARTTLS            %10u\n",
	   M.tasmtp.SmtpSTARTTLS);
/*<VAR><NAME>TA-SMTP.SmtpSTARTTLS</NAME><DESC>
Number of sessions, where remote end has published STARTTLS
capability, and we are taking advantage of it.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpSTARTTLSok          %10u\n",
	   M.tasmtp.SmtpSTARTTLSok);
/*<VAR><NAME>TA-SMTP.SmtpSTARTTLSok</NAME><DESC>
Number of sessions, where we succeeded at starting the TLS encapsulation
of the stream. (Relative to SmtpSTARTTLS.)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpSTARTTLSfail        %10u\n",
	   M.tasmtp.SmtpSTARTTLSfail);
/*<VAR><NAME>TA-SMTP.SmtpSTARTTLSfail</NAME><DESC>
Number of sessions, where we failed at starting the TLS encapsulation
of the stream. (Relative to SmtpSTARTTLS.)
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpEHLO                %10u\n",
	   M.tasmtp.SmtpEHLO);
/*<VAR><NAME>TA-SMTP.SmtpEHLO</NAME><DESC>
Number of sent EHLO greetings.
(Sometimes we may be running in a mode forbidding EHLO, e.g. "smtp-77".)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpEHLOok              %10u\n",
	   M.tasmtp.SmtpEHLOok);
/*<VAR><NAME>TA-SMTP.SmtpEHLOok</NAME><DESC>
Number of EHLO greetings yielding successfull result (and capability sets.)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpEHLOfail            %10u\n",
	   M.tasmtp.SmtpEHLOfail);
/*<VAR><NAME>TA-SMTP.SmtpEHLOfail</NAME><DESC>
Number of EHLO greetings yielding failure.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpHELO                %10u\n",
	   M.tasmtp.SmtpHELO);
/*<VAR><NAME>TA-SMTP.SmtpHELO</NAME><DESC>
Number of sent HELO greetings (e.g. fallback from EHLO due to
moronic firewalls, and/or due to configuration forbidding
sending of "EHLO", e.g. "smtp-77" mode.)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpHELOok              %10u\n",
	   M.tasmtp.SmtpHELOok);
/*<VAR><NAME>TA-SMTP.SmtpHELOok</NAME><DESC>
Number of HELO greetings yielding successfull result.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpHELOfail            %10u\n",
	   M.tasmtp.SmtpHELOfail);
/*<VAR><NAME>TA-SMTP.SmtpHELOfail</NAME><DESC>
Number of HELO greetings yielding failure result.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpLHLO                %10u\n",
	   M.tasmtp.SmtpLHLO);
/*<VAR><NAME>TA-SMTP.SmtpLHLO</NAME><DESC>
Number of sent LHLO greetings, e.g. while talking to remotes
that are actually LMTP speaking message stores into which
we are doing "local delivery".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpLHLOok              %10u\n",
	   M.tasmtp.SmtpLHLOok);
/*<VAR><NAME>TA-SMTP.SmtpLHLOok</NAME><DESC>
Number of LHLO greetings yielding successfull result (and capability sets)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpLHLOfail            %10u\n",
	   M.tasmtp.SmtpLHLOfail);
/*<VAR><NAME>TA-SMTP.SmtpLHLOfail</NAME><DESC>
Number of LHLO greetings yielding failure result.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.capa8BITMIME            %10u\n",
	  M.tasmtp.EHLOcapability8BITMIME);
/*<VAR><NAME>TA-SMTP.capa8BITMIME</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "8BITMIME".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaAUTH                %10u\n",
	  M.tasmtp.EHLOcapabilityAUTH);
/*<VAR><NAME>TA-SMTP.capaAUTH</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "AUTH".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaDSN                 %10u\n",
	  M.tasmtp.EHLOcapabilityDSN);
/*<VAR><NAME>TA-SMTP.capaDSN</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "DSN".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaCHUNKING            %10u\n",
	  M.tasmtp.EHLOcapabilityCHUNKING);
/*<VAR><NAME>TA-SMTP.capaCHUNKING</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "CHUNKING".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaDELIVERBY           %10u\n",
	  M.tasmtp.EHLOcapabilityDELIVERBY);
/*<VAR><NAME>TA-SMTP.capaDELIVERBY</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "DELIVERBY".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaENHANCEDSTATUSCODES %10u\n",
	  M.tasmtp.EHLOcapabilityENHANCEDSTATUSCODES);
/*<VAR><NAME>TA-SMTP.capaENHANCEDSTATUSCODES</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "ENHANCEDSTATUSCODES".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaPIPELINING          %10u\n",
	  M.tasmtp.EHLOcapabilityPIPELINING);
/*<VAR><NAME>TA-SMTP.capaPIPELINING</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "PIPELINING".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaSIZE                %10u\n",
	  M.tasmtp.EHLOcapabilitySIZE);
/*<VAR><NAME>TA-SMTP.capaSIZE</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "SIZE".
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.capaSTARTTLS            %10u\n",
	  M.tasmtp.EHLOcapabilitySTARTTLS);
/*<VAR><NAME>TA-SMTP.capaSTARTTLS</NAME><DESC>
Number of times that EHLO (and LHLO) greeting capability sets
have contained "STARTTLS".
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.sent-option-ENVID       %10u\n",
	   M.tasmtp.SmtpOPT_ENVID);
/*<VAR><NAME>TA-SMTP.sent-option-ENVID</NAME><DESC>
Number of times that these transport agents have sent 
out the "ENVID=" option.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.sent-option-SIZE        %10u\n",
	   M.tasmtp.SmtpOPT_SIZE);
/*<VAR><NAME>TA-SMTP.sent-option-SIZE</NAME><DESC>
Number of times that these transport agents have sent 
out the "SIZE=" option.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.sent-option-RET         %10u\n",
	   M.tasmtp.SmtpOPT_RET);
/*<VAR><NAME>TA-SMTP.sent-option-RET</NAME><DESC>
Number of times that these transport agents have sent 
out the "RET=" option.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.sent-option-NOTIFY      %10u\n",
	   M.tasmtp.SmtpOPT_NOTIFY);
/*<VAR><NAME>TA-SMTP.sent-option-NOTIFY</NAME><DESC>
Number of times that these transport agents have sent 
out the "NOTIFY=" option.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.sent-option-ORCPT       %10u\n",
	   M.tasmtp.SmtpOPT_ORCPT);
/*<VAR><NAME>TA-SMTP.sent-option-ORCPT</NAME><DESC>
Number of times that these transport agents have sent 
out the "ORCPT=" option.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpMAIL                %10u\n",
	   M.tasmtp.SmtpMAIL);
/*<VAR><NAME>TA-SMTP.SmtpMAIL</NAME><DESC>
Number of times that "MAIL" verb has been sent (or at least tried to.)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpMAILok              %10u\n",
	   M.tasmtp.SmtpMAILok);
/*<VAR><NAME>TA-SMTP.SmtpMAILok</NAME><DESC>
Number of times that "MAIL" verb got "ok" result back.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpRCPT                %10u\n",
	   M.tasmtp.SmtpRCPT);
/*<VAR><NAME>TA-SMTP.SmtpRCPT</NAME><DESC>
Number of times that "RCPT" verb has been sent (or at least tried to.)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpRCPTok              %10u\n",
	   M.tasmtp.SmtpRCPTok);
/*<VAR><NAME>TA-SMTP.SmtpRCPTok</NAME><DESC>
Number of times that "RCPT" verb got "ok" result back.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpDATA                %10u\n",
	   M.tasmtp.SmtpDATA);
/*<VAR><NAME>TA-SMTP.SmtpDATA</NAME><DESC>
Number of times that "DATA" verb has been sent (or at least tried to.)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpDATAok              %10u\n",
	   M.tasmtp.SmtpDATAok);
/*<VAR><NAME>TA-SMTP.SmtpDATAok</NAME><DESC>
Number of times that "DATA" verb got "ok" result back.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpBDAT                %10u\n",
	   M.tasmtp.SmtpBDAT);
/*<VAR><NAME>TA-SMTP.SmtpBDAT</NAME><DESC>
Number of times that "BDAT" verb has been sent (or at least tried to.)
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpBDATok              %10u\n",
	   M.tasmtp.SmtpBDATok);
/*<VAR><NAME>TA-SMTP.SmtpBDATok</NAME><DESC>
Number of times that "BDAT" verb got "ok" result back.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMTP.SmtpDATAvolume-kB       %10u\n",
	   M.tasmtp.SmtpDATAvolume);
/*<VAR><NAME>TA-SMTP.SmtpDATAvolume-kB</NAME><DESC>
Number of kilobytes written to remote systems within DATA transaction.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.SmtpBDATvolume-kB       %10u\n",
	   M.tasmtp.SmtpBDATvolume);
/*<VAR><NAME>TA-SMTP.SmtpBDATvolume-kB</NAME><DESC>
Number of kilobytes written to remote systems within BDAT transaction.
</DESC></VAR>*/


  sfprintf(fp,"TA-SMTP.RcptsOk                 %10u\n",
	   M.tasmtp.TaRcptsOk);
/*<VAR><NAME>TA-SMTP.RcptsOk</NAME><DESC>
Number of recipient addresses that have been diagnosed as successfully processed.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.RcptsRetry              %10u\n",
	   M.tasmtp.TaRcptsRetry);
/*<VAR><NAME>TA-SMTP.RcptsRetry</NAME><DESC>
Number of recipient addresses that have been diagnosed as needing to be retried.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMTP.RcptsFail               %10u\n",
	   M.tasmtp.TaRcptsFail);
/*<VAR><NAME>TA-SMTP.RcptsFail</NAME><DESC>
Number of recipient addresses that have been diagnosed as unsuccessfully processed.
</DESC></VAR>*/

#if 0
  sfprintf(fp,"mtaSuccessfulConvertedMessages  %10u\n",
	   M.tasmtp.SuccessfulConvertedMessages);
  sfprintf(fp,"mtaFailedConvertedMessages      %10u\n",
	   M.tasmtp.FailedConvertedMessages);
  sfprintf(fp,"mtaLoopsDetected                %10u\n",
	   M.tasmtp.LoopsDetected);
#endif

  /* SM: */


  sfprintf(fp,"\n");

/*<VAR><HEAD>TA-SMCM.*</HEAD><DESC>
SendMail Compatible Mailer transport agent counters and gauges.
</DESC></VAR>*/


  sfprintf(fp,"TA-SMCM.TaProcessStarts         %10u\n",
	   M.tasmcm.TaProcessStarts);
/*<VAR><NAME>TA-SMCM.TaProcessStarts</NAME><DESC>
Number of times that this transport agent processes type have been
started in this system during this SHM blocks lifetime.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMCM.TaProcCount-G            %9d\n",
	   M.tasmcm.TaProcCountG);
/*<VAR><NAME>TA-SMCM.TaProcCount-G</NAME><DESC>
Gauge of presently running transport agent processes of this type.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMCM.TaIdleStates            %10u\n",
	   M.tasmcm.TaIdleStates);
/*<VAR><NAME>TA-SMCM.TaIdleStates</NAME><DESC>
Number of times this transport agent process type has been placed
into "idle" state by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMCM.TaMessages              %10u\n",
	   M.tasmcm.TaMessages);
/*<VAR><NAME>TA-SMCM.TaMessages</NAME><DESC>
Number of tasks fed to this transport agent process type by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMCM.TaDeliveryStarts        %10u\n",
	   M.tasmcm.TaDeliveryStarts);
/*<VAR><NAME>TA-SMCM.TaDeliveryStarts</NAME><DESC>
Number of times that this transport agent type has started a delivery on
given tasks.  This might be lower count, than TaMessages.
</DESC></VAR>*/

  sfprintf(fp,"TA-SMCM.RcptsOk                 %10u\n",
	   M.tasmcm.TaRcptsOk);
/*<VAR><NAME>TA-SMCM.RcptsOk</NAME><DESC>
Number of recipient addresses that have been diagnosed as successfully processed.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMCM.RcptsRetry              %10u\n",
	   M.tasmcm.TaRcptsRetry);
/*<VAR><NAME>TA-SMCM.RcptsRetry</NAME><DESC>
Number of recipient addresses that have been diagnosed as needing to be retried.
</DESC></VAR>*/
  sfprintf(fp,"TA-SMCM.RcptsFail               %10u\n",
	   M.tasmcm.TaRcptsFail);
/*<VAR><NAME>TA-SMCM.RcptsFail</NAME><DESC>
Number of recipient addresses that have been diagnosed as unsuccessfully processed.
</DESC></VAR>*/





  sfprintf(fp,"\n");

/*<VAR><HEAD>TA-MBOX.*</HEAD><DESC>
MailBOX transport agent  counters and gauges.
</DESC></VAR>*/


  sfprintf(fp,"TA-MBOX.TaProcessStarts         %10u\n",
	   M.tambox.TaProcessStarts);
/*<VAR><NAME>TA-MBOX.TaProcessStarts</NAME><DESC>
Number of times that this transport agent processes type have been
started in this system during this SHM blocks lifetime.
</DESC></VAR>*/
  sfprintf(fp,"TA-MBOX.TaProcCount-G            %9d\n",
	   M.tambox.TaProcCountG);
/*<VAR><NAME>TA-MBOX.TaProcCount-G</NAME><DESC>
Gauge of presently running transport agent processes of this type.
</DESC></VAR>*/
  sfprintf(fp,"TA-MBOX.TaIdleStates            %10u\n",
	   M.tambox.TaIdleStates);
/*<VAR><NAME>TA-MBOX.TaIdleStates</NAME><DESC>
Number of times this transport agent process type has been placed
into "idle" state by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-MBOX.TaMessages              %10u\n",
	   M.tambox.TaMessages);
/*<VAR><NAME>TA-MBOX.TaMessages</NAME><DESC>
Number of tasks fed to this transport agent process type by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-MBOX.TaDeliveryStarts        %10u\n",
	   M.tambox.TaDeliveryStarts);
/*<VAR><NAME>TA-MBOX.TaDeliveryStarts</NAME><DESC>
Number of times that this transport agent type has started a delivery on
given tasks.  This might be lower count, than TaMessages.
</DESC></VAR>*/

  sfprintf(fp,"TA-MBOX.RcptsOk                 %10u\n",
	   M.tambox.TaRcptsOk);
/*<VAR><NAME>TA-MBOX.RcptsOk</NAME><DESC>
Number of recipient addresses that have been diagnosed as successfully processed.
</DESC></VAR>*/
  sfprintf(fp,"TA-MBOX.RcptsRetry              %10u\n",
	   M.tambox.TaRcptsRetry);
/*<VAR><NAME>TA-MBOX.RcptsRetry</NAME><DESC>
Number of recipient addresses that have been diagnosed as needing to be retried.
</DESC></VAR>*/
  sfprintf(fp,"TA-MBOX.RcptsFail               %10u\n",
	   M.tambox.TaRcptsFail);
/*<VAR><NAME>TA-MBOX.RcptsFail</NAME><DESC>
Number of recipient addresses that have been diagnosed as unsuccessfully processed.
</DESC></VAR>*/



  sfprintf(fp,"\n");

/*<VAR><HEAD>TA-HOLD.*</HEAD><DESC>
HOLD transport agent  counters and gauges.
</DESC></VAR>*/

  sfprintf(fp,"TA-HOLD.TaProcessStarts         %10u\n",
	   M.tahold.TaProcessStarts);
/*<VAR><NAME>TA-HOLD.TaProcessStarts</NAME><DESC>
Number of times that this transport agent processes type have been
started in this system during this SHM blocks lifetime.
</DESC></VAR>*/
  sfprintf(fp,"TA-HOLD.TaProcCount-G            %9d\n",
	   M.tahold.TaProcCountG);
/*<VAR><NAME>TA-HOLD.TaProcCount-G</NAME><DESC>
Gauge of presently running transport agent processes of this type.
</DESC></VAR>*/
  sfprintf(fp,"TA-HOLD.TaIdleStates            %10u\n",
	   M.tahold.TaIdleStates);
/*<VAR><NAME>TA-HOLD.TaIdleStates</NAME><DESC>
Number of times this transport agent process type has been placed
into "idle" state by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-HOLD.TaMessages              %10u\n",
	   M.tahold.TaMessages);
/*<VAR><NAME>TA-HOLD.TaMessages</NAME><DESC>
Number of tasks fed to this transport agent process type by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-HOLD.TaDeliveryStarts        %10u\n",
	   M.tahold.TaDeliveryStarts);
/*<VAR><NAME>TA-HOLD.TaDeliveryStarts</NAME><DESC>
Number of times that this transport agent type has started a delivery on
given tasks.  This might be lower count, than TaMessages.
</DESC></VAR>*/

  sfprintf(fp,"TA-HOLD.RcptsOk                 %10u\n",
	   M.tahold.TaRcptsOk);
/*<VAR><NAME>TA-HOLD.RcptsOk</NAME><DESC>
Number of recipient addresses that have been diagnosed as successfully processed.
</DESC></VAR>*/
  sfprintf(fp,"TA-HOLD.RcptsRetry              %10u\n",
	   M.tahold.TaRcptsRetry);
/*<VAR><NAME>TA-HOLD.RcptsRetry</NAME><DESC>
Number of recipient addresses that have been diagnosed as needing to be retried.
</DESC></VAR>*/
  sfprintf(fp,"TA-HOLD.RcptsFail               %10u\n",
	   M.tahold.TaRcptsFail);
/*<VAR><NAME>TA-HOLD.RcptsFail</NAME><DESC>
Number of recipient addresses that have been diagnosed as unsuccessfully processed.
</DESC></VAR>*/



  sfprintf(fp,"\n");

/*<VAR><HEAD>TA-ERRM.*</HEAD><DESC>
ERRorMail transport agent  counters and gauges.
</DESC></VAR>*/

  sfprintf(fp,"TA-ERRM.TaProcessStarts         %10u\n",
	   M.taerrm.TaProcessStarts);
/*<VAR><NAME>TA-ERRM.TaProcessStarts</NAME><DESC>
Number of times that this transport agent processes type have been
started in this system during this SHM blocks lifetime.
</DESC></VAR>*/
  sfprintf(fp,"TA-ERRM.TaProcCount-G            %9d\n",
	   M.taerrm.TaProcCountG);
/*<VAR><NAME>TA-ERRM.TaProcCount-G</NAME><DESC>
Gauge of presently running transport agent processes of this type.
</DESC></VAR>*/
  sfprintf(fp,"TA-ERRM.TaIdleStates            %10u\n",
	   M.taerrm.TaIdleStates);
/*<VAR><NAME>TA-ERRM.TaIdleStates</NAME><DESC>
Number of times this transport agent process type has been placed
into "idle" state by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-ERRM.TaMessages              %10u\n",
	   M.taerrm.TaMessages);
/*<VAR><NAME>TA-ERRM.TaMessages</NAME><DESC>
Number of tasks fed to this transport agent process type by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-ERRM.TaDeliveryStarts        %10u\n",
	   M.taerrm.TaDeliveryStarts);
/*<VAR><NAME>TA-ERRM.TaDeliveryStarts</NAME><DESC>
Number of times that this transport agent type has started a delivery on
given tasks.  This might be lower count, than TaMessages.
</DESC></VAR>*/

  sfprintf(fp,"TA-ERRM.RcptsOk                 %10u\n",
	   M.taerrm.TaRcptsOk);
/*<VAR><NAME>TA-ERRM.RcptsOk</NAME><DESC>
Number of recipient addresses that have been diagnosed as successfully processed.
</DESC></VAR>*/
  sfprintf(fp,"TA-ERRM.RcptsRetry              %10u\n",
	   M.taerrm.TaRcptsRetry);
/*<VAR><NAME>TA-ERRM.RcptsRetry</NAME><DESC>
Number of recipient addresses that have been diagnosed as needing to be retried.
</DESC></VAR>*/
  sfprintf(fp,"TA-ERRM.RcptsFail               %10u\n",
	   M.taerrm.TaRcptsFail);
/*<VAR><NAME>TA-ERRM.RcptsFail</NAME><DESC>
Number of recipient addresses that have been diagnosed as unsuccessfully processed.
</DESC></VAR>*/



  sfprintf(fp,"\n");

/*<VAR><HEAD>TA-EXPI.*</HEAD><DESC>
EXPIrer transport agent  counters and gauges.
</DESC></VAR>*/

  sfprintf(fp,"TA-EXPI.TaProcessStarts         %10u\n",
	   M.taexpi.TaProcessStarts);
/*<VAR><NAME>TA-EXPI.TaProcessStarts</NAME><DESC>
Number of times that this transport agent processes type have been
started in this system during this SHM blocks lifetime.
</DESC></VAR>*/
  sfprintf(fp,"TA-EXPI.TaProcCount-G            %9d\n",
	   M.taexpi.TaProcCountG);
/*<VAR><NAME>TA-EXPI.TaProcCount-G</NAME><DESC>
Gauge of presently running transport agent processes of this type.
</DESC></VAR>*/
  sfprintf(fp,"TA-EXPI.TaIdleStates            %10u\n",
	   M.taexpi.TaIdleStates);
/*<VAR><NAME>TA-EXPI.TaIdleStates</NAME><DESC>
Number of times this transport agent process type has been placed
into "idle" state by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-EXPI.TaMessages              %10u\n",
	   M.taexpi.TaMessages);
/*<VAR><NAME>TA-EXPI.TaMessages</NAME><DESC>
Number of tasks fed to this transport agent process type by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-EXPI.TaDeliveryStarts        %10u\n",
	   M.taexpi.TaDeliveryStarts);
/*<VAR><NAME>TA-EXPI.TaDeliveryStarts</NAME><DESC>
Number of times that this transport agent type has started a delivery on
given tasks.  This might be lower count, than TaMessages.
</DESC></VAR>*/

  sfprintf(fp,"TA-EXPI.RcptsOk                 %10u\n",
	   M.taexpi.TaRcptsOk);
/*<VAR><NAME>TA-EXPI.RcptsOk</NAME><DESC>
Number of recipient addresses that have been diagnosed as successfully processed.
</DESC></VAR>*/
  sfprintf(fp,"TA-EXPI.RcptsRetry              %10u\n",
	   M.taexpi.TaRcptsRetry);
/*<VAR><NAME>TA-EXPI.RcptsRetry</NAME><DESC>
Number of recipient addresses that have been diagnosed as needing to be retried.
</DESC></VAR>*/
  sfprintf(fp,"TA-EXPI.RcptsFail               %10u\n",
	   M.taexpi.TaRcptsFail);
/*<VAR><NAME>TA-EXPI.RcptsFail</NAME><DESC>
Number of recipient addresses that have been diagnosed as unsuccessfully processed.
</DESC></VAR>*/



  sfprintf(fp,"\n");

/*<VAR><HEAD>TA-RERT.*</HEAD><DESC>
RERouTer transport agent  counters and gauges.
</DESC></VAR>*/

  sfprintf(fp,"TA-RERT.TaProcessStarts         %10u\n",
	   M.tarert.TaProcessStarts);
/*<VAR><NAME>TA-RERT.TaProcessStarts</NAME><DESC>
Number of times that this transport agent processes type have been
started in this system during this SHM blocks lifetime.
</DESC></VAR>*/
  sfprintf(fp,"TA-RERT.TaProcCount-G            %9d\n",
	   M.tarert.TaProcCountG);
/*<VAR><NAME>TA-RERT.TaProcCount-G</NAME><DESC>
Gauge of presently running transport agent processes of this type.
</DESC></VAR>*/
  sfprintf(fp,"TA-RERT.TaIdleStates            %10u\n",
	   M.tarert.TaIdleStates);
/*<VAR><NAME>TA-RERT.TaIdleStates</NAME><DESC>
Number of times this transport agent process type has been placed
into "idle" state by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-RERT.TaMessages              %10u\n",
	   M.tarert.TaMessages);
/*<VAR><NAME>TA-RERT.TaMessages</NAME><DESC>
Number of tasks fed to this transport agent process type by the scheduler.
</DESC></VAR>*/
  sfprintf(fp,"TA-RERT.TaDeliveryStarts        %10u\n",
	   M.tarert.TaDeliveryStarts);
/*<VAR><NAME>TA-RERT.TaDeliveryStarts</NAME><DESC>
Number of times that this transport agent type has started a delivery on
given tasks.  This might be lower count, than TaMessages.
</DESC></VAR>*/

  sfprintf(fp,"TA-RERT.RcptsOk                 %10u\n",
	   M.tarert.TaRcptsOk);
/*<VAR><NAME>TA-RERT.RcptsOk</NAME><DESC>
Number of recipient addresses that have been diagnosed as successfully processed.
</DESC></VAR>*/
  sfprintf(fp,"TA-RERT.RcptsRetry              %10u\n",
	   M.tarert.TaRcptsRetry);
/*<VAR><NAME>TA-RERT.RcptsRetry</NAME><DESC>
Number of recipient addresses that have been diagnosed as needing to be retried.
</DESC></VAR>*/
  sfprintf(fp,"TA-RERT.RcptsFail               %10u\n",
	   M.tarert.TaRcptsFail);
/*<VAR><NAME>TA-RERT.RcptsFail</NAME><DESC>
Number of recipient addresses that have been diagnosed as unsuccessfully processed.
</DESC></VAR>*/
