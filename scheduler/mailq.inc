/* code fragment used at  mq2.c  and at  mailq.c */

/*
 * NOTE:  HERE ARE INLINED SPECIAL COMMENTS THAT ARE USED WHEN
 *        GENERATING  mailq-m(5)  MAN-PAGE, AND (IN FUTURE) RELEVANT
 *        PART OF THE ZMAILER MANUAL
 *
 */

#define M  (*MIBMtaEntry)

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

  sfprintf(fp,"\n");


#define PIDTEST(varname, var2)  \
  i = (M.varname != 0 &&				\
       (kill(M.varname, 0) < 0 && errno == ESRCH));	\
  if (i && r) M.varname = M.var2 = i = 0;

  PIDTEST(sys.RouterMasterPID, sys.RouterMasterStartTime)
  sfprintf(fp,"SYS.RouterMasterPID             %10u",
	   M.sys.RouterMasterPID);
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
	   M.sys.SchedulerMasterPID);
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
	   M.sys.SmtpServerMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
/*<VAR><NAME>SC.SmtpServerMasterPID</NAME><DESC>
PID of SMTP-server's master instance.
This process does listen(2) on defined inbound sockets,
and forks actual receiver instances.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SmtpServerMasterStartTime   %10lu\n",
	   (unsigned long)M.sys.SmtpServerMasterStartTime);
/*<VAR><NAME>SC.SmtpServerMasterStartTime</NAME><DESC>
When the SMTP-server's master instance was started the lattest time.
</DESC></VAR>*/
  sfprintf(fp,"SYS.SmtpServerMasterStarts      %10u\n",
	   M.sys.SmtpServerMasterStarts);
/*<VAR><NAME>SC.SmtpServerMasterStarts</NAME><DESC>
How many times the SMTP-server's master instance has been started
during the existence of this SHM segment.
</DESC></VAR>*/


  sfprintf(fp,"SYS.SpoolFreeSpace-kB-G          %9d\n",
	   M.sys.SpoolFreeSpace);
/*<VAR><NAME>SYS.SpoolFreeSpace-kB-G</NAME><DESC>
Amount of free POSTOFFICE filesystem space in the system in kilobytes.

Depending upon the implementation, this may max out at 2 GB
(divided by 1024, e.g. yields a bit over 2 million), but
actual spool space alarms are to be done when this space
gets way below that 2 gigs...
</DESC></VAR>*/
  sfprintf(fp,"SYS.LogFreeSpace-kB-G            %9d\n",
	   M.sys.LogFreeSpace);
/*<VAR><NAME>SYS.LogFreeSpace-kB-G</NAME><DESC>
Amount of free LOGDIR filesystem space in the system in kilobytes.

Depending upon the implementation, this may max out at 2 GB
(divided by 1024, e.g. yields a bit over 2 million), but
actual spool space alarms are to be done when this space
gets way below that 2 gigs...
</DESC></VAR>*/


  sfprintf(fp,"\n");

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
than the global "PARAM MaxParallelConnections" parameter as been configured
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
see this count keep counting up, while the router process count
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
  sfprintf(fp,"RT.StoredRecipients-G            %9d\n",
	   M.rt.StoredRecipients);
/*<VAR><NAME>RT.StoredRecipients-G</NAME><DESC>
Actually a non-managed counter.

To know the number of recipients in the first place, the message
must be scanned thru, which is a task for actual processing, which
is when message gets kicked onwards from the routing queue...
</DESC></VAR>*/
  sfprintf(fp,"RT.StoredVolume-kB-G             %9d\n",
	   M.rt.StoredVolume);
/*<VAR><NAME>RT.StoredVolume-kB-G</NAME><DESC>
Total size of messages in router input queue.
(The usual round up to next kilobyte...)
</DESC></VAR>*/

  sfprintf(fp,"\n");

  sfprintf(fp,"SC.ReceivedMessages             %10u\n",
	   M.sc.ReceivedMessagesSc);
  sfprintf(fp,"SC.ReceivedRecipients           %10u\n",
	   M.sc.ReceivedRecipientsSc);
  sfprintf(fp,"SC.TransmittedMessages          %10u\n",
	   M.sc.TransmittedMessagesSc);
  sfprintf(fp,"SC.TransmittedRecipients        %10u\n",
	   M.sc.TransmittedRecipientsSc);

  sfprintf(fp,"SC.StoredMessages-G              %9d\n",
	   M.sc.StoredMessagesSc);
  sfprintf(fp,"SC.StoredThreads-G               %9d\n",
	   M.sc.StoredThreadsSc);
  sfprintf(fp,"SC.StoredVertices-G              %9d\n",
	   M.sc.StoredVerticesSc);
  sfprintf(fp,"SC.StoredRecipients-G            %9d\n",
	   M.sc.StoredRecipientsSc);

  sfprintf(fp,"SC.ReceivedVolume-kB            %10u\n",
	   M.sc.ReceivedVolumeSc);
  sfprintf(fp,"SC.StoredVolume-kB-G             %9d\n",
	   M.sc.StoredVolumeSc);
  sfprintf(fp,"SC.TransmittedVolume-kB         %10u\n",
	   M.sc.TransmittedVolumeSc);

  sfprintf(fp,"SC.TransportAgentForks          %10u\n",
	   M.sc.TransportAgentForksSc);
  sfprintf(fp,"SC.TransportAgentProcesses-G     %9d\n",
	   M.sc.TransportAgentProcessesSc);
  sfprintf(fp,"SC.TransportAgentsActive-G       %9d\n",
	   M.sc.TransportAgentsActiveSc);
  sfprintf(fp,"SC.TransportAgentsIdle-G         %9d\n",
	   M.sc.TransportAgentsIdleSc);

  sfprintf(fp,"SC.MQ2Parallel-G                 %9d\n",
	   M.sc.MQ2sockParallel);
  sfprintf(fp,"SC.MQ2Connects                  %10u\n",
	   M.sc.MQ2sockConnects);
  sfprintf(fp,"SC.MQ2TcpWrapRej                %10u\n",
	   M.sc.MQ2sockTcpWrapRej);
  sfprintf(fp,"SC.MQ2AuthRej                   %10u\n",
	   M.sc.MQ2sockAuthRej);
  sfprintf(fp,"SC.MQ2TimedOut                  %10u\n",
	   M.sc.MQ2sockTimedOut);
  sfprintf(fp,"SC.MQ2ReadEOF                   %10u\n",
	   M.sc.MQ2sockReadEOF);
  sfprintf(fp,"SC.MQ2ReadFails                 %10u\n",
	   M.sc.MQ2sockReadFails);
  sfprintf(fp,"SC.MQ2WriteFails                %10u\n",
	   M.sc.MQ2sockWriteFails);
  sfprintf(fp,"SC.MQ2Commands                  %10u\n",
	   M.sc.MQ2sockCommands);
  sfprintf(fp,"SC.MQ2CommandsRej               %10u\n",
	   M.sc.MQ2sockCommandsRej);
  sfprintf(fp,"SC.MQ2CommandAUTH               %10u\n",
	   M.sc.MQ2sockCommandAUTH);
  sfprintf(fp,"SC.MQ2CommandQUIT               %10u\n",
	   M.sc.MQ2sockCommandQUIT);
  sfprintf(fp,"SC.MQ2CommandETRN               %10u\n",
	   M.sc.MQ2sockCommandETRN);
  sfprintf(fp,"SC.MQ2CommandKillThr            %10u\n",
	   M.sc.MQ2sockCommandKillThr);
  sfprintf(fp,"SC.MQ2CommandKillMsg            %10u\n",
	   M.sc.MQ2sockCommandKillMsg);
  sfprintf(fp,"SC.MQ2CommandKillProcess        %10u\n",
	   M.sc.MQ2sockCommandKillProcess);
  sfprintf(fp,"SC.MQ2CommandRerouteThr         %10u\n",
	   M.sc.MQ2sockCommandRerouteThr);
  sfprintf(fp,"SC.MQ2CommandRerouteMsg         %10u\n",
	   M.sc.MQ2sockCommandRerouteMsg);
  sfprintf(fp,"SC.MQ2CommandShowQueueThreads   %10u\n",
	   M.sc.MQ2sockCommandShowQueueThreads);
  sfprintf(fp,"SC.MQ2CommandShowQueueThreads2  %10u\n",
	   M.sc.MQ2sockCommandShowQueueThreads2);
  sfprintf(fp,"SC.MQ2CommandShowQueueShort     %10u\n",
	   M.sc.MQ2sockCommandShowQueueShort);
  sfprintf(fp,"SC.MQ2CommandShowQueueVeryShort %10u\n",
	   M.sc.MQ2sockCommandShowQueueVeryShort);
  sfprintf(fp,"SC.MQ2CommandShowThread         %10u\n",
	   M.sc.MQ2sockCommandShowThread);
  sfprintf(fp,"SC.MQ2CommandShowCounters       %10u\n",
	   M.sc.MQ2sockCommandShowCounters);


  sfprintf(fp,"\n");

  sfprintf(fp,"TA-SMTP.TaProcessStarts         %10u\n",
	   M.tasmtp.TaProcessStarts);
  sfprintf(fp,"TA-SMTP.TaProcCount-G            %9d\n",
	   M.tasmtp.TaProcCountG);
  sfprintf(fp,"TA-SMTP.TaIdleStates            %10u\n",
	   M.tasmtp.TaIdleStates);
  sfprintf(fp,"TA-SMTP.TaMessages              %10u\n",
	   M.tasmtp.TaMessages);
  sfprintf(fp,"TA-SMTP.TaDeliveryStarts        %10u\n",
	   M.tasmtp.TaDeliveryStarts);


  sfprintf(fp,"TA-SMTP.SmtpStarts              %10u\n",
	   M.tasmtp.SmtpStarts);
  sfprintf(fp,"TA-SMTP.LmtpConnects            %10u\n",
	   M.tasmtp.LmtpConnects);
  sfprintf(fp,"TA-SMTP.SmtpConnects            %10u\n",
	   M.tasmtp.SmtpConnects);
  sfprintf(fp,"TA-SMTP.SmtpConnectFails        %10u\n",
	   M.tasmtp.SmtpConnectFails);
  sfprintf(fp,"TA-SMTP.SmtpConnectsCnt-G        %9d\n",
	   M.tasmtp.SmtpConnectsCnt);

  sfprintf(fp,"TA-SMTP.SmtpPIPELINING          %10u\n",
	   M.tasmtp.SmtpPIPELINING);

  sfprintf(fp,"TA-SMTP.SmtpSTARTTLS            %10u\n",
	   M.tasmtp.SmtpSTARTTLS);
  sfprintf(fp,"TA-SMTP.SmtpSTARTTLSok          %10u\n",
	   M.tasmtp.SmtpSTARTTLSok);
  sfprintf(fp,"TA-SMTP.SmtpSTARTTLSfail        %10u\n",
	   M.tasmtp.SmtpSTARTTLSfail);

  sfprintf(fp,"TA-SMTP.SmtpEHLO                %10u\n",
	   M.tasmtp.SmtpEHLO);
  sfprintf(fp,"TA-SMTP.SmtpEHLOok              %10u\n",
	   M.tasmtp.SmtpEHLOok);
  sfprintf(fp,"TA-SMTP.SmtpEHLOfail            %10u\n",
	   M.tasmtp.SmtpEHLOfail);
  sfprintf(fp,"TA-SMTP.SmtpHELO                %10u\n",
	   M.tasmtp.SmtpHELO);
  sfprintf(fp,"TA-SMTP.SmtpHELOok              %10u\n",
	   M.tasmtp.SmtpHELOok);
  sfprintf(fp,"TA-SMTP.SmtpHELOfail            %10u\n",
	   M.tasmtp.SmtpHELOfail);
  sfprintf(fp,"TA-SMTP.SmtpLHLO                %10u\n",
	   M.tasmtp.SmtpLHLO);
  sfprintf(fp,"TA-SMTP.SmtpLHLOok              %10u\n",
	   M.tasmtp.SmtpLHLOok);
  sfprintf(fp,"TA-SMTP.SmtpLHLOfail            %10u\n",
	   M.tasmtp.SmtpLHLOfail);

  sfprintf(fp,"TA-SMTP.capa8BITMIME            %10u\n",
	  M.tasmtp.EHLOcapability8BITMIME);
  sfprintf(fp,"TA-SMTP.capaAUTH                %10u\n",
	  M.tasmtp.EHLOcapabilityAUTH);
  sfprintf(fp,"TA-SMTP.capaDSN                 %10u\n",
	  M.tasmtp.EHLOcapabilityDSN);
  sfprintf(fp,"TA-SMTP.capaCHUNKING            %10u\n",
	  M.tasmtp.EHLOcapabilityCHUNKING);
  sfprintf(fp,"TA-SMTP.capaDELIVERBY           %10u\n",
	  M.tasmtp.EHLOcapabilityDELIVERBY);
  sfprintf(fp,"TA-SMTP.capaENHANCEDSTATUSCODES %10u\n",
	  M.tasmtp.EHLOcapabilityENHANCEDSTATUSCODES);
  sfprintf(fp,"TA-SMTP.capaPIPELINING          %10u\n",
	  M.tasmtp.EHLOcapabilityPIPELINING);
  sfprintf(fp,"TA-SMTP.capaSIZE                %10u\n",
	  M.tasmtp.EHLOcapabilitySIZE);
  sfprintf(fp,"TA-SMTP.capaSTARTTLS            %10u\n",
	  M.tasmtp.EHLOcapabilitySTARTTLS);

  sfprintf(fp,"TA-SMTP.sent-option-ENVID       %10u\n",
	   M.tasmtp.SmtpOPT_ENVID);
  sfprintf(fp,"TA-SMTP.sent-option-SIZE        %10u\n",
	   M.tasmtp.SmtpOPT_SIZE);
  sfprintf(fp,"TA-SMTP.sent-option-RET         %10u\n",
	   M.tasmtp.SmtpOPT_RET);
  sfprintf(fp,"TA-SMTP.sent-option-NOTIFY      %10u\n",
	   M.tasmtp.SmtpOPT_NOTIFY);
  sfprintf(fp,"TA-SMTP.sent-option-ORCPT       %10u\n",
	   M.tasmtp.SmtpOPT_ORCPT);

  sfprintf(fp,"TA-SMTP.SmtpMAIL                %10u\n",
	   M.tasmtp.SmtpMAIL);
  sfprintf(fp,"TA-SMTP.SmtpMAILok              %10u\n",
	   M.tasmtp.SmtpMAILok);

  sfprintf(fp,"TA-SMTP.SmtpRCPT                %10u\n",
	   M.tasmtp.SmtpRCPT);
  sfprintf(fp,"TA-SMTP.SmtpRCPTok              %10u\n",
	   M.tasmtp.SmtpRCPTok);

  sfprintf(fp,"TA-SMTP.SmtpDATA                %10u\n",
	   M.tasmtp.SmtpDATA);
  sfprintf(fp,"TA-SMTP.SmtpDATAok              %10u\n",
	   M.tasmtp.SmtpDATAok);

  sfprintf(fp,"TA-SMTP.SmtpBDAT                %10u\n",
	   M.tasmtp.SmtpBDAT);
  sfprintf(fp,"TA-SMTP.SmtpBDATok              %10u\n",
	   M.tasmtp.SmtpBDATok);

  sfprintf(fp,"TA-SMTP.SmtpDATAvolume-kB       %10u\n",
	   M.tasmtp.SmtpDATAvolume);
  sfprintf(fp,"TA-SMTP.SmtpBDATvolume-kB       %10u\n",
	   M.tasmtp.SmtpBDATvolume);

  sfprintf(fp,"TA-SMTP.RcptsOk                 %10u\n",
	   M.tasmtp.TaRcptsOk);
  sfprintf(fp,"TA-SMTP.RcptsRetry              %10u\n",
	   M.tasmtp.TaRcptsRetry);
  sfprintf(fp,"TA-SMTP.RcptsFail               %10u\n",
	   M.tasmtp.TaRcptsFail);


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

  sfprintf(fp,"TA-SMCM.TaProcessStarts         %10u\n",
	   M.tasmcm.TaProcessStarts);
  sfprintf(fp,"TA-SMCM.TaProcCount-G            %9d\n",
	   M.tasmcm.TaProcCountG);
  sfprintf(fp,"TA-SMCM.TaIdleStates            %10u\n",
	   M.tasmcm.TaIdleStates);
  sfprintf(fp,"TA-SMCM.TaMessages              %10u\n",
	   M.tasmcm.TaMessages);
  sfprintf(fp,"TA-SMCM.TaDeliveryStarts        %10u\n",
	   M.tasmcm.TaDeliveryStarts);

  sfprintf(fp,"TA-SMCM.RcptsOk                 %10u\n",
	   M.tasmcm.TaRcptsOk);
  sfprintf(fp,"TA-SMCM.RcptsRetry              %10u\n",
	   M.tasmcm.TaRcptsRetry);
  sfprintf(fp,"TA-SMCM.RcptsFail               %10u\n",
	   M.tasmcm.TaRcptsFail);





  sfprintf(fp,"\n");

  sfprintf(fp,"TA-MBOX.TaProcessStarts         %10u\n",
	   M.tambox.TaProcessStarts);
  sfprintf(fp,"TA-MBOX.TaProcCount-G            %9d\n",
	   M.tambox.TaProcCountG);
  sfprintf(fp,"TA-MBOX.TaIdleStates            %10u\n",
	   M.tambox.TaIdleStates);
  sfprintf(fp,"TA-MBOX.TaMessages              %10u\n",
	   M.tambox.TaMessages);
  sfprintf(fp,"TA-MBOX.TaDeliveryStarts        %10u\n",
	   M.tambox.TaDeliveryStarts);

  sfprintf(fp,"TA-MBOX.RcptsOk                 %10u\n",
	   M.tambox.TaRcptsOk);
  sfprintf(fp,"TA-MBOX.RcptsRetry              %10u\n",
	   M.tambox.TaRcptsRetry);
  sfprintf(fp,"TA-MBOX.RcptsFail               %10u\n",
	   M.tambox.TaRcptsFail);



  sfprintf(fp,"\n");

  sfprintf(fp,"TA-HOLD.TaProcessStarts         %10u\n",
	   M.tahold.TaProcessStarts);
  sfprintf(fp,"TA-HOLD.TaProcCount-G            %9d\n",
	   M.tahold.TaProcCountG);
  sfprintf(fp,"TA-HOLD.TaIdleStates            %10u\n",
	   M.tahold.TaIdleStates);
  sfprintf(fp,"TA-HOLD.TaMessages              %10u\n",
	   M.tahold.TaMessages);
  sfprintf(fp,"TA-HOLD.TaDeliveryStarts        %10u\n",
	   M.tahold.TaDeliveryStarts);

  sfprintf(fp,"TA-HOLD.RcptsOk                 %10u\n",
	   M.tahold.TaRcptsOk);
  sfprintf(fp,"TA-HOLD.RcptsRetry              %10u\n",
	   M.tahold.TaRcptsRetry);
  sfprintf(fp,"TA-HOLD.RcptsFail               %10u\n",
	   M.tahold.TaRcptsFail);



  sfprintf(fp,"\n");

  sfprintf(fp,"TA-ERRM.TaProcessStarts         %10u\n",
	   M.taerrm.TaProcessStarts);
  sfprintf(fp,"TA-ERRM.TaProcCount-G            %9d\n",
	   M.taerrm.TaProcCountG);
  sfprintf(fp,"TA-ERRM.TaIdleStates            %10u\n",
	   M.taerrm.TaIdleStates);
  sfprintf(fp,"TA-ERRM.TaMessages              %10u\n",
	   M.taerrm.TaMessages);
  sfprintf(fp,"TA-ERRM.TaDeliveryStarts        %10u\n",
	   M.taerrm.TaDeliveryStarts);

  sfprintf(fp,"TA-ERRM.RcptsOk                 %10u\n",
	   M.taerrm.TaRcptsOk);
  sfprintf(fp,"TA-ERRM.RcptsRetry              %10u\n",
	   M.taerrm.TaRcptsRetry);
  sfprintf(fp,"TA-ERRM.RcptsFail               %10u\n",
	   M.taerrm.TaRcptsFail);



  sfprintf(fp,"\n");

  sfprintf(fp,"TA-EXPI.TaProcessStarts         %10u\n",
	   M.taexpi.TaProcessStarts);
  sfprintf(fp,"TA-EXPI.TaProcCount-G            %9d\n",
	   M.taexpi.TaProcCountG);
  sfprintf(fp,"TA-EXPI.TaIdleStates            %10u\n",
	   M.taexpi.TaIdleStates);
  sfprintf(fp,"TA-EXPI.TaMessages              %10u\n",
	   M.taexpi.TaMessages);
  sfprintf(fp,"TA-EXPI.TaDeliveryStarts        %10u\n",
	   M.taexpi.TaDeliveryStarts);

  sfprintf(fp,"TA-EXPI.RcptsOk                 %10u\n",
	   M.taexpi.TaRcptsOk);
  sfprintf(fp,"TA-EXPI.RcptsRetry              %10u\n",
	   M.taexpi.TaRcptsRetry);
  sfprintf(fp,"TA-EXPI.RcptsFail               %10u\n",
	   M.taexpi.TaRcptsFail);



  sfprintf(fp,"\n");

  sfprintf(fp,"TA-RERT.TaProcessStarts         %10u\n",
	   M.tarert.TaProcessStarts);
  sfprintf(fp,"TA-RERT.TaProcCount-G            %9d\n",
	   M.tarert.TaProcCountG);
  sfprintf(fp,"TA-RERT.TaIdleStates            %10u\n",
	   M.tarert.TaIdleStates);
  sfprintf(fp,"TA-RERT.TaMessages              %10u\n",
	   M.tarert.TaMessages);
  sfprintf(fp,"TA-RERT.TaDeliveryStarts        %10u\n",
	   M.tarert.TaDeliveryStarts);

  sfprintf(fp,"TA-RERT.RcptsOk                 %10u\n",
	   M.tarert.TaRcptsOk);
  sfprintf(fp,"TA-RERT.RcptsRetry              %10u\n",
	   M.tarert.TaRcptsRetry);
  sfprintf(fp,"TA-RERT.RcptsFail               %10u\n",
	   M.tarert.TaRcptsFail);


/*
<VAR><NAME>TO BE WRITTEN</NAME><DESC>
There are lots and lots more variables to describe...
</DESC></VAR>
*/
