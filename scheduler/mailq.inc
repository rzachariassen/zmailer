/* code fragment used at  mq2.c  and at  mailq.c */

#define M  (*MIBMtaEntry)

  sfprintf(fp,"ZMailer SHM segment dump; Magic=0x%08X\n", M.magic);
  sfprintf(fp,"Time_now                        %10lu\n",
	 (unsigned long)time(NULL));
  sfprintf(fp,"Block_creation_time             %10lu\n",
	 (unsigned long)M.BlockCreationTimestamp);

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
  sfprintf(fp,"SYS.RouterMasterStartTime       %10lu\n",
	   (unsigned long)M.sys.RouterMasterStartTime);
  sfprintf(fp,"SYS.RouterMasterStarts          %10u\n",
	   M.sys.RouterMasterStarts);


  PIDTEST(sys.SchedulerMasterPID, sys.SchedulerMasterStartTime)
  sfprintf(fp,"SYS.SchedulerMasterPID          %10u",
	   M.sys.SchedulerMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
  sfprintf(fp,"SYS.SchedulerMasterStartTime    %10lu\n",
	   (unsigned long)M.sys.SchedulerMasterStartTime);
  sfprintf(fp,"SYS.SchedulerMasterStarts       %10u\n",
	   M.sys.SchedulerMasterStarts);

  PIDTEST(sys.SmtpServerMasterPID, sys.SmtpServerMasterStartTime)
  sfprintf(fp,"SYS.SmtpServerMasterPID         %10u",
	   M.sys.SmtpServerMasterPID);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
  sfprintf(fp,"SYS.SmtpServerMasterStartTime   %10lu\n",
	   (unsigned long)M.sys.SmtpServerMasterStartTime);
  sfprintf(fp,"SYS.SmtpServerMasterStarts      %10u\n",
	   M.sys.SmtpServerMasterStarts);


  sfprintf(fp,"SYS.SpoolFreeSpace-kB-G          %9d\n",
	   M.sys.SpoolFreeSpace);
  sfprintf(fp,"SYS.LogFreeSpace-kB-G            %9d\n",
	   M.sys.LogFreeSpace);


  sfprintf(fp,"\n");

  sfprintf(fp,"SS.Processes-G                        %4d\n",
	   M.ss.IncomingSMTPSERVERprocesses);

  sfprintf(fp,"SS.ParallelSMTPconnects-G             %4d\n",
	   M.ss.IncomingParallelSMTPconnects);
  sfprintf(fp,"SS.ParallelSMTPSconnects-G            %4d\n",
	   M.ss.IncomingParallelSMTPSconnects);
  sfprintf(fp,"SS.ParallelSUBMITconnects-G           %4d\n",
	   M.ss.IncomingParallelSUBMITconnects);

  sfprintf(fp,"SS.ProcessForks                 %10u\n",
	   M.ss.IncomingSMTPSERVERforks);

  sfprintf(fp,"SS.SMTPconnects                 %10u\n",
	   M.ss.IncomingSMTPconnects);
  sfprintf(fp,"SS.SMTPSconnects                %10u\n",
	   M.ss.IncomingSMTPSconnects);
  sfprintf(fp,"SS.SUBMITconnects               %10u\n",
	   M.ss.IncomingSUBMITconnects);
  sfprintf(fp,"SS.SMTPTLSes                    %10u\n",
	   M.ss.IncomingSMTPTLSes);

  sfprintf(fp,"SS.SMTPcommands                 %10u\n",
	   M.ss.IncomingCommands);
  sfprintf(fp,"SS.SMTPcommands-unknown         %10u\n",
	   M.ss.IncomingCommands_unknown);

  sfprintf(fp,"SS.IncomingClientPipelines      %10u\n",
	   M.ss.IncomingClientPipelines);
  sfprintf(fp,"SS.IncomingSmtpTarpits          %10u\n",
	   M.ss.IncomingSmtpTarpits);

  sfprintf(fp,"SS.SMTP_HELO                    %10u\n",
	   M.ss.IncomingSMTP_HELO);
  sfprintf(fp,"SS.SMTP_HELO_ok                 %10u\n",
	   M.ss.IncomingSMTP_HELO_ok);
  sfprintf(fp,"SS.SMTP_HELO_bad                %10u\n",
	   M.ss.IncomingSMTP_HELO_bad);

  sfprintf(fp,"SS.SMTP_EHLO                    %10u\n",
	   M.ss.IncomingSMTP_EHLO);
  sfprintf(fp,"SS.SMTP_EHLO_ok                 %10u\n",
	   M.ss.IncomingSMTP_EHLO_ok);
  sfprintf(fp,"SS.SMTP_EHLO_bad                %10u\n",
	   M.ss.IncomingSMTP_EHLO_bad);

  sfprintf(fp,"SS.SMTP_NOOP                    %10u\n",
	   M.ss.IncomingSMTP_NOOP);
  sfprintf(fp,"SS.SMTP_RSET                    %10u\n",
	   M.ss.IncomingSMTP_RSET);
  sfprintf(fp,"SS.SMTP_HELP                    %10u\n",
	   M.ss.IncomingSMTP_HELP);
  sfprintf(fp,"SS.SMTP_ETRN                    %10u\n",
	   M.ss.IncomingSMTP_ETRN);
  sfprintf(fp,"SS.SMTP_EXPN                    %10u\n",
	   M.ss.IncomingSMTP_EXPN);
  sfprintf(fp,"SS.SMTP_VRFY                    %10u\n",
	   M.ss.IncomingSMTP_VRFY);
  sfprintf(fp,"SS.SMTP_TICK                    %10u\n",
	   M.ss.IncomingSMTP_TICK);
  sfprintf(fp,"SS.SMTP_TURN                    %10u\n",
	   M.ss.IncomingSMTP_TURN);
  sfprintf(fp,"SS.SMTP_VERBOSE                 %10u\n",
	   M.ss.IncomingSMTP_VERBOSE);
  sfprintf(fp,"SS.SMTP_DEBUG                   %10u\n",
	   M.ss.IncomingSMTP_DEBUG);

  sfprintf(fp,"SS.SMTP_MAIL                    %10u\n",
	   M.ss.IncomingSMTP_MAIL);
  sfprintf(fp,"SS.SMTP_MAIL_ok                 %10u\n",
	   M.ss.IncomingSMTP_MAIL_ok);
  sfprintf(fp,"SS.SMTP_MAIL_bad                %10u\n",
	   M.ss.IncomingSMTP_MAIL_bad);

  sfprintf(fp,"SS.SMTP_RCPT                    %10u\n",
	   M.ss.IncomingSMTP_RCPT);
  sfprintf(fp,"SS.SMTP_RCPT_ok                 %10u\n",
	   M.ss.IncomingSMTP_RCPT_ok);
  sfprintf(fp,"SS.SMTP_RCPT_bad                %10u\n",
	   M.ss.IncomingSMTP_RCPT_bad);

  sfprintf(fp,"SS.SMTP_DATA                    %10u\n",
	   M.ss.IncomingSMTP_DATA);
  sfprintf(fp,"SS.SMTP_DATA_ok                 %10u\n",
	   M.ss.IncomingSMTP_DATA_ok);
  sfprintf(fp,"SS.SMTP_DATA_bad                %10u\n",
	   M.ss.IncomingSMTP_DATA_bad);

  sfprintf(fp,"SS.SMTP_BDAT                    %10u\n",
	   M.ss.IncomingSMTP_BDAT);
  sfprintf(fp,"SS.SMTP_BDAT_ok                 %10u\n",
	   M.ss.IncomingSMTP_BDAT_ok);
  sfprintf(fp,"SS.SMTP_BDAT_bad                %10u\n",
	   M.ss.IncomingSMTP_BDAT_bad);

  sfprintf(fp,"SS.SMTP_DATA-kB                 %10u\n",
	   M.ss.IncomingSMTP_DATA_KBYTES);
  sfprintf(fp,"SS.SMTP_BDAT-kB                 %10u\n",
	   M.ss.IncomingSMTP_BDAT_KBYTES);
  sfprintf(fp,"SS.SMTP_input_spool-kB          %10u\n",
	   M.ss.IncomingSMTP_spool_KBYTES);

  sfprintf(fp,"SS.ReceivedMessages             %10u\n",
	   M.ss.ReceivedMessagesSs);
  sfprintf(fp,"SS.ReceivedRecipients           %10u\n",
	   M.ss.ReceivedRecipientsSs);
  sfprintf(fp,"SS.TransmittedMessages          %10u\n",
	   M.ss.TransmittedMessagesSs);
  sfprintf(fp,"SS.TransmittedRecipients        %10u\n",
	   M.ss.TransmittedRecipientsSs);

  sfprintf(fp,"\n");

  sfprintf(fp,"RT.RouterProcesses-G             %9d\n",
	   M.rt.RouterProcessesRt);
  sfprintf(fp,"RT.RouterProcessForks           %10u\n",
	   M.rt.RouterProcessForksRt);

  sfprintf(fp,"RT.ReceivedMessages             %10u\n",
	   M.rt.ReceivedMessagesRt);
  sfprintf(fp,"RT.ReceivedRecipients           %10u\n",
	   M.rt.ReceivedRecipientsRt);
  sfprintf(fp,"RT.TransmittedMessages          %10u\n",
	   M.rt.TransmittedMessagesRt);
  sfprintf(fp,"RT.TransmittedRecipients        %10u\n",
	   M.rt.TransmittedRecipientsRt);

  sfprintf(fp,"RT.ReceivedVolume-kB            %10u\n",
	   M.rt.ReceivedVolumeRt);
  sfprintf(fp,"RT.TransmittedVolume-kB         %10u\n",
	   M.rt.TransmittedVolumeRt);
  sfprintf(fp,"RT.TransmittedVolume2-kB        %10u\n",
	   M.rt.TransmittedVolume2Rt);

  sfprintf(fp,"RT.StoredMessages-G              %9d\n",
	   M.rt.StoredMessagesRt);
  sfprintf(fp,"RT.StoredRecipients-G            %9d\n",
	   M.rt.StoredRecipientsRt);
  sfprintf(fp,"RT.StoredVolume-kB-G             %9d\n",
	   M.rt.StoredVolumeRt);

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

  sfprintf(fp,"TA.OutgoingSmtpTAprocesses      %10u\n",
	   M.tas.OutgoingSmtpTAprocesses);
  sfprintf(fp,"TA.OutgoingSmtpTAprocCount-G    %10u\n",
	   M.tas.OutgoingSmtpTAprocCountG);


  sfprintf(fp,"TA.OutgoingSmtpStarts           %10u\n",
	   M.tas.OutgoingSmtpStarts);
  sfprintf(fp,"TA.OutgoingLmtpConnects         %10u\n",
	   M.tas.OutgoingLmtpConnects);
  sfprintf(fp,"TA.OutgoingSmtpConnects         %10u\n",
	   M.tas.OutgoingSmtpConnects);
  sfprintf(fp,"TA.OutgoingSmtpConnectFails     %10u\n",
	   M.tas.OutgoingSmtpConnectFails);
  sfprintf(fp,"TA.OutgoingSmtpConnectsCnt-G     %9d\n",
	   M.tas.OutgoingSmtpConnectsCnt);

  sfprintf(fp,"TA.OutgoingSmtpPIPELINING       %10u\n",
	   M.tas.OutgoingSmtpPIPELINING);

  sfprintf(fp,"TA.OutgoingSmtpSTARTTLS         %10u\n",
	   M.tas.OutgoingSmtpSTARTTLS);
  sfprintf(fp,"TA.OutgoingSmtpSTARTTLSok       %10u\n",
	   M.tas.OutgoingSmtpSTARTTLSok);
  sfprintf(fp,"TA.OutgoingSmtpSTARTTLSfail     %10u\n",
	   M.tas.OutgoingSmtpSTARTTLSfail);

  sfprintf(fp,"TA.OutgoingSmtpEHLO             %10u\n",
	   M.tas.OutgoingSmtpEHLO);
  sfprintf(fp,"TA.OutgoingSmtpEHLOok           %10u\n",
	   M.tas.OutgoingSmtpEHLOok);
  sfprintf(fp,"TA.OutgoingSmtpEHLOfail         %10u\n",
	   M.tas.OutgoingSmtpEHLOfail);
  sfprintf(fp,"TA.OutgoingSmtpHELO             %10u\n",
	   M.tas.OutgoingSmtpHELO);
  sfprintf(fp,"TA.OutgoingSmtpHELOok           %10u\n",
	   M.tas.OutgoingSmtpHELOok);
  sfprintf(fp,"TA.OutgoingSmtpHELOfail         %10u\n",
	   M.tas.OutgoingSmtpHELOfail);
  sfprintf(fp,"TA.OutgoingSmtpLHLO             %10u\n",
	   M.tas.OutgoingSmtpLHLO);
  sfprintf(fp,"TA.OutgoingSmtpLHLOok           %10u\n",
	   M.tas.OutgoingSmtpLHLOok);
  sfprintf(fp,"TA.OutgoingSmtpLHLOfail         %10u\n",
	   M.tas.OutgoingSmtpLHLOfail);

  sfprintf(fp,"TA.OutgoingSmtpMAIL             %10u\n",
	   M.tas.OutgoingSmtpMAIL);
  sfprintf(fp,"TA.OutgoingSmtpMAILok           %10u\n",
	   M.tas.OutgoingSmtpMAILok);

  sfprintf(fp,"TA.OutgoingSmtpRCPT             %10u\n",
	   M.tas.OutgoingSmtpRCPT);
  sfprintf(fp,"TA.OutgoingSmtpRCPTok           %10u\n",
	   M.tas.OutgoingSmtpRCPTok);

  sfprintf(fp,"TA.OutgoingSmtpDATA             %10u\n",
	   M.tas.OutgoingSmtpDATA);
  sfprintf(fp,"TA.OutgoingSmtpDATAok           %10u\n",
	   M.tas.OutgoingSmtpDATAok);

  sfprintf(fp,"TA.OutgoingSmtpBDAT             %10u\n",
	   M.tas.OutgoingSmtpBDAT);
  sfprintf(fp,"TA.OutgoingSmtpBDATok           %10u\n",
	   M.tas.OutgoingSmtpBDATok);

  sfprintf(fp,"TA.OutgoingSmtpDATAvolume-kB    %10u\n",
	   M.tas.OutgoingSmtpDATAvolume);
  sfprintf(fp,"TA.OutgoingSmtpBDATvolume-kB    %10u\n",
	   M.tas.OutgoingSmtpBDATvolume);

  sfprintf(fp,"TA.OutgoingSmtpRcptsOk          %10u\n",
	   M.tas.OutgoingSmtpRcptsOk);
  sfprintf(fp,"TA.OutgoingSmtpRcptsRetry       %10u\n",
	   M.tas.OutgoingSmtpRcptsRetry);
  sfprintf(fp,"TA.OutgoingSmtpRcptsFail        %10u\n",
	   M.tas.OutgoingSmtpRcptsFail);


#if 0
  sfprintf(fp,"mtaSuccessfulConvertedMessages  %10u\n",
	   M.tas.SuccessfulConvertedMessages);
  sfprintf(fp,"mtaFailedConvertedMessages      %10u\n",
	   M.tas.FailedConvertedMessages);
  sfprintf(fp,"mtaLoopsDetected                %10u\n",
	   M.tas.LoopsDetected);
#endif
