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

  PIDTEST(ts.pid, ts.pid)
  sfprintf(fp,"SC.SchedulerTimeserverPID       %10u",
	   M.ts.pid);
  if (i) sfprintf(fp," NOT PRESENT!");
  sfprintf(fp,"\n");
  sfprintf(fp,"SC.SchedulerTimeserverTime      %10lu\n",
	   (unsigned long)
#ifdef HAVE_SELECT
	   M.ts.tv.tv_sec
#else
	   M.ts.time_sec
#endif
	   );
  sfprintf(fp,"SC.SchedulerTimeserverStarts    %10u\n",
	   M.sc.schedulerTimeserverStarts);
  sfprintf(fp,"SC.SchedulerTimeserverStartTime %10u\n",
	   M.sc.schedulerTimeserverStartTime);

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
	   M.ss.IncomingSMTP_STARTTLS);

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

  sfprintf(fp,"SS.SMTP_STARTTLS                %10u\n",
	   M.ss.IncomingSMTP_STARTTLS);
  sfprintf(fp,"SS.SMTP_STARTTLS_fail           %10u\n",
	   M.ss.IncomingSMTP_STARTTLS_fail);
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


  sfprintf(fp,"SS.Smtp-Opt-ENVID               %10u\n",
	   M.ss.IncomingSMTP_OPT_ENVID);
  sfprintf(fp,"SS.Smtp-Opt-SIZE                %10u\n",
	   M.ss.IncomingSMTP_OPT_SIZE);
  sfprintf(fp,"SS.Smtp-Opt-AUTH                %10u\n",
	   M.ss.IncomingSMTP_OPT_AUTH);
  sfprintf(fp,"SS.Smtp-Opt-DELIVERBY           %10u\n",
	   M.ss.IncomingSMTP_OPT_DELIVERBY);
  sfprintf(fp,"SS.Smtp-Opt-BODY-8BITMIME       %10u\n",
	   M.ss.IncomingSMTP_OPT_BODY_8BITMIME);
  sfprintf(fp,"SS.Smtp-Opt-BODY-BINARYMIME     %10u\n",
	   M.ss.IncomingSMTP_OPT_BODY_BINARYMIME);
  sfprintf(fp,"SS.Smtp-Opt-BODY-7BIT           %10u\n",
	   M.ss.IncomingSMTP_OPT_BODY_7BIT);
  sfprintf(fp,"SS.Smtp-Opt-RETURN              %10u\n",
	   M.ss.IncomingSMTP_OPT_RET);
  sfprintf(fp,"SS.Smtp-Opt-NOTIFY              %10u\n",
	   M.ss.IncomingSMTP_OPT_NOTIFY);
  sfprintf(fp,"SS.Smtp-Opt-ORCPT               %10u\n",
	   M.ss.IncomingSMTP_OPT_ORCPT);

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

