/*
 * ZMailer 2.99.X global variables stored on shared read/write
 * SysV-SHM memory segment on those platforms that support it.
 *
 * These are used for storing counters/gauges for Mail Monitoring MIB
 * (RFC 2249) to such a extent as is relatively easily possible to do.
 *
 * Copyright Matti Aarnio <mea@nic.funet.fi> 1998, 2003
 *
 */

#define ZM_MIB_MAGIC 0x33120004

struct timeserver {
	int	pid;
#ifdef HAVE_SELECT
	struct timeval tv;
#else
	time_t	time_sec;
#endif
};


struct MIB_MtaEntrySys {

  pid_t		RouterMasterPID;
  time_t	RouterMasterStartTime;
  uint		RouterMasterStarts;

  pid_t		SchedulerMasterPID;
  time_t	SchedulerMasterStartTime;
  uint		SchedulerMasterStarts;

  pid_t		SmtpServerMasterPID;
  time_t	SmtpServerMasterStartTime;
  uint		SmtpServerMasterStarts;

  double dummy1; /* cache-line alignment, etc.. */

  /* SpoolFree  is monitored and stored by _XX_ subsystem ?  
     Router and scheduler ?  Smtpserver ?  All three ? */

  uint		SpoolFreeSpace;		/* gauge,	in MB	*/
  uint		LogFreeSpace;		/* gauge,	in MB  ?? */
};

struct MIB_MtaEntrySs {

  /* SMTPSERVER substystem counters */

  uint		IncomingSMTPSERVERprocesses;  /* gauges */
  uint		IncomingParallelSMTPconnects;
  uint		IncomingParallelSMTPSconnects;
  uint		IncomingParallelSUBMITconnects;

  uint		IncomingSMTPSERVERforks;

  uint		IncomingSMTPconnects;	/* Incoming SMTP sessions */
  uint		IncomingSMTPSconnects;	/* Incoming SMTPS sessions */
  uint		IncomingSUBMITconnects;	/* Incoming SUBMIT sessions */

  uint		IncomingSMTPTLSes;	/* Number of STARTTLSes */

  uint		IncomingCommands;	/* counters */
  uint		IncomingCommands_unknown;

  uint		IncomingSMTP_HELO;
  uint		IncomingSMTP_HELO_ok;
  uint		IncomingSMTP_HELO_bad;

  uint		IncomingSMTP_EHLO;
  uint		IncomingSMTP_EHLO_ok;
  uint		IncomingSMTP_EHLO_bad;

  uint		IncomingSMTP_ETRN;
  uint		IncomingSMTP_ETRN_ok;
  uint		IncomingSMTP_ETRN_bad;

  uint		IncomingSMTP_HELP;

  uint		IncomingSMTP_EXPN;
  uint		IncomingSMTP_VRFY;
  uint		IncomingSMTP_RSET;

  uint		IncomingSMTP_MAIL;
  uint		IncomingSMTP_MAIL_ok;
  uint		IncomingSMTP_MAIL_bad;

  uint		IncomingSMTP_RCPT;
  uint		IncomingSMTP_RCPT_ok;
  uint		IncomingSMTP_RCPT_bad;

  uint		IncomingSMTP_DATA;
  uint		IncomingSMTP_DATA_ok;
  uint		IncomingSMTP_DATA_bad;
  uint		IncomingSMTP_BDAT;
  uint		IncomingSMTP_BDAT_ok;
  uint		IncomingSMTP_BDAT_bad;

  uint		IncomingSMTP_DATA_KBYTES;
  uint		IncomingSMTP_BDAT_KBYTES;
  uint		IncomingSMTP_spool_KBYTES;


  double dummy3; /* Alignment, etc.. */

  uint		ReceivedMessagesSs;	/* counter, smtpserver	*/
  uint		ReceivedRecipientsSs;	/* counter, smtpserver	*/
  uint		TransmittedMessagesSs;	/* counter, smtpserver	*/
  uint		TransmittedRecipientsSs;/* counter, smtpserver	*/

  uint		IncomingSMTP_TURN;
  uint		IncomingSMTP_NOOP;
  uint		IncomingSMTP_VERBOSE;
  uint		IncomingSMTP_DEBUG;
  uint		IncomingSMTP_TICK;
  uint		IncomingSMTP_QUIT;

  uint		IncomingClientPipelines;
  uint		IncomingSmtpTarpits;

  uint	space[24]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntryRt {
  /* ROUTER subsystem counters */

  uint		RouterProcessesRt;	/* gauge */
  uint		RouterProcessForksRt;	/* counter, cleared at start */

  uint		ReceivedMessagesRt;	/* counter, router	*/
  uint		ReceivedRecipientsRt;	/* counter, router - not! */
  uint		TransmittedMessagesRt;	/* counter, router	*/
  uint		TransmittedRecipientsRt;/* counter, router	*/

  uint		ReceivedVolumeRt;	/* counter,	in kB	*/
  uint		TransmittedVolumeRt;	/* counter,	in kB	*/
  uint		TransmittedVolume2Rt;	/* counter,	in kB	*/

  /* Subsystem queue size  */
  uint		StoredMessagesRt;	/* gauge, router	*/
  uint		StoredRecipientsRt;	/* gauge, router - not!	*/

  uint		StoredVolumeRt;		/* gauge,	in kB	*/

  uint	space[32]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntrySc {
  /* SCHEDULER subsystem counters */

  uint		ReceivedMessagesSc;	/* counter, scheduler	*/
  uint		ReceivedRecipientsSc;	/* counter, scheduler	*/
  uint		TransmittedMessagesSc;	/* counter, scheduler	*/
  uint		TransmittedRecipientsSc;/* counter, scheduler	*/

  uint		StoredMessagesSc;	/* gauge, scheduler	*/
  uint		StoredThreadsSc;	/* gauge, scheduler	*/
  uint		StoredVerticesSc;	/* gauge, scheduler	*/
  uint		StoredRecipientsSc;	/* gauge, scheduler	*/

  uint		ReceivedVolumeSc;	/* counter,	in kB	*/
  uint		StoredVolumeSc;		/* gauge,	in kB	*/
  uint		TransmittedVolumeSc;	/* counter, ??	in kB	*/

  uint		TransportAgentForksSc;	/* counter		*/
  uint		TransportAgentProcessesSc;/* gauge		*/
  uint		TransportAgentsActiveSc;/* gauge		*/
  uint		TransportAgentsIdleSc;	/* gauge		*/

  /* MQ1 socket */
  uint		MQ1sockConnects;	/* counter */
  uint		MQ1sockParallel;	/* gauge */
  uint		MQ1sockTcpWrapRej;	/* counter */
  
  /* MQ2 socket */

  uint		MQ2sockConnects;	/* counter */
  uint		MQ2sockParallel;	/* gauge   */
  uint		MQ2sockTcpWrapRej;
  uint		MQ2sockAuthRej;
  uint		MQ2sockTimedOut;
  uint		MQ2sockReadEOF;
  uint		MQ2sockReadFails;
  uint		MQ2sockWriteFails;
  uint		MQ2sockCommands;
  uint		MQ2sockCommandsRej;
  uint		MQ2sockCommandAUTH;
  uint		MQ2sockCommandQUIT;
  uint		MQ2sockCommandETRN;
  uint		MQ2sockCommandKillThr;
  uint		MQ2sockCommandKillMsg;
  uint		MQ2sockCommandKillProcess;
  uint		MQ2sockCommandRerouteThr;
  uint		MQ2sockCommandRerouteMsg;
  uint		MQ2sockCommandShowQueueThreads;
  uint		MQ2sockCommandShowQueueThreads2;
  uint		MQ2sockCommandShowQueueShort;
  uint		MQ2sockCommandShowQueueVeryShort;
  uint		MQ2sockCommandShowThread;
  uint		MQ2sockCommandShowCounters;
  uint		MQ2sockCommandShow7;	/* spares.. */
  uint		MQ2sockCommandShow8;

  uint		schedulerTimeserverStarts;
  uint		schedulerTimeserverStartTime;

  uint	space[30]; /* Add to tail without need to change MAGIC */

};

struct MIB_MtaEntryTaS {

  /* SMTP TRANSPORT AGENT generic counters  */

  uint		OutgoingSmtpStarts;	/* counter */
  uint		OutgoingSmtpConnects;	/* counter */
  uint		OutgoingLmtpConnects;	/* counter */
  uint		OutgoingSmtpConnectFails; /* counter ?? */
  uint		OutgoingSmtpConnectsCnt;/* gauge */
  uint		OutgoingSmtpSTARTTLS;	/* counter */
  uint		OutgoingSmtpSTARTTLSok;	/* counter */
  uint		OutgoingSmtpSTARTTLSfail; /* counter */
  uint		OutgoingSmtpEHLO;	/* counter */
  uint		OutgoingSmtpEHLOok;	/* counter */
  uint		OutgoingSmtpEHLOfail;	/* counter */
  uint		OutgoingSmtpHELO;	/* counter */
  uint		OutgoingSmtpHELOok;	/* counter */
  uint		OutgoingSmtpHELOfail;	/* counter */
  uint		OutgoingSmtpLHLO;	/* counter */
  uint		OutgoingSmtpLHLOok;	/* counter */
  uint		OutgoingSmtpLHLOfail;	/* counter */
  uint		OutgoingSmtpMAIL;	/* counter, all tried */
  uint		OutgoingSmtpMAILok;	/* counter, successfull */
  uint		OutgoingSmtpRCPT;	/* counter, all tried */
  uint		OutgoingSmtpRCPTok;	/* counter, successfull */
  uint		OutgoingSmtpDATA;	/* counter, all tried */
  uint		OutgoingSmtpDATAok;	/* counter, successfull */
  uint		OutgoingSmtpBDAT;	/* counter, all tried */
  uint		OutgoingSmtpBDATok;	/* counter, successfull */
  uint		OutgoingSmtpDATAvolume;	/* counter, in kB, successfull	*/
  uint		OutgoingSmtpBDATvolume;	/* counter, in kB, successfull	*/

  uint		OutgoingSmtpRcptsOk;	/* counter, delivered recipients */
  uint		OutgoingSmtpRcptsRetry;	/* counter, issued a retry */
  uint		OutgoingSmtpRcptsFail;	/* counter, resulted in a failure */

  double dummy7; /* Alignment, etc.. */


  /* Hmm...  actually we have never encountered these ... */

  uint		SuccessfulConvertedMessages;	/* counter */
  uint		FailedConvertedMessages;	/* counter */
  uint		LoopsDetected;		/* counter */

  double dummy99; /* Alignment, etc.. */

  uint		OutgoingSmtpTAprocesses;	/* counter */
  uint		OutgoingSmtpTAprocCountG;	/* counter */

  uint		OutgoingSmtpPIPELINING;		/* counter */

  uint	space[29]; /* Add to tail without need to change MAGIC */

};




#if 0
struct MIB_mtaGroupEntry {
  uint		GroupIndex;			/* int */
  uint		GroupReceivedMessages;		/* counter */
  uint		GroupRejectedMessages;		/* counter */
  uint		GroupStoredMessages;		/* gauge   */
  uint		GroupTransmittedMessages;	/* counter */
  uint		GroupReceivedVolume;		/* counter */
  uint		GroupStoredVolume;		/* gauge   */
  uint		GroupTransmittedVolume;		/* counter */
  uint		GroupReceivedRecipients;	/* counter */
  uint		GroupStoredRecipients;		/* gauge   */
  uint		GroupTransmittedReceipients;	/* counter */
  uint		GroupOldestMessageStored;	/* time_t */
  uint		GroupInboundAssociations;	/* gauge   */
  uint		GroupOutboundAssociations;	/* gauge   */
  uint		GroupAccumulatedInboundAssociations;  /* counter */
  uint		GroupAccumulatedOutboundAssociations; /* counter */
  uint		GroupLastInboundActivity;	/* time_t */
  uint		GroupLastOutboundActivity;	/* time_t */
  uint		GroupLastOutboundAssociationAttempt; /* time_t */
  uint		GroupRejectedInboundAssociations; /* counter */
  uint		GroupFailedOutboundAssociations;  /* counter */
  char		GroupInboundRejectionReason[80]; /* display-string ?? */
  char		GroupOutboundConnectFailureReason[80];
  uint		GroupScheduledRetry;		/* time_t */
  uint		GroupMailProtocol;		/* ??? */
  char		GroupName[80];			/* display-string ? */
  uint		GroupSuccessfulConvertedMessages; /* counter */
  uint		GroupFailedConvertedMessages;	/* counter */
  char		GroupDescription[80];		/* ??? */
  char		GroupURL[80];			/* ??? */
  uint		GroupCreationTime;		/* time_t */
  uint		GroupHierarchy;			/* int */
  char		GroupOldestMessageId[80];
  uint		GroupLoopsDetected;		/* counter */
};
#endif


struct MIB_MtaEntry {
	uint	magic;
	time_t	BlockCreationTimestamp;

	struct timeserver	ts;

	double dummy0; /* Alignment / spacer .. */

	struct MIB_MtaEntrySys	sys;

	double dummy1; /* Alignment / spacer .. */

	struct MIB_MtaEntrySs	ss;

	double dummy2; /* Alignment / spacer .. */

	struct MIB_MtaEntryRt	rt;

	double dummy3; /* Alignment / spacer .. */

	struct MIB_MtaEntrySc	sc;

	double dummy4; /* Alignment / spacer .. */

	struct MIB_MtaEntryTaS	tas;
};
