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

#define ZM_MIB_MAGIC 0x33120005

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

  uint		IncomingClientPipelines;
  uint		IncomingSmtpTarpits;

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

  uint		IncomingSMTP_STARTTLS;	/* Number of STARTTLSes */
  uint		IncomingSMTP_STARTTLS_fail;
  uint		IncomingSMTP_HELP;
  uint		IncomingSMTP_EXPN;
  uint		IncomingSMTP_VRFY;
  uint		IncomingSMTP_RSET;
  uint		IncomingSMTP_TURN;
  uint		IncomingSMTP_NOOP;
  uint		IncomingSMTP_VERBOSE;
  uint		IncomingSMTP_DEBUG;
  uint		IncomingSMTP_TICK;
  uint		IncomingSMTP_QUIT;

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

  uint		ReceivedMessagesSs;	/* counter, smtpserver	*/
  uint		ReceivedRecipientsSs;	/* counter, smtpserver	*/
  uint		TransmittedMessagesSs;	/* counter, smtpserver	*/
  uint		TransmittedRecipientsSs;/* counter, smtpserver	*/


  double dummy3; /* Alignment, etc.. */

  uint		IncomingSMTP_OPT_ENVID;
  uint		IncomingSMTP_OPT_SIZE;
  uint		IncomingSMTP_OPT_AUTH;
  uint		IncomingSMTP_OPT_DELIVERBY;
  uint		IncomingSMTP_OPT_BODY_8BITMIME;
  uint		IncomingSMTP_OPT_BODY_BINARYMIME;
  uint		IncomingSMTP_OPT_BODY_7BIT;
  uint		IncomingSMTP_OPT_RET;

  uint		IncomingSMTP_OPT_NOTIFY;
  uint		IncomingSMTP_OPT_ORCPT;

  uint		MaxSameIpSourceCloses;
  uint		MaxParallelConnections;
  uint		ForkFailures;
  uint		ContentPolicyForkFailures;

  uint	space[18]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntryRt {
  /* ROUTER subsystem counters */

  uint		RouterProcesses;	/* gauge */
  uint		RouterProcessForks;	/* counter, cleared at start */

  uint		ReceivedMessages;	/* counter, router	*/
  uint		ReceivedRecipients;	/* counter, router - not! */
  uint		TransmittedMessages;	/* counter, router	*/
  uint		TransmittedRecipients;	/* counter, router	*/

  uint		ReceivedVolume;		/* counter,	in kB	*/
  uint		TransmittedVolume;	/* counter,	in kB	*/
  uint		TransmittedVolume2;	/* counter,	in kB	*/

  /* Subsystem queue size  */
  uint		StoredMessages;		/* gauge, router	*/
  uint		StoredRecipients;	/* gauge, router - not!	*/

  uint		StoredVolume;		/* gauge,	in kB	*/


  uint		RouterProcessFaults;	/* counter, cleared at start */
  uint	space[31]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntrySc {
  /* SCHEDULER subsystem counters */

  uint		schedulerTimeserverStarts;
  uint		schedulerTimeserverStartTime;

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

  uint	space[32]; /* Add to tail without need to change MAGIC */

};

struct MIB_MtaEntryTaS {

  /* SMTP TRANSPORT AGENT generic counters  */

  uint		TaProcessStarts;	/* counter */
  uint		TaProcCountG;		/* gauge */
  uint		TaIdleStates;		/* counter */
  uint		TaMessages;		/* counter */
  uint		TaDeliveryStarts;		/* counter,  delivery() calls */

  uint		SmtpStarts;		/* counter */
  uint		SmtpConnects;		/* counter */
  uint		LmtpConnects;		/* counter */
  uint		SmtpConnectFails; 	/* counter ?? */
  uint		SmtpConnectsCnt;	/* gauge */
  uint		SmtpPIPELINING;		/* counter */
  uint		SmtpSTARTTLS;		/* counter */
  uint		SmtpSTARTTLSok;		/* counter */
  uint		SmtpSTARTTLSfail; 	/* counter */
  uint		SmtpEHLO;		/* counter */
  uint		SmtpEHLOok;		/* counter */
  uint		SmtpEHLOfail;		/* counter */
  uint		SmtpHELO;		/* counter */
  uint		SmtpHELOok;		/* counter */
  uint		SmtpHELOfail;		/* counter */
  uint		SmtpLHLO;		/* counter */
  uint		SmtpLHLOok;		/* counter */
  uint		SmtpLHLOfail;		/* counter */
  uint		SmtpMAIL;		/* counter, all tried */
  uint		SmtpMAILok;		/* counter, successfull */
  uint		SmtpRCPT;		/* counter, all tried */
  uint		SmtpRCPTok;		/* counter, successfull */
  uint		SmtpDATA;		/* counter, all tried */
  uint		SmtpDATAok;		/* counter, successfull */
  uint		SmtpBDAT;		/* counter, all tried */
  uint		SmtpBDATok;		/* counter, successfull */
  uint		SmtpDATAvolume;		/* counter, in kB, successfull	*/
  uint		SmtpBDATvolume;		/* counter, in kB, successfull	*/

  uint		TaRcptsOk;		/* counter, delivered recipients */
  uint		TaRcptsRetry;		/* counter, issued a retry */
  uint		TaRcptsFail;		/* counter, resulted in a failure */

  double dummy7; /* Alignment, etc.. */


  /* Hmm...  actually we have never encountered these ... */

  uint		SuccessfulConvertedMessages;	/* counter */
  uint		FailedConvertedMessages;	/* counter */
  uint		LoopsDetected;		/* counter */

  double dummy99; /* Alignment, etc.. */

  uint		EHLOcapability8BITMIME;
  uint		EHLOcapabilityAUTH;
  uint		EHLOcapabilityCHUNKING;
  uint		EHLOcapabilityDELIVERBY;
  uint		EHLOcapabilityDSN;
  uint		EHLOcapabilityENHANCEDSTATUSCODES;
  uint		EHLOcapabilityPIPELINING;
  uint		EHLOcapabilitySIZE;
  uint		EHLOcapabilitySTARTTLS;

  uint		SmtpOPT_ENVID;
  uint		SmtpOPT_SIZE;
  uint		SmtpOPT_RET;
  uint		SmtpOPT_NOTIFY;
  uint		SmtpOPT_ORCPT;

  uint	space[18]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntryTaSm {
  /* SM TRANSPORT AGENT */
  uint		TaProcessStarts;		/* counter */
  uint		TaProcCountG;			/* gauge */
  uint		TaIdleStates;
  uint		TaMessages;
  uint		TaDeliveryStarts;
  uint		TaRcptsOk;
  uint		TaRcptsRetry;
  uint		TaRcptsFail;

  double dummy99; /* Alignment, etc.. */

  uint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaMbx {
  /* MAILBOX TRANSPORT AGENT */
  uint		TaProcessStarts;		/* counter */
  uint		TaProcCountG;			/* gauge */
  uint		TaIdleStates;
  uint		TaMessages;
  uint		TaDeliveryStarts;
  uint		TaRcptsOk;
  uint		TaRcptsRetry;
  uint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  uint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaHo {
  /* HOLD TRANSPORT AGENT */
  uint		TaProcessStarts;		/* counter */
  uint		TaProcCountG;		/* gauge */
  uint		TaIdleStates;
  uint		TaMessages;
  uint		TaDeliveryStarts;
  uint		TaRcptsOk;
  uint		TaRcptsRetry;
  uint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  uint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaErr {
  /* ERRORMAIL TRANSPORT AGENT */
  uint		TaProcessStarts;		/* counter */
  uint		TaProcCountG;			/* gauge */
  uint		TaIdleStates;
  uint		TaMessages;
  uint		TaDeliveryStarts;
  uint		TaRcptsOk;
  uint		TaRcptsRetry;
  uint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  uint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaExpi {
  /* EXPIRER TRANSPORT AGENT */
  uint		TaProcessStarts;		/* counter */
  uint		TaProcCountG;			/* gauge */
  uint		TaIdleStates;
  uint		TaMessages;
  uint		TaDeliveryStarts;
  uint		TaRcptsOk;
  uint		TaRcptsRetry;
  uint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  uint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaRert {
  /* REROUTE TRANSPORT AGENT */
  uint		TaProcessStarts;		/* counter */
  uint		TaProcCountG;			/* gauge */
  uint		TaIdleStates;
  uint		TaMessages;
  uint		TaDeliveryStarts;
  uint		TaRcptsOk;
  uint		TaRcptsRetry;
  uint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  uint	space[32]; /* Add to tail without need to change MAGIC */
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

	struct MIB_MtaEntryTaS	tasmtp;

	double dummy5; /* Alignment / spacer .. */

	struct MIB_MtaEntryTaSm	tasmcm;

	double dummy6; /* Alignment / spacer .. */

	struct MIB_MtaEntryTaMbx tambox;

	double dummy7; /* Alignment / spacer .. */

	struct MIB_MtaEntryTaHo	tahold;

	double dummy8; /* Alignment / spacer .. */

	struct MIB_MtaEntryTaErr taerrm;

	double dummy9; /* Alignment / spacer .. */

	struct MIB_MtaEntryTaExpi taexpi;

	double dummy10; /* Alignment / spacer .. */

	struct MIB_MtaEntryTaRert tarert;
};
