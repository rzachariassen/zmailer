/*
 * ZMailer 2.99.X global variables stored on shared read/write
 * SysV-SHM memory segment on those platforms that support it.
 *
 * These are used for storing counters/gauges for Mail Monitoring MIB
 * (RFC 2249) to such a extent as is relatively easily possible to do.
 *
 * Copyright Matti Aarnio <mea@nic.funet.fi> 1998, 2003-2004
 *
 */



#define Vpid_t   volatile pid_t
#define Vtime_t  volatile time_t
#define Vuint    volatile uint

#define ZM_MIB_MAGIC 0x33120006

struct timeserver {
	Vuint	pid;
#ifdef HAVE_SELECT
	volatile struct timeval tv;
#else
	Vtime_t	time_sec;
#endif
};

struct MIB_MtaEntrySys {

  Vpid_t	RouterMasterPID;
  Vtime_t	RouterMasterStartTime;
  Vuint		RouterMasterStarts;

  Vpid_t	SchedulerMasterPID;
  Vtime_t	SchedulerMasterStartTime;
  Vuint		SchedulerMasterStarts;

  Vpid_t	SmtpServerMasterPID;
  Vtime_t	SmtpServerMasterStartTime;
  Vuint		SmtpServerMasterStarts;

  double dummy1; /* cache-line alignment, etc.. */

  /* SpoolFree  is monitored and stored by _XX_ subsystem ?  
     Router and scheduler ?  Smtpserver ?  All three ? */

  Vuint		SpoolFreeSpace;		/* gauge,	in kB	*/
  Vuint		SpoolUsedSpace;		/* gauge,	in kB	*/
  Vuint		LogFreeSpace;		/* gauge,	in kB  ?? */
  Vuint		LogUsedSpace;		/* gauge,	in kB  ?? */

  Vuint		SpoolFreeFiles;
  Vuint		SpoolUsedFiles;
  Vuint		LogFreeFiles;
  Vuint		LogUsedFiles;

  Vuint		TportSpoolFreeSpace; /* gauge,	in kB	*/
  Vuint		TportSpoolUsedSpace; /* gauge,	in kB	*/
  Vuint		TportSpoolFreeFiles;
  Vuint		TportSpoolUsedFiles;

  Vuint		dummy99[24];
};

struct MIB_MtaEntrySs {

  /* SMTPSERVER substystem counters */

  Vuint		IncomingSMTPSERVERprocesses;  /* gauges */
  Vuint		IncomingParallelSMTPconnects;
  Vuint		IncomingParallelSMTPSconnects;
  Vuint		IncomingParallelSUBMITconnects;

  Vuint		IncomingSMTPSERVERforks;
  Vuint		MaxSameIpSourceCloses;
  Vuint		MaxParallelConnections;
  Vuint		ForkFailures;
  Vuint		ContentPolicyForkFailures;

  Vuint		IncomingSMTPconnects;	/* Incoming SMTP sessions */
  Vuint		IncomingSMTPSconnects;	/* Incoming SMTPS sessions */
  Vuint		IncomingSUBMITconnects;	/* Incoming SUBMIT sessions */

  Vuint		IncomingClientPipelines;
  Vuint		IncomingSmtpTarpits;

  Vuint		IncomingCommands;	/* counters */
  Vuint		IncomingCommands_unknown;

  Vuint		IncomingSMTP_HELO;
  Vuint		IncomingSMTP_HELO_ok;
  Vuint		IncomingSMTP_HELO_bad;

  Vuint		IncomingSMTP_EHLO;
  Vuint		IncomingSMTP_EHLO_ok;
  Vuint		IncomingSMTP_EHLO_bad;

  Vuint		IncomingSMTP_ETRN;
  Vuint		IncomingSMTP_ETRN_ok;
  Vuint		IncomingSMTP_ETRN_bad;

  Vuint		IncomingSMTP_STARTTLS;	/* Number of STARTTLSes */
  Vuint		IncomingSMTP_STARTTLS_fail;
  Vuint		IncomingSMTP_HELP;
  Vuint		IncomingSMTP_EXPN;
  Vuint		IncomingSMTP_VRFY;
  Vuint		IncomingSMTP_RSET;
  Vuint		IncomingSMTP_TURN;
  Vuint		IncomingSMTP_NOOP;
  Vuint		IncomingSMTP_VERBOSE;
  Vuint		IncomingSMTP_DEBUG;
  Vuint		IncomingSMTP_TICK;
  Vuint		IncomingSMTP_QUIT;

  Vuint		IncomingSMTP_MAIL;
  Vuint		IncomingSMTP_MAIL_ok;
  Vuint		IncomingSMTP_MAIL_bad;

  Vuint		IncomingSMTP_RCPT;
  Vuint		IncomingSMTP_RCPT_ok;
  Vuint		IncomingSMTP_RCPT_bad;

  Vuint		IncomingSMTP_OPT_ENVID;
  Vuint		IncomingSMTP_OPT_SIZE;
  Vuint		IncomingSMTP_OPT_AUTH;
  Vuint		IncomingSMTP_OPT_DELIVERBY;
  Vuint		IncomingSMTP_OPT_BODY_8BITMIME;
  Vuint		IncomingSMTP_OPT_BODY_BINARYMIME;
  Vuint		IncomingSMTP_OPT_BODY_7BIT;
  Vuint		IncomingSMTP_OPT_RET;

  Vuint		IncomingSMTP_OPT_NOTIFY;
  Vuint		IncomingSMTP_OPT_ORCPT;

  Vuint		IncomingSMTP_DATA;
  Vuint		IncomingSMTP_DATA_ok;
  Vuint		IncomingSMTP_DATA_bad;
  Vuint		IncomingSMTP_BDAT;
  Vuint		IncomingSMTP_BDAT_ok;
  Vuint		IncomingSMTP_BDAT_bad;

  Vuint		IncomingSMTP_DATA_KBYTES;
  Vuint		IncomingSMTP_BDAT_KBYTES;
  Vuint		IncomingSMTP_spool_KBYTES;

  Vuint		ReceivedMessagesSs;	/* counter, smtpserver	*/
  Vuint		ReceivedRecipientsSs;	/* counter, smtpserver	*/
  Vuint		TransmittedMessagesSs;	/* counter, smtpserver	*/
  Vuint		TransmittedRecipientsSs;/* counter, smtpserver	*/


  double dummy3; /* Alignment, etc.. */

  Vuint		SubsysRateTrackerPID;
  Vuint		SubsysRouterMasterPID;
  Vuint		SubsysContentfilterMasterPID;

  Vuint		IncomingSMTP_REPORT;

  Vuint	space[28]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntryRt {
  /* ROUTER subsystem counters */

  Vuint		RouterProcesses;	/* gauge */
  Vuint		RouterProcessForks;	/* counter, cleared at start */
  Vuint		RouterProcessFaults;	/* counter, cleared at start */

  Vuint		ReceivedMessages;	/* counter, router	*/
  Vuint		ReceivedRecipients;	/* counter, router - not! */
  Vuint		TransmittedMessages;	/* counter, router	*/
  Vuint		TransmittedRecipients;	/* counter, router	*/

  Vuint		ReceivedVolume;		/* counter,	in kB	*/
  Vuint		TransmittedVolume;	/* counter,	in kB	*/
  Vuint		TransmittedVolume2;	/* counter,	in kB	*/

  /* Subsystem queue size  */
  Vuint		StoredMessages;		/* gauge, router	*/
  Vuint		StoredVolume;		/* gauge,	in kB	*/


  Vuint	space[32]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntrySc {
  /* SCHEDULER subsystem counters */

  Vuint		schedulerTimeserverStarts;
  Vuint		schedulerTimeserverStartTime;

  Vuint		ReceivedMessagesSc;	/* counter, scheduler	*/
  Vuint		ReceivedRecipientsSc;	/* counter, scheduler	*/
  Vuint		TransmittedMessagesSc;	/* counter, scheduler	*/
  Vuint		TransmittedRecipientsSc;/* counter, scheduler	*/

  Vuint		StoredMessagesSc;	/* gauge, scheduler	*/
  Vuint		StoredThreadsSc;	/* gauge, scheduler	*/
  Vuint		StoredVerticesSc;	/* gauge, scheduler	*/
  Vuint		StoredRecipientsSc;	/* gauge, scheduler	*/

  Vuint		ReceivedVolumeSc;	/* counter,	in kB	*/
  Vuint		StoredVolumeSc;		/* gauge,	in kB	*/
  Vuint		TransmittedVolumeSc;	/* counter, ??	in kB	*/

  Vuint		TransportAgentForksSc;	/* counter		*/
  Vuint		TransportAgentProcessesSc;/* gauge		*/
  Vuint		TransportAgentsActiveSc;/* gauge		*/
  Vuint		TransportAgentsIdleSc;	/* gauge		*/

  /* MQ1 socket */
  Vuint		MQ1sockConnects;	/* counter */
  Vuint		MQ1sockParallel;	/* gauge */
  Vuint		MQ1sockTcpWrapRej;	/* counter */
  
  /* MQ2 socket */

  Vuint		MQ2sockConnects;	/* counter */
  Vuint		MQ2sockParallel;	/* gauge   */
  Vuint		MQ2sockTcpWrapRej;
  Vuint		MQ2sockAuthRej;
  Vuint		MQ2sockTimedOut;
  Vuint		MQ2sockReadEOF;
  Vuint		MQ2sockReadFails;
  Vuint		MQ2sockWriteFails;
  Vuint		MQ2sockCommands;
  Vuint		MQ2sockCommandsRej;
  Vuint		MQ2sockCommandAUTH;
  Vuint		MQ2sockCommandQUIT;
  Vuint		MQ2sockCommandETRN;
  Vuint		MQ2sockCommandKillThr;
  Vuint		MQ2sockCommandKillMsg;
  Vuint		MQ2sockCommandKillProcess;
  Vuint		MQ2sockCommandRerouteThr;
  Vuint		MQ2sockCommandRerouteMsg;
  Vuint		MQ2sockCommandShowQueueThreads;
  Vuint		MQ2sockCommandShowQueueThreads2;
  Vuint		MQ2sockCommandShowQueueShort;
  Vuint		MQ2sockCommandShowQueueVeryShort;
  Vuint		MQ2sockCommandShowThread;
  Vuint		MQ2sockCommandShowCounters;
  Vuint		MQ2sockCommandShow7;	/* spares.. */
  Vuint		MQ2sockCommandShow8;

  Vuint	space[32]; /* Add to tail without need to change MAGIC */

};

struct MIB_MtaEntryTaS {

  /* SMTP TRANSPORT AGENT generic counters  */

  Vuint		TaProcessStarts;	/* counter */
  Vuint		TaProcCountG;		/* gauge */
  Vuint		TaIdleStates;		/* counter */
  Vuint		TaMessages;		/* counter */
  Vuint		TaDeliveryStarts;		/* counter,  delivery() calls */

  Vuint		SmtpStarts;		/* counter */
  Vuint		SmtpConnects;		/* counter */
  Vuint		LmtpConnects;		/* counter */
  Vuint		SmtpConnectFails; 	/* counter ?? */
  Vuint		SmtpConnectsCnt;	/* gauge */
  Vuint		SmtpPIPELINING;		/* counter */
  Vuint		SmtpSTARTTLS;		/* counter */
  Vuint		SmtpSTARTTLSok;		/* counter */
  Vuint		SmtpSTARTTLSfail; 	/* counter */
  Vuint		SmtpEHLO;		/* counter */
  Vuint		SmtpEHLOok;		/* counter */
  Vuint		SmtpEHLOfail;		/* counter */
  Vuint		SmtpHELO;		/* counter */
  Vuint		SmtpHELOok;		/* counter */
  Vuint		SmtpHELOfail;		/* counter */
  Vuint		SmtpLHLO;		/* counter */
  Vuint		SmtpLHLOok;		/* counter */
  Vuint		SmtpLHLOfail;		/* counter */

  Vuint		EHLOcapability8BITMIME;
  Vuint		EHLOcapabilityAUTH;
  Vuint		EHLOcapabilityCHUNKING;
  Vuint		EHLOcapabilityDELIVERBY;
  Vuint		EHLOcapabilityDSN;
  Vuint		EHLOcapabilityENHANCEDSTATUSCODES;
  Vuint		EHLOcapabilityPIPELINING;
  Vuint		EHLOcapabilitySIZE;
  Vuint		EHLOcapabilitySTARTTLS;

  Vuint		SmtpOPT_ENVID;
  Vuint		SmtpOPT_SIZE;
  Vuint		SmtpOPT_RET;
  Vuint		SmtpOPT_NOTIFY;
  Vuint		SmtpOPT_ORCPT;

  Vuint		SmtpMAIL;		/* counter, all tried */
  Vuint		SmtpMAILok;		/* counter, successfull */
  Vuint		SmtpRCPT;		/* counter, all tried */
  Vuint		SmtpRCPTok;		/* counter, successfull */
  Vuint		SmtpDATA;		/* counter, all tried */
  Vuint		SmtpDATAok;		/* counter, successfull */
  Vuint		SmtpBDAT;		/* counter, all tried */
  Vuint		SmtpBDATok;		/* counter, successfull */
  Vuint		SmtpDATAvolume;		/* counter, in kB, successfull	*/
  Vuint		SmtpBDATvolume;		/* counter, in kB, successfull	*/

  Vuint		TaRcptsOk;		/* counter, delivered recipients */
  Vuint		TaRcptsRetry;		/* counter, issued a retry */
  Vuint		TaRcptsFail;		/* counter, resulted in a failure */

  double dummy7; /* Alignment, etc.. */


  /* Hmm...  actually we have never encountered these ... */

  Vuint		SuccessfulConvertedMessages;	/* counter */
  Vuint		FailedConvertedMessages;	/* counter */
  Vuint		LoopsDetected;		/* counter */

  double dummy99; /* Alignment, etc.. */

  Vuint	space[32]; /* Add to tail without need to change MAGIC */

};


struct MIB_MtaEntryTaSm {
  /* SM TRANSPORT AGENT */
  Vuint		TaProcessStarts;		/* counter */
  Vuint		TaProcCountG;			/* gauge */
  Vuint		TaIdleStates;
  Vuint		TaMessages;
  Vuint		TaDeliveryStarts;
  Vuint		TaRcptsOk;
  Vuint		TaRcptsRetry;
  Vuint		TaRcptsFail;

  double dummy99; /* Alignment, etc.. */

  Vuint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaMbx {
  /* MAILBOX TRANSPORT AGENT */
  Vuint		TaProcessStarts;		/* counter */
  Vuint		TaProcCountG;			/* gauge */
  Vuint		TaIdleStates;
  Vuint		TaMessages;
  Vuint		TaDeliveryStarts;
  Vuint		TaRcptsOk;
  Vuint		TaRcptsRetry;
  Vuint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  Vuint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaHo {
  /* HOLD TRANSPORT AGENT */
  Vuint		TaProcessStarts;		/* counter */
  Vuint		TaProcCountG;		/* gauge */
  Vuint		TaIdleStates;
  Vuint		TaMessages;
  Vuint		TaDeliveryStarts;
  Vuint		TaRcptsOk;
  Vuint		TaRcptsRetry;
  Vuint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  Vuint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaErr {
  /* ERRORMAIL TRANSPORT AGENT */
  Vuint		TaProcessStarts;		/* counter */
  Vuint		TaProcCountG;			/* gauge */
  Vuint		TaIdleStates;
  Vuint		TaMessages;
  Vuint		TaDeliveryStarts;
  Vuint		TaRcptsOk;
  Vuint		TaRcptsRetry;
  Vuint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  Vuint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaExpi {
  /* EXPIRER TRANSPORT AGENT */
  Vuint		TaProcessStarts;		/* counter */
  Vuint		TaProcCountG;			/* gauge */
  Vuint		TaIdleStates;
  Vuint		TaMessages;
  Vuint		TaDeliveryStarts;
  Vuint		TaRcptsOk;
  Vuint		TaRcptsRetry;
  Vuint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  Vuint	space[32]; /* Add to tail without need to change MAGIC */
};

struct MIB_MtaEntryTaRert {
  /* REROUTE TRANSPORT AGENT */
  Vuint		TaProcessStarts;		/* counter */
  Vuint		TaProcCountG;			/* gauge */
  Vuint		TaIdleStates;
  Vuint		TaMessages;
  Vuint		TaDeliveryStarts;
  Vuint		TaRcptsOk;
  Vuint		TaRcptsRetry;
  Vuint		TaRcptsFail;


  double dummy99; /* Alignment, etc.. */

  Vuint	space[32]; /* Add to tail without need to change MAGIC */
};



struct MIB_MtaEntry {
	Vuint	magic;
	Vtime_t	BlockCreationTimestamp;

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
