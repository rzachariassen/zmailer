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

#define ZM_MIB_MAGIC 0x33120002


struct timeserver {
	int	pid;
#ifdef HAVE_SELECT
	struct timeval tv;
#else
	time_t	time_sec;
#endif
#define MAPSIZE 16*1024 /* Should work at all systems ? */
};


struct MIB_MtaEntryMain {
  uint	magic;

  pid_t		mtaRouterMasterPID;
  pid_t		mtaSchedulerMasterPID;
  pid_t		mtaSmtpServerMasterPID;

  double dummy0; /* cache-line alignment, etc.. */


  /* SMTPSERVER substystem counters */

  uint		mtaIncomingSMTPSERVERprocesses;  /* gauges */
  uint		mtaIncomingParallelSMTPconnects;
  uint		mtaIncomingParallelSMTPSconnects;
  uint		mtaIncomingParallelSUBMITconnects;

  uint		mtaIncomingSMTPconnects;	/* Incoming SMTP sessions */
  uint		mtaIncomingSMTPSconnects;	/* Incoming SMTPS sessions */
  uint		mtaIncomingSUBMITconnects;	/* Incoming SUBMIT sessions */

  uint		mtaIncomingSMTPTLSes;		/* Number of STARTTLSes */

  uint		mtaIncomingCommands;		/* counters */
  uint		mtaIncomingCommands_unknown;

  uint		mtaIncomingSMTP_MAIL;
  uint		mtaIncomingSMTP_MAIL_ok;
  uint		mtaIncomingSMTP_MAIL_bad;

  uint		mtaIncomingSMTP_RCPT;
  uint		mtaIncomingSMTP_RCPT_ok;
  uint		mtaIncomingSMTP_RCPT_bad;

  uint		mtaIncomingSMTP_HELO;
  uint		mtaIncomingSMTP_EHLO;
  uint		mtaIncomingSMTP_ETRN;
  uint		mtaIncomingSMTP_HELP;

  uint		mtaIncomingSMTP_DATA;
  uint		mtaIncomingSMTP_DATA_ok;
  uint		mtaIncomingSMTP_DATA_bad;
  uint		mtaIncomingSMTP_BDAT;
  uint		mtaIncomingSMTP_BDAT_ok;
  uint		mtaIncomingSMTP_BDAT_bad;

  uint		mtaIncomingSMTP_DATA_KBYTES;
  uint		mtaIncomingSMTP_BDAT_KBYTES;
  uint		mtaIncomingSMTP_spool_KBYTES;


  double dummy1; /* Alignment, etc.. */

  uint		mtaReceivedMessagesSs;		/* counter, smtpserver	*/
  uint		mtaReceivedRecipientsSs;	/* counter, smtpserver	*/
  uint		mtaTransmittedMessagesSs;	/* counter, smtpserver	*/
  uint		mtaTransmittedRecipientsSs;	/* counter, smtpserver	*/

  double dummy2; /* Alignment, etc.. */

  /* ROUTER subsystem counters */

  uint		mtaRouterProcesses;		/* gauge */

  uint		mtaReceivedMessagesRt;		/* counter, router	*/
  uint		mtaReceivedRecipientsRt;	/* counter, router - not! */
  uint		mtaTransmittedMessagesRt;	/* counter, router	*/
  uint		mtaTransmittedRecipientsRt;	/* counter, router	*/

  uint		mtaReceivedVolumeRt;		/* counter,	in kB	*/
  uint		mtaTransmittedVolumeRt;		/* counter,	in kB	*/
  uint		mtaTransmittedVolume2Rt;	/* counter,	in kB	*/

  /* Subsystem queue size  */
  uint		mtaStoredMessagesRt;		/* gauge, router	*/
  uint		mtaStoredRecipientsRt;		/* gauge, router - not!	*/

  uint		mtaStoredVolumeRt;		/* gauge,	in kB	*/


  double dummy3; /* Alignment, etc.. */

  /* SCHEDULER subsystem counters */

  uint		mtaReceivedMessagesSc;		/* counter, scheduler	*/
  uint		mtaReceivedRecipientsSc;	/* counter, scheduler	*/
  uint		mtaTransmittedMessagesSc;	/* counter, scheduler	*/
  uint		mtaTransmittedRecipientsSc;	/* counter, scheduler	*/

  uint		mtaStoredMessagesSc;		/* gauge, scheduler	*/
  uint		mtaStoredRecipientsSc;		/* gauge, scheduler	*/

  uint		mtaReceivedVolumeSc;		/* counter,	in kB	*/
  uint		mtaStoredVolumeSc;		/* gauge,	in kB	*/
  uint		mtaTransmittedVolumeSc;		/* counter, ??	in kB	*/

  uint		mtaStoredThreadsSc;		/* gauge -- can do ?	*/

  uint		mtaTransportAgentsActiveSc;	/* gauge		*/
  uint		mtaTransportAgentsIdleSc;	/* gauge		*/


  double dummy4; /* Alignment, etc.. */


  /* SMTP TRANSPORT AGENT generic counters  */

  uint		mtaOutgoingSmtpConnects;	/* counter */
  uint		mtaOutgoingSmtpConnectFails;	/* counter ?? */
  uint		mtaOutgoingSmtpSTARTTLS;	/* counter */
  uint		mtaOutgoingSmtpMAIL;		/* counter */
  uint		mtaOutgoingSmtpRCPT;		/* counter */
  uint		mtaOutgoingSmtpDATA;		/* counter */
  uint		mtaOutgoingSmtpBDAT;		/* counter */
  uint		mtaOutgoingSmtpDATAvolume;	/* counter, in kB	*/
  uint		mtaOutgoingSmtpBDATvolume;	/* counter, in kB	*/


  uint		mtaOutgoingSmtpMAILok;		/* counter - successes only */
  uint		mtaOutgoingSmtpRCPTok;		/* counter - successes only */
  uint		mtaOutgoingSmtpDATAok;		/* counter - successes only */
  uint		mtaOutgoingSmtpBDATok;		/* counter - successes only */
  uint		mtaOutgoingSmtpDATAvolumeOK;	/* counter, in kB	*/
  uint		mtaOutgoingSmtpBDATvolumeOK;	/* counter, in kB	*/


  double dummy6; /* Alignment, etc.. */

  /* SpoolFree  is monitored and stored by _XX_ subsystem ?  
     Router and scheduler ?  Smtpserver ?  All three ? */

  uint		mtaSpoolFreeSpace;		/* gauge,	in MB	*/
  uint		mtaLogFreeSpace;		/* gauge,	in MB  ?? */


  double dummy7; /* Alignment, etc.. */


  /* Hmm...  actually we have never encountered these ... */

  uint		mtaSuccessfulConvertedMessages;	/* counter */
  uint		mtaFailedConvertedMessages;	/* counter */
  uint		mtaLoopsDetected;		/* counter */

  double dummy99; /* Alignment, etc.. */
};





struct MIB_mtaGroupEntry {
  uint		mtaGroupIndex;			/* int */
  uint		mtaGroupReceivedMessages;	/* counter */
  uint		mtaGroupRejectedMessages;	/* counter */
  uint		mtaGroupStoredMessages;		/* gauge   */
  uint		mtaGroupTransmittedMessages;	/* counter */
  uint		mtaGroupReceivedVolume;		/* counter */
  uint		mtaGroupStoredVolume;		/* gauge   */
  uint		mtaGroupTransmittedVolume;	/* counter */
  uint		mtaGroupReceivedRecipients;	/* counter */
  uint		mtaGroupStoredRecipients;	/* gauge   */
  uint		mtaGroupTransmittedReceipients; /* counter */
  uint		mtaGroupOldestMessageStored;	/* time_t */
  uint		mtaGroupInboundAssociations;	/* gauge   */
  uint		mtaGroupOutboundAssociations;	/* gauge   */
  uint		mtaGroupAccumulatedInboundAssociations;  /* counter */
  uint		mtaGroupAccumulatedOutboundAssociations; /* counter */
  uint		mtaGroupLastInboundActivity;	/* time_t */
  uint		mtaGroupLastOutboundActivity;	/* time_t */
  uint		mtaGroupLastOutboundAssociationAttempt; /* time_t */
  uint		mtaGroupRejectedInboundAssociations; /* counter */
  uint		mtaGroupFailedOutboundAssociations;  /* counter */
  char		mtaGroupInboundRejectionReason[80]; /* display-string ?? */
  char		mtaGroupOutboundConnectFailureReason[80];
  uint		mtaGroupScheduledRetry;		/* time_t */
  uint		mtaGroupMailProtocol;		/* ??? */
  char		mtaGroupName[80];		/* display-string ? */
  uint		mtaGroupSuccessfulConvertedMessages; /* counter */
  uint		mtaGroupFailedConvertedMessages; /* counter */
  char		mtaGroupDescription[80];	/* ??? */
  char		mtaGroupURL[80];		/* ??? */
  uint		mtaGroupCreationTime;		/* time_t */
  uint		mtaGroupHierarchy;		/* int */
  char		mtaGroupOldestMessageId[80];
  uint		mtaGroupLoopsDetected;		/* counter */
};


struct MIB_MtaEntry {

	struct MIB_MtaEntryMain	m;
	struct timeserver	ts;

};
