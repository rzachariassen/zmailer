/*
 * ZMailer 2.99.X global variables stored on shared read/write
 * SysV-SHM memory segment on those platforms that support it.
 *
 * These are used for storing counters/gauges for Mail Monitoring MIB
 * (RFC 2249) to such a extent as is relatively easily possible to do.
 *
 * Copyright Matti Aarnio <mea@nic.funet.fi> 1998
 *
 */


struct MIB_MtaEntry {
  uint32	mtaReceivedMessages;		/* counter */
  uint32	mtaStoredMessages;		/* gauge   */
  uint32	mtaTransmittedMessages;		/* counter */
  uint32	mtaReceivedVolume;		/* counter */
  uint32	mtaStoredVolume;		/* gauge   */
  uint32	mtaTransmittedVolume;		/* counter */
  uint32	mtaReceivedRecipients;		/* counter */
  uint32	mtaStoredRecipients;		/* gauge   */
  uint32	mtaTransmittedRecipients;	/* counter */
  uint32	mtaSuccessfulConvertedMessages;	/* counter */
  uint32	mtaFailedConvertedMessages;	/* counter */
  uint32	mtaLoopsDetected;		/* counter */
};

struct MIB_mtaGroupEntry {
  uint32	mtaGroupIndex;			/* int */
  uint32	mtaGroupReceivedMessages;	/* counter */
  uint32	mtaGroupRejectedMessages;	/* counter */
  uint32	mtaGroupStoredMessages;		/* gauge   */
  uint32	mtaGroupTransmittedMessages;	/* counter */
  uint32	mtaGroupReceivedVolume;		/* counter */
  uint32	mtaGroupStoredVolume;		/* gauge   */
  uint32	mtaGroupTransmittedVolume;	/* counter */
  uint32	mtaGroupReceivedRecipients;	/* counter */
  uint32	mtaGroupStoredRecipients;	/* gauge   */
  uint32	mtaGroupTransmittedReceipients; /* counter */
  uint32	mtaGroupOldestMessageStored;	/* time_t */
  uint32	mtaGroupInboundAssociations;	/* gauge   */
  uint32	mtaGroupOutboundAssociations;	/* gauge   */
  uint32	mtaGroupAccumulatedInboundAssociations;  /* counter */
  uint32	mtaGroupAccumulatedOutboundAssociations; /* counter */
  uint32	mtaGroupLastInboundActivity;	/* time_t */
  uint32	mtaGroupLastOutboundActivity;	/* time_t */
  uint32	mtaGroupLastOutboundAssociationAttempt; /* time_t */
  uint32	mtaGroupRejectedInboundAssociations; /* counter */
  uint32	mtaGroupFailedOutboundAssociations;  /* counter */
  char		mtaGroupInboundRejectionReason[80]; /* display-string ?? */
  char		mtaGroupOutboundConnectFailureReason[80];
  uint32	mtaGroupScheduledRetry;		/* time_t */
  uint32	mtaGroupMailProtocol;		/* ??? */
  char		mtaGroupName[80];		/* display-string ? */
  uint32	mtaGroupSuccessfulConvertedMessages; /* counter */
  uint32	mtaGroupFailedConvertedMessages; /* counter */
  char		mtaGroupDescription[80];	/* ??? */
  char		mtaGroupURL[80];		/* ??? */
  uint32	mtaGroupCreationTime;		/* time_t */
  uint32	mtaGroupHierarchy;		/* int */
  char		mtaGroupOldestMessageId[80];
  uint32	mtaGroupLoopsDetected;		/* counter */
};
