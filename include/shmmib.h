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
  uint		mtaReceivedMessagesRt;		/* counter */
  uint		mtaReceivedMessagesSc;		/* counter */
  uint		mtaStoredMessages;		/* gauge   */
  uint		mtaTransmittedMessagesRt;	/* counter */
  uint		mtaTransmittedMessagesSc;	/* counter */
  uint		mtaReceivedVolume;		/* counter, in kB */
  uint		mtaStoredVolume;		/* gauge,   in kB */
  uint		mtaTransmittedVolume;		/* counter, in kB */
  uint		mtaReceivedRecipientsRt;	/* counter */
  uint		mtaReceivedRecipientsSc;	/* counter */
  uint		mtaStoredRecipients;		/* gauge   */
  uint		mtaTransmittedRecipientsRt;	/* counter */
  uint		mtaTransmittedRecipientsSc;	/* counter */
  uint		mtaSuccessfulConvertedMessages;	/* counter */
  uint		mtaFailedConvertedMessages;	/* counter */
  uint		mtaLoopsDetected;		/* counter */
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
