/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-1997.
 */

#include "smtpserver.h"


#define	TYPE_(m)	type(SS,-214, NULL, "%s", m);
#define	TYPE(m)		type(SS,214, NULL, "%s", m);

/*
 * parse the query string and print an appropriate help message.
 */

void help(SS, cfinfo, query)
SmtpState *SS;
struct smtpconf *cfinfo;
const char *query;
{
    int col;
    const char *cp;
    struct command *carp;

    for (carp = &command_list[0]; carp->verb != NULL; ++carp) {
	if (CISTREQ(carp->verb, query))
	    break;
    }
    switch (carp->cmd) {
    case Hello:
    case Hello2:
	TYPE_("EHLO your.domain.name");
	TYPE_("HELO your.domain.name");
	TYPE_("\tThe 'EHLO' is for Extended SMTP feature recognition, and is preferred!.");
	TYPE_("\tIt is polite to introduce yourself before talking.");
	TYPE("\tI will in fact ignore you until you do!");
	break;
    case Mail:
    case Mail2:
	TYPE_("MAIL FROM:<sender> (ESMTP parameters)");
	TYPE_("EMAL FROM:<sender>");
	TYPE_("\tSpecify the originator address for the next message.");
	if (STYLE(cfinfo, 'f')) {
	    TYPE("\tThe address will be checked before it is accepted.");
	} else {
	    TYPE("\tAny address will be accepted here, but may be rejected later.");
	}
	break;
    case Recipient:
	TYPE_("RCPT TO:<recipient> (ESMTP parameters)");
	TYPE_("\tSpecify a destination address for the next message.");
	if (STYLE(cfinfo, 't')) {
	    TYPE("\tThe address will be checked before it is accepted.");
	} else {
	    TYPE("\tAny address will be accepted here, but may be rejected later.");
	}
	break;
    case Data:
	TYPE_("DATA");
	TYPE_("\tStart collecting the message itself.  The text data");
	TYPE("\tis terminated by a <CRLF>.<CRLF> combination.");
	break;
    case BData:
	TYPE_("BDAT nnn [LAST]");
	TYPE_("\tESMTP \"CHUNKING\" service extension; See RFC 1830");
	break;
    case Reset:
	TYPE_("RSET");
	TYPE_("\tReset the state of the SMTP server to be ready for");
	TYPE_("\tthe next message, and abort any current transaction.");
	TYPE_("");
	switch (SS->state) {
	case Hello:
	    cp = "Waiting for \"HELO\" command";
	    break;
	case Mail:
	    cp = "Waiting for \"MAIL\" command";
	    break;
	case MailOrHello:
	    cp = "Waiting for \"MAIL\" or \"EHLO\"/\"HELO\" command";
	    break;
	case Recipient:
	    cp = "Waiting for \"RCPT\" command";
	    break;
	case RecipientOrData:
	    cp = "Waiting for \"RCPT\" or \"DATA\" command";
	default:
	    cp = "Unknown";
	    break;
	}
	type(SS, 214, NULL, "The current state is: %s.", cp);
	break;
    case Send:
    case Send2:
    case SendOrMail:
    case SendAndMail:
    case Turn:
	TYPE_(carp->verb);
	TYPE("\tThis command will never be implemented.");
	break;
    case Turnme:
	type(SS, -214, NULL, "%s hostname", carp->verb);
	TYPE_("\tThis command schedules (at least tries to) all");
	TYPE_("\toutbound traffic to ``hostname'' host.");
	TYPE_("\tFor security reasons this server will initiate the");
	TYPE("\tSMTP-transport towards relay/recipient SMTP-server.");
	break;
    case Verify:
    case Verify2:
	TYPE_("VRFY <recipient>");
	TYPE_("EVFY <recipient>");
	if (STYLE(cfinfo, 'v')) {
	    TYPE_("\tPrints the recipients for the given address.")
		TYPE("\tIf the address is local, it is not expanded.");
	} else {
	    TYPE("\tThis command is disabled.");
	}
	break;
    case Expand:
	TYPE_("EXPN <recipient>");
	if (STYLE(cfinfo, 'e')) {
	    TYPE_("\tPrints the recipients for the given address.")
		TYPE("\tIf the address is local, it is expanded.");
	} else {
	    TYPE("\tThis command is disabled.");
	}
	break;
    case NoOp:
	TYPE_(carp->verb);
	TYPE("\tThis command does nothing.");
	break;
    case Quit:
	TYPE_("QUIT");
	TYPE("\tTerminate the SMTP protocol conversation.");
	break;
    case Verbose:
	TYPE_("VERB");
	TYPE_("\tPrints out the SMTP server version and copyright notice.");
	TYPE("\tThis command has no other effect.");
	break;
    case Tick:
	TYPE_("TICK id");
	TYPE("\tThis BSMTP command is just reflected back at you.");
	break;
    case Help:
	TYPE_("HELP [command]");
	TYPE_("\tReminder of what the SMTP command does, or prints:");
	TYPE_("");
	/* fall through */
    case Null:
    default:
	TYPE_(Copyright);
	TYPE_(Copyright2);
	TYPE_("");
	if (helplines[0] != NULL) {
	    int i;
	    for (i = 0; helplines[i] != NULL; ++i)
		TYPE_(helplines[i]);
	    TYPE_("");
	}
	printf("214-The following commands are recognized:");
	if (logfp)
	    fprintf(logfp, "%dw\t214-The following commands are recognized:", pid);
	col = 100;
	for (carp = &command_list[0]; carp->verb != NULL; ++carp) {
	    if (col > 70) {
		col = 12;
		printf("\r\n214-\t%s", carp->verb);
		if (logfp)
		    fprintf(logfp, "\n%dw\t214\t%s", pid, carp->verb);
	    } else {
		printf(", %s", carp->verb);
		if (logfp)
		    fprintf(logfp, ", %s", carp->verb);
		col += 6;
	    }
	}
	printf("\r\n");
	if (logfp)
	    fprintf(logfp, "\n");
	TYPE_("");
	TYPE_("The normal sequence is: EHLO/HELO (MAIL RCPT+ DATA)+ QUIT.");
	TYPE_("");
	TYPE_("This mailer will always accept 8-bit and binary message data");
	TYPE_("though you are better to use MIME format!");
	TYPE_("");
	type(SS, -214, NULL, "For local information contact: postmaster@%s",
	     SS->myhostname);
	type(SS, 214, NULL, "SMTP server comments and bug reports to: <zmhacks@nic.funet.fi>");
	break;
    }
    typeflush(SS);
    if (logfp)
	fflush(logfp);
}
