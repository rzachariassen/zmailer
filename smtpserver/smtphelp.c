/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2000.
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
    Command cmd;
    char linebuf[3000];

    while (query && (*query == ' ' || *query == '\t')) ++query;

    for (carp = &command_list[0]; carp->verb != NULL; ++carp) {
	if (CISTREQ(carp->verb, query))
	    break;
    }

    cmd = carp->cmd;
    if (lmtp_mode && (cmd == Hello || cmd == Hello2)) cmd = Null;
    if (!lmtp_mode && (cmd == HelloL)) cmd = Null;

    switch (cmd) {
    case Hello:
    case Hello2:
    case HelloL:
        if (lmtp_mode) {
	  TYPE_("LHLO your.domain.name");
	  TYPE_("    The 'LHLO' is for RFC 2033 / LMTP session greeting.");
	} else {
	  TYPE_("EHLO your.domain.name");
	  TYPE_("HELO your.domain.name");
	  TYPE_("    The 'EHLO' is for Extended SMTP feature recognition, and is preferred!.");
	}
	TYPE_("    It is polite to introduce yourself before talking.");
	TYPE("    I will in fact ignore you until you do!");
	break;
    case Mail:
    case Mail2:
	TYPE_("MAIL FROM:<sender> (ESMTP parameters)");
	TYPE_("EMAL FROM:<sender>");
	TYPE_("    Specify the originator address for the next message.");
	if (STYLE(cfinfo, 'f')) {
	    TYPE("    The address will be checked before it is accepted.");
	} else {
	    TYPE("    Any address will be accepted here, but may be rejected later.");
	}
	break;
    case Recipient:
	TYPE_("RCPT TO:<recipient> (ESMTP parameters)");
	TYPE_("    Specify a destination address for the next message.");
	if (STYLE(cfinfo, 't')) {
	    TYPE("    The address will be checked before it is accepted.");
	} else {
	    TYPE("    Any address will be accepted here, but may be rejected later.");
	}
	break;
    case Data:
	TYPE_("DATA");
	TYPE_("    Start collecting the message itself.  The text data");
	TYPE("    is terminated by a <CRLF>.<CRLF> combination.");
	break;
    case BData:
	TYPE_("BDAT nnn [LAST]");
	TYPE_("    ESMTP \"CHUNKING\" service extension; See RFC 1830");
	break;
    case Reset:
	TYPE_("RSET");
	TYPE_("    Reset the state of the SMTP server to be ready for");
	TYPE_("    the next message, and abort any current transaction.");
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
	TYPE("    This command will never be implemented.");
	break;
    case Turnme:
	type(SS, -214, NULL, "%s hostname", carp->verb);
	TYPE_("    This command schedules (at least tries to) all");
	TYPE_("    outbound traffic to ``hostname'' host.");
	TYPE_("    For security reasons this server will initiate the");
	TYPE("    SMTP-transport towards relay/recipient SMTP-server.");
	break;
    case Verify:
    case Verify2:
	TYPE_("VRFY <recipient>");
	TYPE_("EVFY <recipient>");
	if (STYLE(cfinfo, 'v')) {
	    TYPE_("    Prints the recipients for the given address.")
		TYPE("    If the address is local, it is not expanded.");
	} else {
	    TYPE("    This command is disabled.");
	}
	break;
    case Expand:
	TYPE_("EXPN <recipient>");
	if (STYLE(cfinfo, 'e')) {
	    TYPE_("    Prints the recipients for the given address.")
		TYPE("    If the address is local, it is expanded.");
	} else {
	    TYPE("    This command is disabled.");
	}
	break;
    case NoOp:
	TYPE_(carp->verb);
	TYPE("    This command does nothing.");
	break;
    case Quit:
	TYPE_("QUIT");
	TYPE("    Terminate the SMTP protocol conversation.");
	break;
    case Verbose:
	TYPE_("VERB");
	TYPE_("    Prints out the SMTP server version and copyright notice.");
	TYPE("    This command has no other effect.");
	break;
    case Tick:
	TYPE_("TICK id");
	TYPE("    This BSMTP command is just reflected back at you.");
	break;
    case Help:
	TYPE_("HELP [command]");
	TYPE_("    Reminder of what the SMTP command does.");
	break;
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
	TYPE_("The following commands are recognized:");
	col = 4;
	strcpy(linebuf, "    ");
	for (carp = &command_list[0]; carp->verb != NULL; ++carp) {
	    if (carp->cmd == HelloL && !lmtp_mode)
	      continue;
	    if (lmtp_mode && (carp->cmd == Hello || carp->cmd == Hello2))
	      continue;
	    if (carp->cmd == Silent)
	      continue;
	    if (col > 55) {
		TYPE_(linebuf);
		col = 4;
		strcpy(linebuf, "    ");
	    } else if (col == 4) {
		sprintf(linebuf+col, "%s", carp->verb);
	    } else {
		sprintf(linebuf+col, ", %s", carp->verb);
	    }
	    col += strlen(linebuf+col);
	}
	/* If it has more than just the start indentation. */
	if (linebuf[4] != 0) TYPE_(linebuf);

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
