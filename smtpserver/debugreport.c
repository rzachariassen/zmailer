#include "smtpserver.h"

void debug_report(SS, verb, remotehost, buf)
SmtpState *SS;
int verb;
const char *remotehost, *buf;
{
#if 0				/* From  UNIDO, though a bit vulgar.. */
    if (!verb) {
	type(SS, 423, "", "To See Figure 1, go into VERBose mode first.");
	return;
    }
    type(SS, -521, "", "    ---------------------------------");
    type(SS, -521, "", "    !               _               !");
    type(SS, -521, "", "    !              { }              !");
    type(SS, -521, "", "    !              | |              !");
    type(SS, -521, "", "    !              | |              !");
    type(SS, -521, "", "    !           .-.! !.-.           !");
    type(SS, -521, "", "    !         .-!  ! !  !.-.        !");
    type(SS, -521, "", "    !         ! !       !  ;        !");
    type(SS, -521, "", "    !         \\           ;         !");
    type(SS, -521, "", "    !          \\         ;          !");
    type(SS, -521, "", "    !           !       :           !");
    type(SS, -521, "", "    !           !       :           !");
    type(SS, -521, "", "    !           !       :           !");
    type(SS, -521, "", "    !                               !");
    type(SS, -521, "", "    !_______________________________!");
    type(SS, -521, "", "                 Figure 1.           ");
    type(SS, -521, "", "");
    type(SS, -521, "", "");
    type(SS, 521, "", "See Figure 1, %s.", remotehost);
    exit(0);
#endif
    if (!verb) {
	type(SS, 423, "", "Must be VERBose to use DEBUG");
	return;
    }
    if (strlen(buf) < 8) {
	type(SS, 423, "", "Umm..  DEBUG <password>");
	return;
    }
    type(SS, -521, "", "Ex cuse me ?  You try to exploit the DEBUG-hole on this hosts sendmail ?");
    type(SS, 521, "", "Unfortunately (for you) we do not have sendmail...");
#if 0
    type(SS, -521, "", "Do following, and know what we think of you:");
    type(SS, -521, "", "   telnet mail.Germany.EU.net smtp");
    type(SS, -521, "", "   220 ...");
    type(SS, -521, "", "   VERB");
    type(SS, -521, "", "   200 ...");
    type(SS, 521, "", "   DEBUG");
#endif
    exit(0);
}
