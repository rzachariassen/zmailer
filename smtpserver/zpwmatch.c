/*
 *  ZMailer smtpserver,  AUTH command things;
 *  part of ZMailer.
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999
 */

/* This is *NOT* universal password matcher!
   Consider Shadow passwords, PAM systems, etc.. */

#define _GNU_SOURCE /* Very short hand define to please compilation
		       at glibc 2.1.* -- _XOPEN_SOURCE_EXTENDED + BSD + ... */

#include "mailer.h"

#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>

int zpwmatch(uname,password)
     char *uname, *password;
{
    struct passwd *pw = getpwnam(uname);
    char *cr;

    if (!pw) return 0; /* No such user */
    cr = crypt(password, pw->pw_passwd);

    return (strcmp(cr, pw->pw_passwd) == 0);
}
