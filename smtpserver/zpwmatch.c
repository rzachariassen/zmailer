/*
 *  ZMailer smtpserver,  AUTH command things;
 *  part of ZMailer.
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999
 */

/* This is *NOT* universal password matcher!
   Consider Shadow passwords, PAM systems, etc.. */

#define _XOPEN_SOURCE /* Linux glibc 2.1 needs this for crypt() et.al. */

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
