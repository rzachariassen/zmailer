/* locally added autoconfig test report entries */

/* What command was used to configure this setup ? */
#undef CONFIGURE_CMD

/* Define if you have the Andrew File System.  */
#undef AFS

/* Define to `unsigned long' if <sys/types.h> doesn't define.  */
#undef ino_t

/* Define if there is a member named d_ino in the struct describing
   directory headers.  */
#undef D_INO_IN_DIRENT

/* Timezone information storage */
/* If 'struct tm' has a 'tm_zone' member */
#undef HAVE_TM_ZONE
/* Alternatively if the  'extern char *zname[];' is found: */
#undef HAVE_TZNAME
/* Perhaps 'struct tm' has 'tm_gmtoff' member ? */
#undef HAVE_TM_GMTOFF
/* or perhaps there is global variable 'altzone' ? (and friends) */
#undef HAVE_ALTZONE
/* or maybe we have POSIX (?) style with only one variable: */
#undef HAVE_TIMEZONE

/* IPv6 related tests.  We use the protocol-independent
   getaddrinfo()/getnameinfo() for the actual work in
   all systems.  Though in systems without IPv6 those
   routines don't support AF_INET6 ... */
#undef INET6

#undef HAVE__GETADDRINFO_

/* socklen_t type can be found by including <sys/socket.h> */
#undef HAVE_SOCKLEN_T

#undef HAVE_NETINET_IN_H
/* Sigh....  Linux 2.1.x series with IPv6  */
#undef HAVE_NETINET_IN6_H
#undef HAVE_NETINET6_IN6_H
#undef HAVE_LINUX_IN6_H

/* Define if there is no specific function for reading the list of
   mounted filesystems.  fread will be used to read /etc/mnttab.  [SVR2]  */
#undef MOUNTED_FREAD

/* Define if (like SVR2) there is no specific function for reading the
   list of mounted filesystems, and your system has these header files:
   <sys/fstyp.h> and <sys/statfs.h>.  [SVR3]  */
#undef MOUNTED_FREAD_FSTYP

/* Define if there is a function named getfsstat for reading the list
   of mounted filesystems.  [DEC Alpha running OSF/1]  */
#undef MOUNTED_GETFSSTAT

/* Define if there is a function named getmnt for reading the list of
   mounted filesystems.  [Ultrix]  */
#undef MOUNTED_GETMNT

/* Define if there is a function named getmntent for reading the list
   of mounted filesystems, and that function takes a single argument.
   [4.3BSD, SunOS, HP-UX, Dynix, Irix]  */
#undef MOUNTED_GETMNTENT1

/* Define if there is a function named getmntent for reading the list of
   mounted filesystems, and that function takes two arguments.  [SVR4]  */
#undef MOUNTED_GETMNTENT2

/* Define if there is a function named getmntinfo for reading the list
   of mounted filesystems.  [4.4BSD]  */
#undef MOUNTED_GETMNTINFO

/* Define if there is a function named mntctl that can be used to read
   the list of mounted filesystems, and there is a system header file
   that declares `struct vmount.'  [AIX]  */
#undef MOUNTED_VMOUNT

/* Defined if we have the appropriate databases and they are usable.  We
   cannot merely depend on the existence of headers because sometimes they
   exist without the corresponding libraries.  Also in some cases, critical
   functionality does not exist.  One example of this is, for NDBM, the lack 
   of a dbm_pagfno() on OpenBSD. */
#undef HAVE_DB1
#undef HAVE_DB2
#undef HAVE_DB3
#undef HAVE_NDBM
#undef HAVE_GDBM
#undef HAVE_SDBM

/* Defined if NDBM has  dbm_error()  function */
#undef HAVE_DBM_ERROR

/* Have SleepyCat's BSD DB 2.x version of BSD DB database */
#undef HAVE_DB_OPEN2
/* Have SleepyCat's BSD DB 3.x version of BSD DB database */
#undef HAVE_DB_CREATE

/* Latter versions of 2.x have 4-args (db->cursor)() method */
#undef HAVE_DB_CURSOR4


/* Defined if using LDAP */
#undef HAVE_LDAP

/* Defined if socket structure has  sa_len  field */
#undef HAVE_SA_LEN

/* Doing email spool locking with "dot-lock" system */
#undef HAVE_DOTLOCK

/* SysVr4 (Solaris only?)  maillock()  function */
#undef HAVE_MAILLOCK

/* Function  dup2()  does exist! */
#undef HAVE_DUP2

/* DNS Resolver does exist */
#undef HAVE_RESOLVER

/* NIS (or "YP" for old salts) does exist */
#undef HAVE_YP

/* Want (not) to use TABs in RFC-822 headers to separate header name, and
   its value from each other:  "From:" <TAB> <value> */
#undef RFC822TABS

/* The  sprintf()  returns a char*, or int ? */
#undef SPRINTF_CHAR

/*  Define if  statfs takes 3 args.  [DEC Alpha running OSF/1]  */
#undef STAT_STATFS3_OSF1

/* Define if there is no specific function for reading filesystems usage
   information and you have the <sys/filsys.h> header file.  [SVR2]  */
#undef STAT_READ_FILSYS

/* Define if statfs takes 2 args and struct statfs has a field named f_bsize.
   [4.3BSD, SunOS 4, HP-UX, AIX PS/2]  */
#undef STAT_STATFS2_BSIZE

/* Define if statfs takes 2 args and struct statfs has a field named f_fsize.
   [4.4BSD, NetBSD]  */
#undef STAT_STATFS2_FSIZE

/* Define if statfs takes 2 args and the second argument has
   type struct fs_data.  [Ultrix]  */
#undef STAT_STATFS2_FS_DATA

/* Define if statfs takes 4 args.  [SVR3, Dynix, Irix, Dolphin]  */
#undef STAT_STATFS4

/* Define if there is a function named statvfs.  [SVR4]  */
#undef STAT_STATVFS

/* */
#undef HAVE_SYS_SIGLIST

/* */
#undef USE_TCPWRAPPER

/* */
#undef HAVE_SOCKET

/* */
#undef HAVE_SOCKETPAIR

/* */
#undef HAVE_GETHOSTBYNAME

/* */
#undef TA_USE_MMAP

/* */
#undef SVR4_elf

/* */
#undef SVR4_kvm

/* */
#undef HAVE_WHOSON_H

/* HAVE_OPENSSL -- The system has www.OpenSSL.org software;
   version 0.9.3a, very least */
#undef HAVE_OPENSSL

/* For mailbox; check mailbox quota thru  checkmbsize() routine.. */
#undef CHECK_MB_SIZE

/* Charset translation on incming text messages */
#undef USE_TRANSLATION

/* Defined if resolver's  HEADER  structure has  cd  and  ad  fields */
#undef HAVE_HEADER_CD_AD

/* */
#undef HAVE_GETADDRINFO

/* */
#undef HAVE_GETNAMEINFO

/* */
#undef HAVE_INET_NTOP

/* */
#undef HAVE_INET_PTON

/* */
#undef HAVE_TCPD_H
