/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Also Guy Middleton, and Matti Aarnio have hacked this piece -- 1993
 *
 *	In 1996 Matti Aarnio <mea@nic.funet.fi> converted this to GNU autoconf
 *	and did serious rewriteing...
 */

/*LINTLIBRARY*/

#include "hostenv.h"
#include <stdio.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <string.h>
#include "mail.h"

#include "libc.h"


#ifdef	MOUNTED_GETMNT /* DEC Ultrix */
#include <sys/param.h>
#include <sys/mount.h>
#endif

#ifdef	MOUNTED_GETMNTINFO /* DEC OSF/1 */
#include <sys/types.h>
#include <sys/mount.h>
#endif

#ifdef MOUNTED_GETMNTENT2
#include <sys/mnttab.h>
#include <sys/mntent.h>
#define	MNTTYPE	struct mnttab
#endif

#ifdef MOUNTED_GETMNTENT1
#include <mntent.h>
#define	MNTTYPE	struct mntent
#endif

#ifdef MOUNTED_VMOUNT		/* AIX */
#include <sys/vfs.h>
#include <fshelp.h>
#endif

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 64
#endif	/* MAXHOSTNAMELEN */

static char	hostname[MAXHOSTNAMELEN+1];


/*
 * Given a name like /usr/src/etc/foo.c returns the mount point
 * for the file system it lives in, or NULL in case of any error.
 */
#ifdef MOUNTED_GETMNT /* Ultrix */
char *
whathost(file)
	const char	*file;
{
	int	mountind, nummount;
	static struct fs_data	mounts[1];
	struct stat	filestat, dirstat;
	char *s;

	if (stat(file, &filestat) < 0) {
		perror(file);
		return(NULL);
	}
	mountind = 0;
	while ((nummount = getmountent(&mountind, mounts, 1)) > 0) {
		if ((stat(mounts[0].fd_path, &dirstat) >= 0) &&
		   (filestat.st_dev == dirstat.st_dev)) {
			strncpy(hostname,hmounts[0].fd_devname,sizeof(hostname));
			hostname[sizeof(hostname)-1] = 0;
			s = strchr(hostname,':');
			if (s != NULL) {
			  *s = 0;
			  return hostname;
			}
			return "localhost";
		}
	}
	if (nummount == -1)
		perror("Can't get mount information");
	return NULL;
}
#else
#ifdef MOUNTED_GETMNTINFO /* DEC OSF/1 */
char *
whathost(file)
	const char	*file;
{
	int	nummount, i;
	struct	statfs *mounts;
	struct  stat    filestat, dirstat;
	char *s;

	if (stat(file, &filestat) < 0) {
		perror(file);
		return(NULL);
	}

	mounts = NULL;
	if ((nummount = getmntinfo(&mounts, MNT_NOWAIT)) == 0) {
		perror("Can't get mount information");
		return NULL;
	}
	*hostname = 0;
	for (i=0; i<nummount; i++) {
	  if ((stat(mounts[i].f_mntonname, &dirstat) >= 0) &&
	      (filestat.st_dev == dirstat.st_dev)) {
	    s = strchr(mounts[i].f_mntfromname, ':');
	    if (s != NULL) {
	      *s = 0;
	      strncpy(hostname,mounts[i].f_mntfromname,sizeof(hostname));
	      hostname[sizeof(hostname)-1] = 0;
	      if (strncmp(s+1,"(pid",4) == 0) {
		/* Umm.. Most likely this is an automount mountpoint!
		   Lets try to find the real one, if we can! */
		continue;
	      }
	    } else {
	      strcpy(hostname,"localhost");
	    }
	    break;
	  }
	}
	/*free(mounts);*/ /* DONT FREE IT! */
	if (*hostname != 0)
	  return hostname;
	return NULL;
}
#else
#ifdef MOUNTED_GETMNTENT1
char *
whathost(file)
	const char	*file;
{
	FILE	*mntp;
	MNTTYPE	*mnt;
	struct stat	filestat, dirstat;
	char *s;

	if (stat(file, &filestat) < 0) {
		perror(file);
		return(NULL);
	}
	if ((mntp = setmntent(MOUNTED, "r")) == NULL) {
		perror(MOUNTED);
		return(NULL);
	}
	while ((mnt = getmntent(mntp)) != 0) {
		if (strcmp(mnt->mnt_type, MNTTYPE_IGNORE) == 0 ||
		    strcmp(mnt->mnt_type, MNTTYPE_SWAP) == 0)
			continue;
		if ((stat(mnt->mnt_dir, &dirstat) >= 0) &&
		   (filestat.st_dev == dirstat.st_dev)) {
			s = strchr(mnt->mnt_fsname,':');
			if (s != NULL) {
			  *s = 0;
			  strncpy(hostname,mnt->mnt_fsname,sizeof(hostname)-1);
			  hostname[sizeof(hostname)-1] = 0;
			} else
			    strcpy(hostname,"localhost");
			endmntent(mntp);
			return hostname;
		}
	}
	endmntent(mntp);
	return NULL;
}
#else
#ifdef MOUNTED_GETMNTENT2
char *
whathost(file)
	const char	*file;
{
	FILE	*mntp;
	MNTTYPE	*mnt;
	static MNTTYPE	rmnt;
	struct stat	filestat, dirstat;
	char *s;

	if (stat(file, &filestat) < 0) {
		perror(file);
		return(NULL);
	}
	mnt = &rmnt;
	if ((mntp = fopen(MNTTAB, "r")) == NULL) {
		perror(MNTTAB);
		return(NULL);
	}
	*hostname = 0;
	while (getmntent(mntp, mnt) == 0) {
	  if (strcmp(mnt->mnt_fstype, MNTTYPE_SWAP) == 0)
	    continue;
	  if ((stat(mnt->mnt_mountp, &dirstat) >= 0) &&
	      (filestat.st_dev == dirstat.st_dev)) {
	    /* So ok, filestat matches, but it may be an automount/autofs
	       mountpoint, try to recognize it too */
	    s = strchr(mnt->mnt_special,':');
	    if (s != NULL) {
	      *s = 0;
	      strncpy(hostname,mnt->mnt_special,sizeof(hostname)-1);
	      hostname[sizeof(hostname)-1] = 0;
	      if (strcmp(mnt->mnt_fstype,"autofs") == 0 /* Solaris */ ||
		  strncmp(s+1,"(pid",4) == 0 /* Other automounters */ )
		continue;
	    } else {
	      strcpy(hostname,"localhost");
	      if (strcmp(mnt->mnt_fstype, "autofs") == 0)
		continue;
	    }
	    fclose(mntp);
	    return hostname;
	  }
	}
	fclose(mntp);
	if (*hostname != 0)
	  return hostname;
	return NULL;
}
#else
#if defined(MOUNTED_VMOUNT) /* AIX */

/* Much of the following code is from GNU fileutils 3.13 */

char *
whathost(file)
	const char	*file;
{
	struct stat  dirstat, statb;
	int bufsize;
	char *entries, *thisent;
	struct vmount *vmp;
	char *dir, *host;

	/* Stat the file, is it a regular file, or a directory ? */
	if (stat(file, &statb) < 0)
		return NULL;
	if (statb.st_mode & S_IFMT & (S_IFREG|S_IFDIR) == 0)
	  return NULL;

	/* Ask how many bytes to allocate for the mounted filesystem info.  */
	mntctl (MCTL_QUERY, sizeof bufsize, (struct vmount *) &bufsize);
#ifdef USE_ALLOCA
	entries = alloca (bufsize);
#else
	entries = malloc (bufsize);
	if (entries == NULL) return NULL; /* Ah well... */
#endif
	
	/* Get the list of mounted filesystems.  */
	mntctl (MCTL_QUERY, bufsize, (struct vmount *) entries);

	vmp = NULL;
	for (thisent = entries; thisent < entries + bufsize;
	     thisent += vmp->vmt_length) {
	  
	  vmp  = (struct vmount *) thisent;
	  if (vmp->vmt_flags == -1) break;

	  dir  = thisent + vmp->vmt_data[VMT_STUB].vmt_off;

	  /* Stat it;  Is it at same device as the file/dir ? */
	  if (stat(dir,&dirstat) < 0 ||
	      dirstat.st_dev != statb.st_dev)
	    continue;

	  /* Now the mount-point device does match with the file device;
	     we know the mount-point where our file is located at! */

	  if (vmp->vmt_flags & MNT_REMOTE) {
	    /* A remote system! Return the hostname */
	    host = thisent + vmp->vmt_data[VMT_HOSTNAME].vmt_off;
	    strncpy(hostname,host,sizeof(hostname));
	    hostname[sizeof(hostname)-1] = 0;
#ifndef USE_ALLOCA
	    free(entries);
#endif
	    return hostname;
	  } else {
#ifndef USE_ALLOCA
	    free(entries);
#endif
	    return "localhost";
	  }
	}

#ifndef USE_ALLOCA
	free(entries);
#endif
	return NULL;
}

#else	/* Not AIX -- all other systems .. */

error:error:error: Unknown/unimplemented filesystem mount-info method

#endif
#endif
#endif
#endif
#endif
