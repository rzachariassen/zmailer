/*
 *  zmpoll() -- A routine for ZMailer  libz.a -library.
 *
 *  All former  select()  things are now done thru  zmpoll()  interface,
 *  even in machines that don't have real poll underneath.
 *  (Most do, which is good..)
 *
 *  Copyright Matti Aarnio, 2006
 */

#ifndef __ZM_POLL_H__
#define __ZM_POLL_H__ 1

#define ZM_POLLIN   0x001
#define ZM_POLLPRI  0x002  /* Never used by ZMailer codes */
#define ZM_POLLOUT  0x004

#define ZM_POLLERR  0x008
#define ZM_POLLHUP  0x010
#define ZM_POLLNVAL 0x020


struct zmpollfd {
  int fd;
  short events;
  short revents;
  struct zmpollfd **backptr;
};

extern int zmpoll __((struct zmpollfd *__fds, int __nfds, long __timeout));

/*  rdfd >= 0  -->  POLLIN,   wrfd >= 0  -->  POLLOUT, if polling same fd
    for both directions, both fds must be same.  */
extern int zmpoll_addfd __((struct zmpollfd **fdsp, int* nfdsp, int rdfd, int wrfd, struct zmpollfd **backptr));

#endif
