/*
 * Signal portability things for ZMailer
 *
 * By Matti Aarnio <mea@utu.fi> 1995
 *
 */

/* TO BE CALLED AFTER   #include "hostenv.h"  !!! */

#include <signal.h>

#ifndef RETSIGTYPE
#define RETSIGTYPE void	/* Propably not globally portable.. */
#endif

#if defined(SV_INTERRUPT) && !defined(HAVE_SIGPROCMASK)	/* BSDism */
	/* ================ BSD 4.3+ (?) STUFF ================ */
#define	SIGNAL_HANDLE(X,Y)	\
	{	struct sigvec sv;			\
		sigvec(X, (struct sigvec *)NULL, &sv);	\
		sv.sv_handler = Y;			\
		sv.sv_flags |= SV_INTERRUPT;		\
		sigvec(X, &sv, (struct sigvec *)NULL);	\
	}
#define	SIGNAL_HANDLESAVE(X,Y,OLD)	\
	{	struct sigvec sv;			\
		sigvec(X, (struct sigvec *)NULL, &sv);	\
		OLD = sv.sv_handler;			\
		sv.sv_handler = Y;			\
		sv.sv_flags |= SV_INTERRUPT;		\
		sigvec(X, &sv, (struct sigvec *)NULL);	\
	}
#define SIGNAL_HOLD(SIG) \
	sigblock(sigmask(SIG))
#define SIGNAL_RELEASE(SIG) \
	sigsetmask(~sigmask(SIG) & sigblock(SIGNAL_HOLD(SIG)))
#define SIGNAL_IGNORE(SIG) \
	SIGNAL_HANDLE(SIG,SIG_IGN)

#else	/* No SIGVEC stuff */

#if	defined(SA_NOCLDSTOP)||defined(SA_ONSTACK)||defined(SA_RESTART)
	/* ================ POSIX.1 STUFF ================ */
#ifndef SA_NODEFER
# define SA_NODEFER 0
#endif
#ifdef SA_INTERRUPT
#define SIGNAL_HANDLE(X,Y) \
	{	struct sigaction act;		\
		act.sa_handler = Y;		\
		act.sa_flags   = SA_INTERRUPT|SA_NODEFER; \
		sigemptyset(&act.sa_mask);	\
		sigaction (X, &act, NULL);	\
	}
#define SIGNAL_HANDLESAVE(X,Y,OLD) \
	{	struct sigaction act, oact;	\
		act.sa_handler = Y;		\
		act.sa_flags   = SA_INTERRUPT|SA_NODEFER; \
		sigemptyset(&act.sa_mask);	\
		sigemptyset(&oact.sa_mask);	\
		sigaction (X, &act, &oact);	\
		OLD = oact.sa_handler;		\
	}
#define SIGNAL_HOLD(SIG) \
	{	sigset_t	sigmsk;		\
		sigemptyset(&sigmsk);		\
		sigaddset(&sigmsk,SIG);		\
		sigprocmask(SIG_BLOCK,&sigmsk,NULL);	\
	}
#define SIGNAL_RELEASE(SIG) \
	{	sigset_t	sigmsk;		\
		sigemptyset(&sigmsk);		\
		sigaddset(&sigmsk,SIG);		\
		sigprocmask(SIG_UNBLOCK,&sigmsk,NULL);	\
	}
#define SIGNAL_IGNORE(SIG) \
	SIGNAL_HANDLE(SIG,SIG_IGN)

#else /* No  SA_INTERRUPT */

#define SIGNAL_HANDLE(X,Y) \
	{	struct sigaction act;		\
		act.sa_handler = Y;		\
		act.sa_flags   = SA_NODEFER;	\
		sigemptyset(&act.sa_mask);	\
		sigaction (X, &act, NULL);	\
	}
#define SIGNAL_HANDLESAVE(X,Y,OLD) \
	{	struct sigaction act, oact;	\
		act.sa_handler = Y;		\
		act.sa_flags   = SA_NODEFER;	\
		sigemptyset(&act.sa_mask);	\
		sigemptyset(&oact.sa_mask);	\
		sigaction (X, &act, &oact);	\
		OLD = oact.sa_handler;		\
	}
#define SIGNAL_HOLD(SIG) \
	{	sigset_t	sigmsk;		\
		sigemptyset(&sigmsk);		\
		sigaddset(&sigmsk,SIG);		\
		sigprocmask(SIG_BLOCK,&sigmsk,NULL);	\
	}
#define SIGNAL_RELEASE(SIG) \
	{	sigset_t	sigmsk;		\
		sigemptyset(&sigmsk);		\
		sigaddset(&sigmsk,SIG);		\
		sigprocmask(SIG_UNBLOCK,&sigmsk,NULL);	\
	}
#define SIGNAL_IGNORE(SIG) \
	SIGNAL_HANDLE(SIG,SIG_IGN)
#endif /* no SA_INTERRUPT */
	
#else	/* No SIGACTION (POSIX), nor SIGVEC stuff */

	/* ================ Everything  else.. ================ */
	/*         ...  Well, I think it is  SVR3 ...		*/
#define	SIGNAL_HANDLE(X,Y)	\
		signal(X,Y)
#define	SIGNAL_HANDLESAVE(X,Y,OLD)	\
		OLD=signal(X,Y)
#define SIGNAL_HOLD(SIG) \
		sighold(SIG)
#define SIGNAL_RELEASE(SIG) \
		sigrelse(SIG)
#define SIGNAL_IGNORE(SIG) \
		sigignore(SIG)

#endif
#endif

#ifndef SIGCHLD
#define SIGCHLD SIGCLD
#endif
