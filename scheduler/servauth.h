/*
 *	ZMailer 2.99.50 Scheduler mailq authentication mechanism
 *
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1998
 *
 */

#define ZSVAUTH_NONE	0x0000	/* No rights */
#define ZSCAUTH_MAILQ	0x0001	/* Queue lookups via MAILQ */
#define ZSCAUTH_ETRN	0x0002	/* ETRN via MAILQ */
#define ZSCAUTH_MSGDEL	0x0004	/* Delete one msg */
