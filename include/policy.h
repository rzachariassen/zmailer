/*
 *  policy.h  -- ZMailer's smtpserver's runtime address acceptance
 *               policy database mechanisms.
 *
 *  By Matti Aarnio <mea@nic.funet.fi> after the model of
 *  Gabor Kiss's <kissg@sztaki.hu> first edition, which
 *  did require a router running in parallel to resolve
 *  each and all of the SMTP session's address processings.
 *  (Uhh... ... the load..)
 *
 */

/* All entries on the database are of triple-form:
     u_char len		-- total length of this triplet
     u_char type
     u_char data[*]
   That is, all keys, and all attribute/value -pairs are presented
   with this form of data. */

struct policy {
	unsigned char len;
	unsigned char type;
	unsigned char data[1];
};

#define P_K_IPv4   1 /* [128.214.6.0]/24 -- translated into binary form */
		     /* Alternative form:  128.214.6.0/24               */
struct policy_ipv4 {
	unsigned char len;
	unsigned char type;
	unsigned char ipnum[4];
	unsigned char width;
};
#define P_K_IPv6   2 /* [ipv6.::ffff:128.214.248.0]/120 -- translated...*/
		     /* Alternative form:  ::ffff:128.214.248.0/120     */
struct policy_ipv6 {
	unsigned char len;
	unsigned char type;
	unsigned char ipnum[16];
	unsigned char width;
};
#define P_K_TAG    3 /* Starts with an underscore -- fully in ASCII,
			and with \000 for the end of the string         */
struct policy_tag {
	unsigned char len;
	unsigned char type;
	unsigned char tag[1];
};
#define P_K_DOMAIN 4 /* Any (possibly w/ leading dot) name - in ASCII,
		        and in all-lowercase, and with string ending 0.	*/
struct policy_dom {
	unsigned char len;
	unsigned char type;
	unsigned char dom[1];
};
#define P_K_USER   5 /* Starts with @    -- fully in ASCII, string
			ending with \000                                */
struct policy_user {
	unsigned char len;
	unsigned char type;
	unsigned char tag[1];
};


/* Attributes */

#define P_A_ALIAS		1
#define P_A_REJECTNET		2
#define P_A_FREEZENET		3
#define P_A_REJECTSOURCE	4
#define P_A_FREEZESOURCE	5
#define P_A_RELAYCUSTOMER	6
#define P_A_RELAYCUSTNET	7
#define P_A_RELAYTARGET		8
#define P_A_ACCEPTifMX          9
#define P_A_ACCEPTifDNS         10
#define P_A_SENDERokWithDNS	11
#define P_A_ACCEPTbutFREEZE	12
#define P_A_SENDERNoRelay	13
#define P_A_TestDnsRBL		14
#define P_A_MESSAGE		15
#define P_A_LocalDomain		16

#define P_A_FirstAttr	        2
#define P_A_LastAttr	        16
/* Note: Attribute codes outside range 1..31 cause problems at policystate
         processing!  If you ever need modify these, fix the  policytest.c,
	 and  policytest.h: struct policystate { char values[]; } array,
	 very least... */

struct attribute {
	unsigned char len;
	unsigned char attrib;
	unsigned char data[1];
};

#ifdef _POLICYTEST_INTERNAL_

static char *_KK[] = {
	"UNKNOWN",
	"IPv4",
	"IPv6",
	"TAG",
	"DOMAIN",
	"USER"
};
#define MAX_KK 5
#define KK(x) ((((x)>0)&&((x)<=MAX_KK))?_KK[(x) & 0xFF]:"??")

static char *_KA[] = {
	"UNKNOWN",
	"alias",
	"rejectnet",
	"freezenet",
	"rejectsource",
	"freezesource",
	"relaycustomer",
	"relaycustnet",
	"relaytarget",
	"acceptifmx",
	"acceptifdns",
	"senderokwithdns",
	"acceptbutfreeze",
	"sendernorelay",
	"test-dns-rbl",
	"message",
	"localdomain",
};
#define KA(x) ((((x)>0)&&((x)<=P_A_LastAttr))?_KA[(x) & 0xFF]:"??")

#endif
