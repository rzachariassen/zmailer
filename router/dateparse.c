/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Maintenance by Ken Lalonde, 1999.
 */
/*
  From: Ken Lalonde <ken@uunet.ca>
  To:   mea@nic.funet.fi
  Subject: Bug fix for zmailer-2.99.50s11/router/dateparse.c
  Date: Fri, 5 Feb 1999 16:39:45 -0500

  Hi Matti,

  The router/dateparse.c code doesn't handle year 2000 dates correctly.
  I don't think this actually matters very much,
  but just in case, here's a version that does.

  All the best,

  Ken Lalonde
  Network Engineering
  UUNET, an MCI WorldCom Company
  Phone: +1 416-216-5133 Fax: +1 416-368-4080
*/

/*

  Yes, however USAGE of this code is limited; while it does get
  called by the router, it's result is effectively ignored.
  People do produce copious amounts of "Date:" headers that are
  so ingenuinely wrong in syntax, that spending time in parsing
  them is wasted time.. :-(    Ignoring that wastage, current
  Mailer passes on arriving "Date:" header, and generates one
  only when it doesn't exist in the arriving headers.

  However somebody may decide to reuse this code somewhere else;
  at some userspace program, for example, which can live with that
  ugly fact of life..

  /Matti Aarnio <mea@nic.funet.fi>

 */

/*
 * RFC822 date routines.
 *
 * The functions in this file will parse and generate RFC822 format dates.
 * In fact, the date parser accepts date strings in quite a variety of
 * formats, in accordance with the lack of adhered-to standards in this
 * area. The actual parsing code was originally inspired by the complexity
 * of a yacc-based date parser by Rich Wales. The language spanned by that
 * parser was very simple:
 *
 *	(MONTH_NAME [.] | num)[/- ](day-number)[/- ](yy[yy]) (DAY_NAME[.]) time
 *
 *	time: [ hh[[:.]mm[[:.]ss]] ] [ AM/PM ] [ zone ]
 *
 *	zone:	  [-] STD_ZONE [ DST_SUFFIX ]
 *		| [-] DST_ZONE
 *		| {+|-} [+|-] hh[[:.]mm]
 *
 * The token-based parser here is intended to implement a more flexible
 * version of this grammar. Individual tokens are identified as to their
 * possible meaning, and are then pinned down by a relaxation scheme.
 * Seems to work pretty well, but I didn't lose the complexity, alas.
 */

#include "hostenv.h"
#include "mailer.h"
#include <ctype.h>

extern int cistrncmp();

/* The following table and binary search code originally by Rich Wales */

typedef enum { nilDate, Month, AmPm, StdZone, DstZone, Day } DateType;

static DateType was;

/* Binary-search symbol table. */

static struct wordtable {
	char		*text;
	DateType	type;
	int  		value;
} wordtable[] = {
    /* text            token          lexval */
	{ "A",		StdZone,	60 },	/* UTC+1h */
	{ "ACSST",	DstZone,	630 },	/* Cent. Australia */
	{ "ACST",	StdZone,	570 },	/* Cent. Australia */
	{ "ADT",	DstZone,	-180 },	/* Atlantic Daylight Time */
	{ "AESST",	DstZone,	660 },	/* E. Australia */
	{ "AEST",	StdZone,	600 },	/* Australia Eastern Std Time */
	{ "AHST",	StdZone,	600 },	/* Alaska-Hawaii Std Time */
	{ "AM",		AmPm,		0 },
	{ "APR",	Month,		4 },
	{ "APRIL",	Month,		4 },
	{ "AST",	StdZone,	-240 },	/* Atlantic Std Time (Canada) */
	{ "AT",		nilDate,	0 },	/* "at" (throwaway) */
	{ "AUG",	Month,		8 },
	{ "AUGUST",	Month,		8 },
	{ "AWSST",	DstZone,	540 },	/* W. Australia */
	{ "AWST",	StdZone,	480 },	/* W. Australia */
	{ "B",		StdZone,	120 },	/* UTC+2h */
	{ "BST",	StdZone,	60 },	/* British Summer Time */
	{ "BT",		StdZone,	180 },	/* Baghdad Time */
	{ "C",		StdZone,	180 },	/* UTC+3h */
	{ "CADT",	DstZone,	630 },	/* Central Australian DST */
	{ "CAST",	StdZone,	570 },	/* Central Australian ST */
	{ "CAT",	StdZone,	-600 },	/* Central Alaska Time */
	{ "CCT",	StdZone,	480 },	/* China Coast */
	{ "CDT",	DstZone,	-300 },	/* Central Daylight Time */
	{ "CET",	StdZone,	60 },	/* Central European Time */
	{ "CETDST",	DstZone,	120 },	/* Central European Dayl.Time */
	{ "CST",	StdZone,	-360 },	/* Centrail Standard Time */
	{ "D",		StdZone,	240 },	/* UTC+4h */
	{ "DEC",	Month,		12 },
	{ "DECEMBER",	Month,		12 },
	{ "DNT",	StdZone,	60 },	/* Dansk Normal Tid */
	{ "DST",	nilDate,	0 },
	{ "E",		StdZone,	300 },	/* UTC+5h */
	{ "EAST",	StdZone,	-600 },	/* East Australian Std Time */
	{ "EDT",	DstZone,	-240 },	/* Eastern Daylight Time */
	{ "EET",	StdZone,	120 },	/* East. Europe, USSR Zone 1 */
	{ "EETDST",	DstZone,	180 },	/* Eastern Europe */
	{ "EST",	StdZone,	-300 },	/* Eastern Standard Time */
	{ "F",		StdZone,	360 },	/* UTC+6h */
	{ "FEB",	Month,		2 },
	{ "FEBRUARY",	Month,		2 },
	{ "FRI",	Day,		5 },
	{ "FRIDAY",	Day,		5 },
	{ "FST",	StdZone,	60 },	/* French Summer Time */
	{ "FWT",	DstZone,	120 },	/* French Winter Time  */
	{ "G",		StdZone,	420 },	/* UTC+7h */
	{ "GMT",	StdZone,	0 },	/* Greenwish Mean Time */
	{ "GST",	StdZone,	600 },	/* Guam Std Time, USSR Zone 9 */
	{ "H",		StdZone,	480 },	/* UTC+8h */
	{ "HDT",	DstZone,	-540 },	/* Hawaii/Alaska */
	{ "HMT",	DstZone,	180 },	/* Hellas ? ? */
	{ "HST",	StdZone,	-600 },	/* Hawaii Std Time */
	{ "I",		StdZone,	540 },	/* UTC+9h */
	{ "IDLE",	StdZone,	720 },	/* Intl. Date Line, East */
	{ "IDLW",	StdZone,	-720 },	/* Intl. Date Line, West */
	{ "IST",	StdZone,	120 },	/* Israel */
	{ "IT",		StdZone,	220 },	/* Iran Time */
	{ "JAN",	Month,		1 },
	{ "JANUARY",	Month,		1 },
	{ "JST",	StdZone,	540 },	/* Japan Std Time,USSR Zone 8 */
	{ "JT",		StdZone,	450 },	/* Java Time */
	{ "JUL",	Month,		7 },
	{ "JULY",	Month,		7 },
	{ "JUN",	Month,		6 },
	{ "JUNE",	Month,		6 },
	{ "K",		StdZone,	600 },	/* UTC+10h */
	{ "KST",	StdZone,	540 },	/* Korea Standard Time */
	{ "L",		StdZone,	660 },	/* UTC+11h */
	{ "LIGT",	StdZone,	600 },	/* From Melbourne, Australia */
	{ "M",		StdZone,	720 },	/* UTC+12h */
	{ "MAR",	Month,		3 },
	{ "MARCH",	Month,		3 },
	{ "MAY",	Month,		5 },
	{ "MDT",	DstZone,	-360 },	/* Mountain Daylight Time */
	{ "MEST",	DstZone,	120 },	/* Middle Europe Summer Time */
	{ "MET",	StdZone,	60 },	/* Middle Europe Time */
	{ "METDST",	DstZone,	120 },	/* Middle Europe Daylight Time*/
	{ "MEWT",	StdZone,	60 },	/* Middle Europe Winter Time */
	{ "MEZ",	StdZone,	60 },	/* Mittel Europaeische Zeigt */
	{ "MON",	Day,		1 },
	{ "MONDAY",	Day,		1 },
	{ "MST",	StdZone,	-420 },	/* Mountain Standard Time */
	{ "MT",		StdZone,	510 },	/* Moluccas Time */
	{ "N",		StdZone,	-60 },	/* UTC-1h */
	{ "NDT",	DstZone,	-150 },	/* Nfld. Daylight Time */
	{ "NFT",	StdZone,	-210 },	/* Newfoundland Standard Time */
	{ "NOR",	StdZone,	60 },	/* Norway Standard Time */
	{ "NOV",	Month,		11 },
	{ "NOVEMBER",	Month,		11 },
	{ "NST",	StdZone,	-210 },	/* Nfld. Standard Time */
	{ "NT",		StdZone,	-660 },	/* Nome Time */
	{ "NZDT",	DstZone,	780 },	/* New Zealand Daylight Time */
	{ "NZST",	StdZone,	720 },	/* New Zealand Standard Time */
	{ "NZT",	StdZone,	720 },	/* New Zealand Time */
	{ "O",		StdZone,	-120 },	/* UTC-2h */
	{ "OCT",	Month,		10 },
	{ "OCTOBER",	Month,		10 },
	{ "ON",		nilDate,	0 },	/* "on" (throwaway) */
	{ "P",		StdZone,	-180 },	/* UTC-3h */
	{ "PDT",	DstZone,	-420 },	/* Pacific Daylight Time */
	{ "PM",		AmPm,		720 },
	{ "PST",	StdZone,	-480 },	/* Pacific Standard Time */
	{ "Q",		StdZone,	-240 },	/* UTC-4h */
	{ "R",		StdZone,	-300 },	/* UTC-5h */
	{ "S",		StdZone,	-360 },	/* UTC-6h */
	{ "SADT",	DstZone,	630 },	/* S. Australian Dayl. Time */
	{ "SAST",	StdZone,	570 },	/* South Australian Std Time */
	{ "SAT",	Day,		6 },
	{ "SATURDAY",	Day,		6 },
	{ "SEP",	Month,		9 },
	{ "SEPT",	Month,		9 },
	{ "SEPTEMBER",	Month,		9 },
	{ "SET",	StdZone,	-60 },	/* Seychelles Time ?? */
	{ "SST",	DstZone,	120 },	/* Swedish Summer Time */
	{ "SUN",	Day,		0 },
	{ "SUNDAY",	Day,		0 },
	{ "SWT",	StdZone,	60 },	/* Swedish Winter Time  */
	{ "T",		StdZone,	-420 },	/* UTC-7h */
	{ "THU",	Day,		4 },
	{ "THUR",	Day,		4 },
	{ "THURS",	Day,		4 },
	{ "THURSDAY",	Day,		4 },
	{ "TUE",	Day,		2 },
	{ "TUES",	Day,		2 },
	{ "TUESDAY",	Day,		2 },
	{ "U",		StdZone,	-480 },	/* UTC-8h */
	{ "UT",		StdZone,	0 },
	{ "UTC",	StdZone,	0 },
	{ "V",		StdZone,	-540 },	/* UTC-9h */
	{ "W",		StdZone,	-600 },	/* UTC-10h */
	{ "WADT",	DstZone,	480 },	/* West Australian DST */
	{ "WAST",	StdZone,	420 },	/* West Australian Std Time */
	{ "WAT",	StdZone,	-60 },	/* West Africa Time */
	{ "WDT",	DstZone,	540 },	/* West Australian DST */
	{ "WED",	Day,		3 },
	{ "WEDNESDAY",	Day,		3 },
	{ "WEDS",	Day,		3 },
	{ "WET",	StdZone,	0 },	/* Western Europe */
	{ "WETDST",	DstZone,	60 },	/* Western Europe */
	{ "WST",	StdZone,	480 },	/* West Australian Std Time */
	{ "X",		StdZone,	-660 },	/* UTC-11h */
	{ "Y",		StdZone,	-720 },	/* UTC-12h */
	{ "YDT",	DstZone,	-480 },	/* Yukon Daylight Time */
	{ "YST",	StdZone,	-540 },	/* Yukon Standard Time */
	{ "Z",		StdZone,	0 },	/* UTC */
	{ "ZP4",	StdZone,	-240 },	/* GMT +4  hours. */
	{ "ZP5",	StdZone,	-300 },	/* GMT +5  hours. */
	{ "ZP6",	StdZone,	-360 }	/* GMT +6  hours. */
};

#if	0
/* These time zones are orphans, i.e. the name is also used by a more
   likely-to-appear time zone */
	"AT",		StdZone,	-120,	/* Azores Time */
	"BST",		StdZone,	-180,	/* Brazil Std Time */
	"BT",		StdZone,	-660,	/* Bering Time */
	"EDT",		StdZone,	660,	/* Australian Eastern DaylTime*/
	"EST",		StdZone,	600,	/* Australian Eastern Std Time*/
	"IST",		StdZone,	330,	/* Indian Standard Time */
	"NST",		StdZone,	510,	/* North Sumatra Time */
	"SST",		StdZone,	420,	/* South Sumatra, USSR Zone 6 */
	"SST",		StdZone,	480,	/* Singapore Std Time */
	"WET",		StdZone,	60,	/* Western European Time */
#endif

/*
 * Lilian day calculation, from
 * http://www.software.ibm.com/year2000/tips15.html
 */
#define INT(x) (x)	/* just to keep the formulae the same */

static int lilian __((int yyyy, int mm, int dd));

static int
lilian(yyyy, mm, dd)
	int yyyy, mm, dd;
{
	int ly, nnn, lil;

	/* Determine day in year (nnn) */
	ly = yyyy%4 == 0 ? 1 : 0;
	if (yyyy%100 == 0) ly = 0;
	if (yyyy%400 == 0) ly = 1;
	nnn = INT(3 / (mm + 1)) * (31 * (mm -1) + dd) + 
		INT((mm + 9) / 12) * (INT(((305 * (mm - 1) - 15) +
		INT((mm + 3) / 12) * 5 * INT(18 / mm)) / 10) +
		dd + ly);
	/* Determine Lilian day from YYYY NNN */
	lil = INT(((yyyy - 1201) * 36525) / 100) -
		139444 + nnn -
		INT((yyyy - 1201) / 100)+
		INT((yyyy - 1201) / 400);
	return lil;
}

/* Multiple-value return of token type and value */

static int
dateToken(s, len)
	register char *s;
	register int len;
{
	register int low, mid, high;
	register int comparison;

	low = 0;
	high = sizeof wordtable / sizeof wordtable[0] - 1;
	while (high >= low) {
		mid = (low + high) / 2;
		comparison = *wordtable[mid].text -
					(islower(*s) ? toupper(*s) : *s);
		if (comparison == 0) {
			comparison = cistrncmp(wordtable[mid].text, s, len);
			if (comparison == 0) {
				if (wordtable[mid].text[len] != '\0') {
					comparison = 1;
				} else {
					was = wordtable[mid].type;
					return wordtable[mid].value;
				}
			}
		}
		if (comparison > 0)
			high = mid - 1;
		else
			low = mid + 1;
	}
	was = nilDate;
	return 0;
}

/* Bits in a flag describing possible semantics of each token */

#define	HHMMSS	01		/* hours-minutes-seconds, e.g. 213245 */
#define HHMM	02		/* hours-minutes, e.g. 2132 */
#define	HH	04		/* hours, 0 <= HH < 24 */
#define MM	010		/* minutes, 0 <= MM < 60 */
#define SS	020		/* seconds, 0 <= SS < 60 */
#define MIY	040		/* month-in-year, e.g. Jan */
#define	DD	0100		/* day-in-month, e.g. 5 */
#define YY	0200		/* year-in-century, e.g. 88 */
#define YYYY	0400		/* anno domini */
#define MAXFLAG	YYYY		/* used to tell if one & only one bit is set */

/*
 * Parse a tokenlist scanned from a date-string.
 */

long
dateParse(localtmptr, t)
	struct tm *localtmptr;
	token822 *t;
{
	register int	val = 0, i, could_be;
	int	century, year, month, dayinmonth, days;
	int	*prev_could_be, j, index, zone, aval, zoneindex, expect_zone;
#define TYPESMAX 50
	int     values[TYPESMAX], types[TYPESMAX];      /* TODO: fix limits */
	long	sec;
	int	have_year = 0;
	static int this_century = -1;

	if (this_century < 0)
		this_century = (localtmptr->tm_year + 1900) / 100;
	index = 0;
	zone = 0;		/* minutes offset from UTC */
	zoneindex = 0;
	expect_zone = 0;
	types[0] = 0;
	prev_could_be = &types[0];
	for (; t != NULL; t = t->t_next) {
		/* if (t->t_type != Atom)
			continue; */
		if (t->t_type == Comment || t->t_type == Space)
			continue;
		/* X: need to take care of embedded slashes */
		could_be = 0;
		if (*(t->t_pname) >= '0' && *(t->t_pname) <= '9') {
			if (t->t_len == 0)
				val = atoi((char *)t->t_pname);
			else {
				val = 0;
				for (i = 0; i < t->t_len; ++i)
					val = 10*val + (*(t->t_pname+i) - '0');
			}
			if (expect_zone != 0) {
				aval = abs(val);
				if (aval < 24) {
					zone += val * 60 * expect_zone;
					continue;
				} else if (aval >= 100 && aval%100 < 60) {
					zone += (val%100 + (val/100)*60)
						* expect_zone;
					continue;
				}
			}
			if (val < 13)
				could_be |= MIY;
			if (val < 24)
				could_be |= HH;
			if (val < 32)
				could_be |= DD;
			if (val < 60) {
				if ((*prev_could_be) & HH)
					could_be |= MM;
				if ((*prev_could_be) & MM)
					could_be |= SS;
				if (this_century >= 20)
					could_be |= YY;
			}
			if (val > 59) {
				if (val < 100)
					could_be |= YY;
				else {
					if (val%100 < 60) {
						if (val < 2400)
							could_be |= HHMM;
						else if (val > 10000
						    && val < 240000
						    && (val%10000) < 2400)
							could_be |= HHMMSS;
					}
					if (val/100 == this_century ||
					   (val/100 == this_century+1
						    && val%100 <= 20))
						could_be |= YYYY;
				}
			}
		} else if (*(t->t_pname) == '+' || *(t->t_pname) == '-') {
			/*
			 * Either it is GMT+5 or similar, or we are looking
			 * at 7-APR-88 (or APR-7-88 or 88-APR-7 etc) type thing,
			 * or it is -0400 timezone offset like MH spits out.
			 */
			if ((zoneindex > 0 && zoneindex == index - 1)
			    || (zoneindex == 0 && t->t_len > 1)) {
				if ((*prev_could_be) & (SS|MM|HH|HHMM|HHMMSS))
					*prev_could_be &= SS|MM|HH|HHMM|HHMMSS;
				j = 1;
				if (*(t->t_pname) == '-')
					j = -j;
				if (t->t_len == 1) {
					if (t->t_next != NULL)
						t = t->t_next;
					else
						break;
				}
				if (t->t_len == 0)
					val = atoi((char *)t->t_pname);
				else {
					val = 0;
					i = *(t->t_pname) == '-'
						|| *(t->t_pname) == '+';
					for (; i < t->t_len; ++i) {
						val = 10*val
						    + (*(t->t_pname+i) - '0');
					}
				}
				val *= j;
				aval = abs(val);
				if (aval < 24)
					zone += val * 60;
				else	/* be careful about minutes */
					zone += val%100 + (val/100)*60;
			} else if (*(t->t_pname) == '+')
				expect_zone = 1;
			else
				expect_zone = -1;
			continue;	/* don't null expect_zone at bottom */
		} else if (*(t->t_pname) == '.') {
			/* ignore this one and the next one */
			if (t->t_next != NULL)
				t = t->t_next;
		} else if (*(t->t_pname) == ':') {
			/* colon is typically always after HH or MM */
			if ((*prev_could_be) & (HH|MM))
				*prev_could_be &= HH|MM;
		} else {
			val = dateToken((char *)t->t_pname, (int)t->t_len);
			switch (was) {
			case Month:
				could_be = MIY;
				break;
			case AmPm:
			case StdZone:
			case DstZone:
				if ((*prev_could_be) & (SS|MM|HH|HHMM|HHMMSS))
					*prev_could_be &= SS|MM|HH|HHMM|HHMMSS;
				zone += val;
				zoneindex = index;
				break;
			default:
				break;
			}
		}
		if (could_be) {
			values[index] = val;
			types[index] = could_be;
			prev_could_be = &types[index];
			++index;
		}
		expect_zone = 0;
	}
	/* internal constraints */
again:	/* \relax */
	val = 0;
	for (i = 0; i < index; ++i) {
		/* If types[i] has exactly one bit set... */
		if (types[i] != 0 && (MAXFLAG/types[i])*types[i] == MAXFLAG)
			val |= types[i];
	}
	for (i = 0; i < index; ++i) {
		if ((types[i]&val) != types[i])
			types[i] &= ~val;
	}
	/* the day of month is either just before or just after the month */
	if (val & MIY) {
		for (i = 0; i < index; ++i)
			if (types[i] == MIY) {
				if (i > 0 && (types[i-1] & DD)
				    && (i+1 == index || !(types[i+1] & DD))) {
					types[i-1] = DD;
					val |= DD;
				}
				if (i+1 < index && (types[i+1] & DD)
				    && (i == 0 || !(types[i-1] & DD))) {
					types[i+1] = DD;
					val |= DD;
				}
				break;
			}
	}
	/* enforce HH MM SS order */
	if (val & HHMM) {
		for (i = 0; i < index; ++i)
			if (types[i]&(HH|MM|HHMMSS))
				types[i] &= ~(HH|MM|HHMMSS);
	}
	if (val & HHMMSS) {
		for (i = 0; i < index; ++i)
			if (types[i]&(HH|MM|SS|HHMM))
				types[i] &= ~(HH|MM|SS|HHMM);
	}
	if (val & SS) {
		for (i = 0; i < index; ++i)
			if (types[i] == SS) {
				if (i > 0 && (types[i-1] & MM)) {
					types[i-1] = MM;
					val |= MM;
				}
				break;
			}
	}
	if (val & HH) {
		for (i = 0; i < index; ++i)
			if (types[i] == HH) {
				if (i+1 < index && (types[i+1] & MM)) {
					types[i+1] = MM;
					val |= MM;
				}
				break;
			}
	}
	if (val & MM) {
		for (i = 0; i < index; ++i)
			if (types[i] == MM) {
				if (i > 0 && (types[i-1] & HH)) {
					types[i-1] = HH;
					val |= HH;
				}
				if (i+1 < index && (types[i+1] & SS)) {
					types[i+1] = SS;
					val |= SS;
				}
				break;
			}
	}
	for (i = 0; i < index; ++i) {
		if ((types[i]&val) != types[i])
			types[i] &= ~val;
	}
	/* disambiguate stuff... */
	for (i = 0; i < index; ++i) {
		if (types[i] == 0)
			continue;
		if ((MAXFLAG/types[i])*types[i] != MAXFLAG) {
			/* There's more than one bit set */
			if (zoneindex >= i+1 && zoneindex <= i+3) {
				if (types[zoneindex-1] & (MM|SS))
					types[--zoneindex] &= (MM|SS);
				if (types[zoneindex-1] & (HH|MM|HHMM))
					types[--zoneindex] &= (HH|MM|HHMM);
				if (zoneindex > 0 && (types[zoneindex-1] & HH))
					types[--zoneindex] &= HH;
				zoneindex = 0;
				goto again;
			} else if ((types[i] & MIY)
				   && i+1 < index && (types[i+1] & DD)) {
				types[i] &= MIY;
				types[i+1] &= DD;
				goto again;
			} else if ((types[i] & MM)
				   && i+1 < index && (types[i+1] & SS)) {
				types[i] &= MM;
				types[i+1] &= SS;
				goto again;
			} else if ((types[i] & YYYY)
				   && ((i+1 < index
					    && (types[i+1] & (HH|HHMM|HHMMSS))
					    == types[i+1])
				       || (i > 0 && types[i-1] == DD))) {
				types[i] &= YYYY;
			}
		}
	}
	century = month = dayinmonth = -1;
	year = 0;
	sec = 0;
	for (i = 0; i < index; ++i) {
		switch (types[i]) {
		case HHMMSS:	sec = values[i]%100;
				values[i] /= 100;
		case HHMM:	sec += 60 * values[i]%100;
				values[i] /= 100;
		case HH:	values[i] *= 60;
		case MM:	values[i] *= 60;
		case SS:	sec += values[i];
				break;
		case MIY:	month = values[i];
				break;
		case DD:	dayinmonth = values[i];
				break;
		case YY:
				/* 00..38 => next century */
				/* 39 .. 99 => this one */
				values[i] += values[i] > 38 ? 1900 : 2000;
		case YYYY:
				if (types[i] == YYYY)
					have_year++;	/* explicit year */
				year += values[i]%100;
				century = values[i]/100;
				break;
		}
	}
	if (century < 0)	/* default century */
		century = this_century;
	if (year <= 0 && !have_year) /* default year (wraparound buggy...) */
		year += localtmptr->tm_year%100;
	if (month < 0) 	/* default month */
		month = localtmptr->tm_mon + 1;
	if (dayinmonth < 0)	/* default day in month */
		dayinmonth = localtmptr->tm_mday;
	days = lilian(century*100+year, month, dayinmonth) - lilian(1970, 1, 1);
	sec += (days * 24 * 60 - zone) * 60;
	return sec < 0 ? 0L : sec;
}
