/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include "mailer.h"
#include <ctype.h>
#include "libz.h"

extern int optind;
extern char *optarg;
char *progname = "rfc822test";
int D_alloc = 0;

extern union misc parse822();
extern token822 *readlines();
extern time_t time();
extern int fprintToken();

int
main(argc, argv)
	int argc;
	char *argv[];
{
	register token822 *t;
	u_long	len;
	time_t now;
	const u_char	*cp, *ocp;
	int c;
	HeaderSemantics entry_pt;
	token822 *tlist, **prev_tp, *scan_t, *nt;
	struct address *a;
	struct addr *p;
	struct tm localtm;
	union misc val;
	FILE *tracefp;

	entry_pt = AddressList;
	tracefp = NULL;
	while ((c = getopt(argc, argv, "e:T")) != EOF) {
		switch (c) {
		case 'e':
			entry_pt = (HeaderSemantics)atoi(optarg);
			break;
		case 'T':
			tracefp = stdout;
			(void) setvbuf(stdout, (char *)NULL, _IOLBF, 0);
			break;
		}
	}
again:
	tlist = NULL;
	prev_tp = &tlist;
	for (t = readlines(); t != NULL; t = t->t_next) {
		if (t->t_type != Line)	/* sanity check */
			continue;
		/*
		 * Scan the entire line at a time, instead of having the
		 * parser call the scanner when a token is needed. This avoids
		 * nontrivial function-call overhead, but does decrease
		 * flexibility slightly.
		 */
		cp = t->t_pname;
		len = TOKENLEN(t);
		while (len > 0) {
			ocp = cp;
			nt = t;
			if (entry_pt == DateTime || entry_pt == Received)
				scan_t = scan822(&cp, len, '-', '/', 0, &nt);
			else
				scan_t = scan822(&cp, len, '!', '%', 0, &nt);
			if (nt != t) {	   /* compound token across line */
				while (t != nt)
					t = t->t_next;
				/* len should be 0 */
				len = t->t_pname - cp + TOKENLEN(t);
			} else
				len -= cp - ocp;
			/* Append the scanner tokens to the list of tokens */
			*prev_tp = scan_t;
			while (scan_t != NULL) {
				/*
				 * Doing it in a loop allows the scanner to
				 * return a token list instead of one token.
				 */
				prev_tp = &(scan_t->t_next);
				scan_t = scan_t->t_next;
			}
		}
	}
	*prev_tp = NULL;
	time(&now);
	localtm = *(localtime(&now));
	val = parse822(entry_pt, &tlist, &localtm, tracefp);
	switch (entry_pt) {
	case Received:
		printf("Received:\n");
		printf("\tFrom:");
		if (val.r->r_from != NULL)
			errprint(stdout, val.r->r_from->a_tokens);
		else
			printf("\tnull\n");
		printf("\tBy:");
		if (val.r->r_by != NULL)
			errprint(stdout, val.r->r_by->a_tokens);
		else
			printf("\tnull\n");
		printf("\tVia:\t%s\n",
			val.r->r_via ? formatToken(val.r->r_via) : "null");
		t = val.r->r_with;
		printf("\tWith:\t%s", t ? formatToken(t) : "null");
		if (t != NULL)
			t = t->t_next;
		while (t != NULL)
			printf(", %s", formatToken(t));
		printf("\n");
		printf("\tId:");
		if (val.r->r_id != NULL)
			errprint(stdout, val.r->r_id->a_tokens);
		else
			printf("\tnull\n");
		printf("\tFor:");
		if (val.r->r_for != NULL)
			errprint(stdout, val.r->r_for->a_tokens);
		else
			printf("\tnull\n");
		if (val.r->r_time != 0L)
			printf("\tDate: %s", rfc822date(&(val.r->r_time)));
		else
			printf("\tDate: null\n");
		break;
	case DateTime:
		if (val.d != 0)
			printf("DateTime: %s\n", rfc822date(&val.d));
		else
			printf("DateTime: null\n");
		break;
	default:
		for (a = val.a; a != NULL && a->a_tokens != NULL;a = a->a_next){
			for (p = a->a_tokens; p != NULL; p=p->p_next) {
				printf("\t%s:\n", formatAddr(p->p_type));
				for (t = p->p_tokens; t != NULL; t = t->t_next)
					printf("\t\t%s\n", formatToken(t));
			}
			errprint(stdout, a->a_tokens);
			printf("--- end of address ---\n");
		}
		break;
	}
	exit(0);
}

token822 *
readlines()
{
	token822 *t, **pt;
	char buf[BUFSIZ];

	pt = &t;
	/*while*/ if (gets(buf) != NULL) {
		*pt = makeToken(buf, strlen(buf));
		(*pt)->t_type = Line;
		pt = &((*pt)->t_next);
	} else exit(1);
	*pt = NULL;
	return t;
}

#if 0
char *
tmalloc(n)
	int n;
{
	return malloc(n);
}

char *
strnsave(s, n)
	char *s;
	int n;
{
	char *cp = tmalloc(n+1);
	memcpy(cp, s, n);
	*(cp+n) = '\0';
	return cp;
}
#endif

#define OFFSET 1

errprint(fp, pp)
	FILE *fp;
	register struct addr *pp;
{
	int inAddress, n, i, j, len;
	token822 *t;
	struct addr *lastp, *tpp;
	struct { int pos; token822 *tokens; } errmsg[200];

	inAddress = 0;
	for (lastp = NULL, tpp = pp; tpp != NULL; tpp = tpp->p_next)
		if (tpp->p_type == anAddress)
			lastp = tpp;
	(void) putc('\t', fp);
	len = OFFSET;
	n = 0;
	for (; pp != NULL; pp = pp->p_next) {
		if (pp->p_type == aComment)
			putc('(', fp), ++len;
		else if (pp->p_type == anAddress)
			inAddress = 1;
		else if (pp->p_type == anError) {
			errmsg[n].pos = len - OFFSET;
			errmsg[n++].tokens = pp->p_tokens;
			continue;
		}
		for (t = pp->p_tokens; t != NULL; t = t->t_next) {
			switch (pp->p_type) {
			case aPhrase:
			case aComment:
			case aGroup:
			case aWord:
				if (t != pp->p_tokens)
					putc(' ', fp), ++len;
				/* fall through */
			case anAddress:
			case aDomain:
			case reSync:
				len = fprintToken(fp, t, len);
				(void) fprintToken(fp, t, 0);
				if (pp->p_type == reSync && t->t_next != NULL
				    && (t->t_next->t_type == t->t_type))
					putc(' ', fp), ++len;
				break;
			case aSpecial:
				if (t != pp->p_tokens && *(t->t_pname) == '<')
					putc(' ', fp), ++len;
				putc((*t->t_pname), fp), ++len;
			case anError:
				break;
			}
		}
		if (pp->p_type == aComment) {
			putc(')', fp), ++len;
		} else if (lastp == pp)
			inAddress = 0;
		if (!inAddress && pp->p_next != NULL
			       && pp->p_next->p_type != anError
		    && !(pp->p_next->p_type == anAddress
			 && pp->p_type == aSpecial
			 && *pp->p_tokens->t_pname == '<')
		    && !(pp->p_next->p_type == aSpecial
			 && pp->p_type == anAddress
			 && *pp->p_next->p_tokens->t_pname == '>')
		    && !(pp->p_next->p_type == aSpecial
			 && *pp->p_next->p_tokens->t_pname == ':')) {
			putc(' ', fp), ++len;
		}
	}
	(void) putc('\n', fp);
	if (n == 0)
		return;
	(void) putc('\t', fp);
	for (i = 0, len = 0; i < n;) {
		for (; (len+1)/8 < errmsg[i].pos/8; len = ((len/8)+1)*8)
			(void) putc('\t', fp);
		for (; len < errmsg[i].pos; ++len)
			(void) putc(' ', fp);
		while (i < n && len == errmsg[i].pos)
			(void) putc('^', fp), ++i;
		++len;
	}
	--n;
	fprintf(fp, "-%s", errmsg[n].tokens->t_pname);
	for (t = errmsg[n].tokens->t_next; t != NULL; t = t->t_next)
		fprintf(fp, ", %s", t->t_pname);
	(void) putc('\n', fp);
	for (j = 0; j < n; ++j) {
		(void) putc('\t', fp);
		for (i = 0, len = 0; i < n-j;) {
			for (; (len+1)/8 < errmsg[i].pos/8; len = ((len/8)+1)*8)
				(void) putc('\t', fp);
			for (; len < errmsg[i].pos; ++len)
				(void) putc(' ', fp);
			while (i < n-j && len == errmsg[i].pos) {
				if (i == n-j-1) {
					if (j == 0)
						(void) putc(' ', fp), ++i;
					(void) putc('\\', fp), ++i;
				} else
					(void) putc('|', fp), ++i;
			}
			++len;
		}
		fprintf(fp, "-%s", errmsg[n-j-1].tokens->t_pname);
		for (t = errmsg[n-j-1].tokens->t_next; t != NULL; t = t->t_next)
			fprintf(fp, ", %s", t->t_pname);
		(void) putc('\n', fp);
	}
}
