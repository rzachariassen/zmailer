/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Header rewriting extended by Daniel Kiper <dkiper@netspace.com.pl>.
 */

#include "router.h"
#include "vis.h"

#ifndef LONG_MAX
#if SIZEOF_LONG == 4
# define LONG_MAX 2147483647L /* For 32 bit machine! */
#else
# define LONG_MAX 9223372036854775807L /* For 64 bit machine! */
#endif
#endif

#ifndef LONG_MIN
#if SIZEOF_LONG == 4
# define LONG_MIN -2147483648L /* For 32 bit machine! */
#else
# define LONG_MIN -9223372036854775808  /* For 64 bit machine! */
#endif
#endif


#define HRR_VIS_DISABLE		"hrr_vis_disable"
#define HRR_UNVIS_DISABLE	"hrr_unvis_disable"

conscell **return_valuep;
conscell *s_value;

int
l_apply(fname, l)
	const char *fname;
	conscell *l;
{
	int retval;
	conscell *retvp = NULL;
	conscell **oretvp = return_valuep;
	GCVARS2;

	GCPRO2(l, retvp);

	return_valuep = &retvp;

	retval = lapply(fname, l);
	s_value = retvp;

	return_valuep = oretvp;
	UNGCPRO2;
	return retval;
}


int
s_apply(argc, argv)
	int argc;
	const char *argv[];
{
	int retval;
	conscell *retvp = NULL;
	conscell **oretvp = return_valuep;
	GCVARS1;

	GCPRO1(retvp);

	return_valuep = &retvp;

	retval = apply(argc, argv);
	s_value = retvp;
	return_valuep = oretvp;
	UNGCPRO1;
	return retval;
}

int
n_apply(cpp, argc, argv)
	int argc;
	char **cpp;
	const char *argv[];
{
	int retval;

	sb_external(FILENO(stdout));	/* set up for retrieval of stdout */
	retval = apply(argc, argv);
	*cpp = sb_retrieve(FILENO(stdout));	/* safe alloc'ed memory */
	return retval;
}

static int
get_hrr_vis_flag(var_hrr_vis_name, name, stage_name)
	const char *var_hrr_vis_name;
	const char *name;
	const char *stage_name;
{
	char *endptr;
	long int tmp;
	conscell *var_hrr_vis;

	if ((var_hrr_vis = v_find(var_hrr_vis_name)) != NULL) {
		if (cdr(var_hrr_vis) != NULL && !LIST(cdr(var_hrr_vis))) {
			tmp = strtol(cdr(var_hrr_vis)->string, &endptr, 10);
			if (cdr(var_hrr_vis)->string != '\0' && *endptr == '\0' &&
			    (tmp != LONG_MAX || errno != ERANGE) && tmp >= 0)
				return tmp ? 1 : 0;
		}
		fprintf(stderr, "%s(%s): invalid %s - ignored\n", name, stage_name, var_hrr_vis_name);
	}
	return 0;
}

/*
 * Call func with tokenlist t as the argument.
 * This is used to rewrite an address.
 */

static int s_rewrite __((const char *func, token822 *t,
			 const char *sender, const char *argx));

static int
s_rewrite(func, t, sender, argx)
	const char *func, *sender, *argx;
	token822 *t;
{
	register char *cp, *bp;
	const char *av[4];
	char *buf = malloc(4000);
	int bufspc = 4000;
	int rc;

	if (t == NULL)
		return 0;
	cp = buf;
	cp += printdToken(&buf, &bufspc, t, (token822 *)NULL, 0);
	/* Was it a quote-containing string ?  If so, strip the quotes,
	   and undo back-slash quoting */
	if (t->t_next == NULL && t->t_type == String && buf[0] == '"') {
		*(cp-1) = '\0';
		cp = buf + 1;
		bp = buf;
		for (bp = buf, cp = buf + 1 ; *cp != '\0' ; ++cp) {
			if (*cp == '\\' && *(cp+1) != '\0')
				*bp++ = *++cp;
			else
				*bp++ = *cp;
		}
		*bp = '\0';
	}

	/* shell interface - we want stdout to show up here */
	av[0] = func;
	av[1] = buf;
	av[2] = argx;
	av[3] = NULL;
	rc = s_apply(argx == NULL ? 2 : 3, av);
	free(buf);
	return rc;
}


/*
 * The transformed message header addresses must be merged with their
 * original format (including comments, etc). We want to change the 'look'
 * of a message header address as little as possible, so we merge the new
 * pure address with the old version. RFC822 mumbles something about all
 * addresses being transmitted in a canonical format (without comments
 * embedded in route-addr's for example), but since we aren't generating
 * anything the original UA wouldn't generate, that requirement is blithely
 * ignored.
 */

static struct addr *mergeAddress __((struct addr *pp, token822 *t));

static struct addr *
mergeAddress(pp, t)
	struct addr *pp;
	token822 *t;
{
	struct addr *ppp, *npp, *fpp;
	token822 *nt, *pt;

	pt = NULL;
	for (ppp = fpp = NULL; pp != NULL; pp = pp->p_next, ppp = npp) {
		npp = (struct addr *)tmalloc(sizeof (struct addr));
		if (ppp != NULL)
			ppp->p_next = npp;
		else
			fpp = npp;
		if (pp->p_type != anAddress) {
			/* copy non-address portions unchanged */
			*npp = *pp;
		} else if (t != NULL) {
			/* copy the same number of tokens as was there */
			/* ... this is not terribly sophisticated ... */
			npp->p_type = anAddress;
			npp->p_tokens = t;
			for (nt = pp->p_tokens; nt != NULL && t != NULL;
						nt = nt->t_next, t = t->t_next)
				pt = t;
			if (t != NULL)
				pt->t_next = NULL;
		}
		npp->p_next = NULL;
	}
	if (t != NULL && pt != NULL)
		pt->t_next = t;
	return fpp;
}

/*
 * Rewrite a header nicely...
 */

struct header *
hdr_rewrite(name, h)
	const char *name;
	struct header *h;
{
	register struct address *ap;
	register struct addr *pp;
	register token822 *t;
	struct address *nap = NULL, *pap;
	token822 *nt, *pt, *addrtokens;
	struct header *nh;
	const char *cp, *eocp;
	char *s, buf[4096], *eobuf; 	/* XX */

	eobuf = buf + sizeof(buf)-1;

	if (D_hdr_rewrite) {
		printf("---------------------------\n");
		printf("Sending this through %s:\n", name);
		dumpHeader(h);
	}
	nh = (struct header *)tmalloc(sizeof (struct header));
	*nh = *h;
	nh->h_contents.a = NULL;
	nh->h_next = NULL;
	pap = NULL;	/* shut up lint */
	for (ap = h->h_contents.a; ap != NULL; ap = ap->a_next) {
		addrtokens = NULL;
		pt = NULL;
		for (pp = ap->a_tokens; pp != NULL; pp = pp->p_next) {
			if (pp->p_type != anAddress)
				continue;
			for (t = pp->p_tokens; t != NULL; t = t->t_next) {
				nt = copyToken(t);
				if (pt != NULL)
					pt->t_next = nt;
				pt = nt;
				if (addrtokens == NULL)
					addrtokens = nt;
			}
		}
		if (addrtokens != NULL
		    && addrtokens->t_next == NULL
		    && addrtokens->t_type == String) {
			eocp = addrtokens->t_pname + TOKENLEN(addrtokens);
			for (cp = addrtokens->t_pname, s=buf; cp < eocp; ++cp) {
				if (*cp == '\\' && cp < eocp - 1 && *(cp+1) == '"')
					continue;
				if (s < eobuf)
				  *s++ = *cp;
			}
			*s = 0;
			addrtokens->t_pname = strsave(buf);
		}
		nap = (struct address *)tmalloc(sizeof (struct address));
		nap->a_pname = NULL;
		nap->a_stamp = newAddress;
		nap->a_tokens = NULL;
		/* don't bother initializing a_uid/a_mode here, no use */
		nap->a_next = NULL;
		nap->a_dsn  = NULL;
		deferit = 0;
		v_set(DEFER, "");
		/*
		 * Header rewrite routines "intramachine", "null", and
		 * "internet" in script  crossbar.cf  can take header
		 * name (for debug purposes).
		 */
		if (addrtokens == NULL)
			s_value = NULL;
		else if (s_rewrite(name, addrtokens, NULL, h->h_pname) != 0) {
			if (s_value != NULL) {
			  /* s_free_tree(s_value); */
			  s_value = NULL;
			}
			if (deferit
			    && s_rewrite(DEFERHDR, addrtokens, NULL, h->h_pname)
			    && s_value != NULL) {
			  /* s_free_tree(s_value); */
			  s_value = NULL;
			}
		}
		if (s_value != NULL
		    && (LIST(s_value) || *(s_value->string) == '\0')) {
		  /* s_free_tree(s_value); */
		  s_value = NULL;
		}
		if (s_value == NULL) {
			/* copy this address unchanged */
			nap->a_tokens = ap->a_tokens;
		} else {
			/* integrate result with original address form */

			const char *cs = s_value->cstring;
			char *s;
			memtypes osticky = stickymem;
			stickymem = MEM_TEMP;

			/* This really does need long-term storage! */
			s = tmalloc(strlen(cs)+1);
			strcpy(s, cs);
			/* t = HDR_SCANNER(cs); */
			t = scan822((const char**)&s, strlen(s),
				    '!', '%', &ap->a_tokens->p_tokens);

			stickymem = osticky;

			/* X: check for errors! */
			nap->a_tokens = mergeAddress(ap->a_tokens, t);
		}
		if (nh->h_contents.a == NULL)
			nh->h_contents.a = nap;
		else
			pap->a_next = nap;
		pap = nap;
	}
	if (D_hdr_rewrite) {
		printf("Resulting in this header:\n");
		dumpHeader(nh);
		hdr_print(nh, stdout);
	}
	return nh;
}

struct header *
header_rewrite(name, h, fp, stage)
	const char *name;
	struct header *h;
	FILE *fp;
	int stage;
{
	const char *av[5], *stage_name[] = {"hrr_ab", "hrr_rr", "hrr_ae"};
	const char *tmp, *token;
	token822 *t;
	struct header *nh = NULL, *th = NULL;

	av[0] = name;
	av[1] = stage_name[stage];
	av[4] = NULL;

	if (stage == HRR_RR) {
		sb_external(FILENO(fp));
		hdr_print(h, fp);
		if ((tmp = sb_retrieve(FILENO(fp))) == NULL
		    || (tmp = strchr(tmp, ':')) == NULL)
			return h;
		++tmp;
		*(char *)(tmp + strlen(tmp) - 1) = '\0';
		av[2] = h->h_pname;
		if (get_hrr_vis_flag(HRR_VIS_DISABLE, name, stage_name[stage]))
			av[3] = tmp;
		else {
			av[3] = tmalloc(strlen(tmp) * 4 + 1);
			strvis((char *)av[3], tmp, VIS_OCTAL | VIS_GLOB | VIS_WHITE);
		}
	} else
		av[2] = av[3] = "";

	if (s_apply(4, av) == -1 || s_value == NULL)
		return h;

	if (!LIST(s_value) || car(s_value) == NULL || !LIST(car(s_value))) {
		fprintf(stderr, "%s(%s): returned value is invalid\n", name, stage_name[stage]);
		return h;
	}

	if (stage == HRR_RR && caar(s_value) == NULL)
		return NULL;

	for (s_value = car(s_value); s_value != NULL; s_value = cdr(s_value)) {

		if (!LIST(s_value) || car(s_value) == NULL || LIST(car(s_value))
		    || cdar(s_value) == NULL || LIST(cdar(s_value))) {
			fprintf(stderr, "%s(%s): returned value is invalid\n", name, stage_name[stage]);
			return h;
		}

		if (get_hrr_vis_flag(HRR_UNVIS_DISABLE, name, stage_name[stage]))
			tmp = cdar(s_value)->string;
		else {
			tmp = tmalloc(strlen(cdar(s_value)->string) + 1);
			if (strunvis((char *)tmp, cdar(s_value)->string) == -1) {
				fprintf(stderr, "%s(%s): invalid escape sequence\n", name, stage_name[stage]);
				return h;
			}
		}

		if (nh == NULL)
			nh = th = makeHeader(spt_headers, car(s_value)->string, strlen(car(s_value)->string));
		else {
			th->h_next = makeHeader(spt_headers, car(s_value)->string, strlen(car(s_value)->string));
			th = th->h_next;
		}

		th->h_descriptor = &nullhdr;
		th->h_lines = NULL;

		t = NULL;

		while (1) {
			while ((*tmp == '\n') || ((*tmp == '\r') && (*(tmp + 1) == '\n'))) {
				if (*tmp == '\r')
					++tmp;
				++tmp;
			}
			if (*tmp == '\0')
				break;
			if ((tmp = strpbrk(token = tmp, "\n")) == NULL) {
				if (t == NULL) {
					th->h_lines = makeToken(token, strlen(token));
					th->h_lines->t_type = Line;
				} else {
					t->t_next = makeToken(token, strlen(token));
					t->t_next->t_type = Line;
				}
				break;
			}
			if (t == NULL) {
				th->h_lines = t = makeToken(token, *(tmp - 1) == '\r' ? tmp - token - 1 : tmp - token);
				th->h_lines->t_type = Line;
			} else {
				t->t_next = makeToken(token, *(tmp - 1) == '\r' ? tmp - token - 1 : tmp - token);
				t->t_next->t_type = Line;
				t = t->t_next;
			}
		}

		if (th->h_lines == NULL) {
			fprintf(stderr, "%s(%s): returned value is invalid\n", name, stage_name[stage]);
			return h;
		}
	}

	return nh;
}

void
setenvinfo(e)
	struct envelope *e;
{
	struct header *h;
	conscell *pl, *plhead;
	char buf[20];
	GCVARS1;
	int slen;

	/* include header size ("headersize"), message size ("size"),
	   message body size ("bodysize"), now ("now"), resent ("resent")
	   trusted ("trusted"), message file name ("file"), message id
	   ("message-id") */

#define	CONSTSTR(s)	slen = strlen(s); cdr(pl) = conststring(s, slen); pl = cdr(pl)
#define	NEWSTR(s)	slen = strlen(s); cdr(pl) = newstring(s, slen);   pl = cdr(pl)
#define	NEWDUPSTR(s)	slen = strlen(s); cdr(pl) = newstring(dupnstr(s, slen), slen);   pl = cdr(pl)
#define	NEWSTRD(d)	sprintf(buf, "%ld", (long)(d)); NEWDUPSTR(buf)

	pl = plhead = conststring("file", 4);
	GCPRO1(plhead);

	CONSTSTR(e->e_file);

	if (e->e_messageid != NULL) {
		CONSTSTR("message-id");
		CONSTSTR(e->e_messageid);
	}

	CONSTSTR("spoolid");
	CONSTSTR(e->e_spoolid);

	CONSTSTR("uid");
	NEWSTRD(e->e_statbuf.st_uid);

	CONSTSTR("gid");
	NEWSTRD(e->e_statbuf.st_gid);

	CONSTSTR("size");
	NEWSTRD(e->e_statbuf.st_size - e->e_hdrOffset);

	CONSTSTR("headersize");
	NEWSTRD(e->e_msgOffset - e->e_hdrOffset);

	CONSTSTR("bodysize");
	NEWSTRD(e->e_statbuf.st_size - e->e_msgOffset);

	CONSTSTR("now");
	NEWSTRD(e->e_nowtime);

	CONSTSTR("delay");
	NEWSTRD(e->e_nowtime - e->e_statbuf.st_mtime);

	CONSTSTR("resent");
	CONSTSTR(e->e_resent ? "yes" : "no");

	CONSTSTR("trusted");
	CONSTSTR(e->e_trusted ? "yes" : "no");

	/* for every non-address envelope header, include
	   header-name header-value pair in property list */

	for (h = e->e_eHeaders; h != NULL; h = h->h_next) {
		if (h->h_descriptor->user_type != nilUserType)
			continue;
		CONSTSTR(h->h_descriptor->hdr_name);
		if (h->h_lines == NULL || *h->h_lines->t_pname == '\0') {
			CONSTSTR(h->h_descriptor->hdr_name);
		} else {
			CONSTSTR(h->h_lines->t_pname);
		}
	}
	cdr(pl) = NULL;
	plhead = ncons(plhead);
	v_setl("envelopeinfo", plhead);
	UNGCPRO1;
}

static char gsbuf[30];
/*
 *  newattribute_2()
 */
char *newattribute_2(onam,nam,val)
     const char *onam, *nam, *val;
{
	conscell *l, *lc, *tmp, **pl;
	conscell	*l1;
	GCVARS4;
	int slen;

	l1 = v_find(onam);
	if (!l1)
	  return NULL;
	l = copycell(cdr(l1));
	lc = tmp = l1 = NULL;
	GCPRO4(l, lc, tmp, l1);

	cdr(l) = NULL;
	car(l) = s_copy_chain(car(l));
	pl = &car(l);
	l1 = *pl;
	for (lc = l1; lc && cdr(lc); pl = &cddr(lc),lc = *pl) {
	  if (!STRING(lc)) {
	    UNGCPRO4;
	    return NULL; /* ?? */
	  }
	  if (STREQ(nam,lc->string)) {
	    if (!cdr(lc)) {
	      UNGCPRO4;
	      return NULL;
	    }
	    *pl = cddr(lc) /* Skip this in chain */;
	  }
	}

	/* Prepend in reverse order */
	slen = strlen(val);
	tmp = newstring(dupnstr(val, slen), slen);
	cdr(tmp) = car(l);
	car(l) = tmp;
	slen = strlen(nam);
	tmp = newstring(dupnstr(nam, slen), slen);
	cdr(tmp) = car(l);
	car(l) = tmp;

	sprintf(gsbuf, gs_name, gensym++);
	/* gX (name in gsbuf) will be freed by free_gensym() later */
	v_setl(gsbuf, l);
	UNGCPRO4;
	return gsbuf;
}

/*
 * Build gensym
 */
static char  *build_gensym __((int, const char*, const char*, const char*, const char*, const char*, const char*));

static char *
build_gensym(uid, type, DSNstr, DSNret, DSNenv, errorsto, sender)
     int uid;
     const char *type, *DSNstr, *DSNret, *DSNenv, *errorsto, *sender;
{
	char buf[20];
	conscell *l, *pl;
	GCVARS1;
	int slen;

	/* assemble the default attribute list: (privilege <uid>) */
	l = conststring("privilege", 9);
	GCPRO1(l);
	sprintf(buf, "%d", uid);
	pl = l;
	NEWDUPSTR(buf);
	if (type) {
		CONSTSTR("type");
		CONSTSTR(type); /* Always a constant string */
	}
	if (DSNstr) {
		CONSTSTR("DSN");
		NEWDUPSTR(DSNstr);
	}
	if (DSNret) {
		CONSTSTR("DSNr");
		NEWDUPSTR(DSNret);
	}
	if (DSNenv) {
		CONSTSTR("DSNe");
		NEWDUPSTR(DSNenv);
	}
	/* See if some "errorsto" definition is available.. */
	if (errorsto) {
		CONSTSTR("ERR");
		NEWDUPSTR(errorsto);
	}
	/* See if some "sender" definition is available.. */
	if (sender) {
		CONSTSTR("sender");
		NEWDUPSTR(sender);
	}
	cdr(pl) = NULL; /* not needed in reality */
	l = ncons(l);
	sprintf(gsbuf, gs_name, gensym++);
	/* gX (name in gsbuf) will be freed by free_gensym() later */
	v_setl(gsbuf, l);
	UNGCPRO1;
	return gsbuf;
}

/*
 * The router function must return three values,
 *	a (channel, host, user) triple.
 *
 * If we get a deferral while routing, call a deferral
 * function to deal with it.
 */

conscell *
router(a, uid, type, senderstr)
	struct address *a;
	int uid;
	const char *type, *senderstr;
{
	register token822 *t, *tt;
	int r;
	token822 *last;
	struct addr *p;
	conscell *l;
	const char *gsym;
	struct notary *DSN = NULL;
	const char *DSNstr;
	const char *DSNret;
	const char *DSNenv;
	GCVARS1;

	if (a == NULL)
		return NULL;
	t = last = NULL;
	DSN = a->a_dsn;
	DSNstr = DSNret = DSNenv = NULL;
	if (DSN) {
	  DSNstr = DSN->dsn;
	  DSNret = DSN->ret;
	  DSNenv = DSN->envid;
	}
	for (p = a->a_tokens; p != NULL; p = p->p_next)
		if (p->p_type == anAddress) {
			/* link up all address tokens together */
			for (tt = p->p_tokens; tt != NULL; tt = tt->t_next) {
				if (t == NULL) {
					t = copyToken(tt);
					last = t;
				} else {
					last->t_next = copyToken(tt);
					last = last->t_next;
				}
			}
		}
	if (D_router) {
		printf("Routing:\n");
		for (tt = t; tt != NULL; tt = tt->t_next)
			printf("\t\t%s\n", formatToken(tt));
	}
	if (t == NULL)
		return NULL;
	if (t->t_pname[0] == '<' && TOKENLEN(t) == 1 && t->t_next == NULL)
		abort();

	gsym = build_gensym(uid, type, DSNstr, DSNret, DSNenv, errors_to, senderstr);

	deferit = 0;
	v_set(DEFER, "");
	r = s_rewrite(ROUTER, t, NULL, gsym);
#if 0
	if (deferit) {
	  /* s_free_tree(s_value); */
	  s_value = NULL;
	  r = s_rewrite(DEFERENV, t, NULL, gsym);
	}
#endif
	if (r != 0 || s_value == NULL || !LIST(s_value)) {
	  /* router returned something invalid */
	  /* s_free_tree(s_value); */
	  s_value = NULL;
	  return NULL;
	}

	/*
	 * We expect router to either return
	 * (local - user attributes) or (((local - user attributes)))
	 */
	l = NULL;
	GCPRO1(l);
	if (car(s_value) && LIST(car(s_value))) {
		if (!LIST(caar(s_value)) || !STRING(caaar(s_value))) {
			fprintf(stderr,
				"%s: '%s' returned invalid 2-level list: ",
				progname, ROUTER);
			s_grind(s_value, stderr);
			/* s_free_tree(s_value); */
			s_value = NULL;
			UNGCPRO1;
			return NULL;
		}
		l = s_copy_chain(s_value);
	} else {
		l = s_copy_chain(s_value);
		l = ncons(l);
		l = ncons(l);
	}

	/* s_free_tree(s_value); */
	s_value = NULL;
	UNGCPRO1;

	return l;
}

/*
 * Crossbar switch. That's the closest metaphor I can think of that describes
 * what this function actually does --- which is looking at the sender and
 * recipient addresses, or more precisely the (channel, host, user) triples,
 * and munging them both appropriately using whatever criteria it wishes.
 *
 * The crossbar configuration file function should return 7 values, as
 * shown below. The first six are its munged calling parameters, the
 * seventh if non-null is the name of another configuration file function
 * which will be called for munging the message header addresses.
 * The munged parameters will eventually find their way onto the envelopes.
 */

conscell *
crossbar(from, to)
	conscell *from, *to;
{
	conscell *l = NULL;
	GCVARS3;

	GCPRO3(l, from, to);

	l = copycell(from);
	l = ncons(l);

	cdar(l) = to;

	if (l_apply(CROSSBAR, l) != 0 || s_value == NULL) {
	  s_value = NULL;
	  return NULL;
	}

	/*
	 * We expect to see something like
	 * (rewrite (fc fh fu) (tc th tu)) or
	 * ((address-rewrite header-rewrite) (fc fh fu) (tc th tu))
	 * back from the crossbar function.
	 */

	l = s_value;
	s_value = NULL;
	UNGCPRO3;

	return l;
}
