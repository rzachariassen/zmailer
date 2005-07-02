/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2005.
 */

/*
 * ZMailer SMTP server.
 */

#include "smtpserver.h"

static int called_getbindaddr = 0;


static char *SKIPSPACE __((char *Y));
static char *SKIPSPACE (Y)
     char *Y;
{
	if (!Y) return Y;

	while (*Y == ' ' || *Y == '\t')
	  ++Y;

	return Y;
}

static char *SKIPDIGIT __((char *Y));
static char *SKIPDIGIT (Y)
     char *Y;
{
	if (!Y) return Y;

	while ('0' <= *Y && *Y <= '9')
	  ++Y;

	return Y;
}

/* SKIPTEXT:
 *
 *  Detect " -> scan until matching double quote
 *  Detect ' -> scan until matching single quote
 *  Detect non-eol, non-space(tab): scan until eol, or white-space
 *
 *  Will thus stop when found non-quoted space/tab, or
 *  end of line/string.
 */

static char * SKIPTEXT __((char *Y));
static char * SKIPTEXT (Y)
     char *Y;
{
	if (!Y) return Y;

	if (*Y == '"') {
	  ++Y;
	  while (*Y && *Y != '"')
	    ++Y;
	  /* STOP at the tail-end " */
	} else if ( *Y == '\'' ) {
	  ++Y;
	  while(*Y && *Y != '\'')
	    ++Y;
	  /* STOP at the tail-end ' */
	} else {
	  while (*Y && *Y != ' ' && *Y != '\t')
	    ++Y;
	  /* Stop at white-space */
	}

	return Y;
}

static void dollarexpand __((unsigned char *s0, int space));
static void dollarexpand(s0, space)
     unsigned char *s0;
     int space;
{
    unsigned char *str = s0;
    unsigned char *eol = s0 + space; /* assert(str < eol) */
    unsigned char namebuf[80];
    unsigned char *s;
    int len, taillen;

    while (*str) {
      if (*str != '$') {
	++str;
	continue;
      }
      /*  *str == '$' */
      s0 = str; /* start position */
      ++str;
      if (*str == '$') {
	/* A '$$' sequence shrinks to '$' */
	strcpy((char*)str, (const char *)(str+1));
	continue;
      }
      s = namebuf;
      if (*str == '{' || *str == '(') {
	int endc = (*str == '{') ? '}' : ')';
	++str;
	for (;*str;++str) {
	  if (*str == endc)
	    break;
	  if (s < namebuf + sizeof(namebuf)-1)
	    *s++ = *str;
	}
	if (*str) ++str; /* End char */
	*s = 0; /* name end */
      } else {
	for (;*str;++str) {
	  if (!((isascii(*str) && isalnum(*str)) || *str == '_'))
	    break; /* 'A'..'Z', 'a'..'z', '0'..'9', '_' */
	  if (s < namebuf + sizeof(namebuf)-1)
	    *s++ = *str;
	}
	*s = 0;
      }
      if (*namebuf == 0) /* If there are e.g.  "$/" or "${}" or "$()", or
			    just "$" at the end of the line, then let it be. */
	continue;
      s = (unsigned char*) getzenv((char*)namebuf); /* Pick whatever name there was.. */
      if (!s) continue;     /* No ZENV variable with this name ? */

      len     = strlen((char*)s);
      taillen = strlen((char*)str);

      if (len > (str - s0)) {
	/* Must expand the spot! */

	unsigned char *replacementend = s0  + len;

	if ((replacementend + taillen) >= eol) {
	  /* Grows past the buffer end, can't! */
	  taillen = eol - replacementend;
	} /* else
	     We have space */

	if (taillen > 0) {
	  unsigned char *si = str            + taillen;
	  unsigned char *so = replacementend + taillen;
	  /* Copy also the tail NIL ! */
	  for (;taillen>=0; --taillen, --so, --si) *so = *si;
	}

	if ((s0 + len) >= eol)
	  /* The fill-in goes over the buffer end */
	  len = eol - s0; /* Cut down */
	if (len > 0) { /* Still something can be copied ? */
	  memcpy(s0, s, len);
	  str = s0 + len;
	} else
	  str = s0 + (*s0 == '$'); /* Hmm.. grumble.. */

      } else {

	/* Same space, or can shrink! */

	if (len > 0)
	  memcpy(s0, s, len);
	if (s0+len < str)
	  /* Copy down */
	  strcpy((char*)(s0+len), (const char *)str);
	str = s0 + len;
	str[taillen] = 0; /* Chop the possible old junk from the tail */

      }
    }
    eol[-1] = 0;
}


static int cfg_add_bindaddr(CP, param1, use_ipv6, bindtype, bindport)
     ConfigParams *CP;
     char *param1;
     int use_ipv6, bindtype, bindport;
{
	Usockaddr bindaddr;
	int rc;

	called_getbindaddr=1;
	rc = zgetbindaddr(param1, use_ipv6, &bindaddr);
#if 0  /* The  zgetbindaddr() does parse v6 addresses even when
	  wanting to get only v4 address and reject all else.. */
	if ( !rc ) {
	  switch (use_ipv6) {
	  case 0: /* This is presumed to be IPv4 */
	    if (bindaddr.v4.sin_family != AF_INET) {
	      /* But the address literal is not IPv4 ... */
	      rc = 1;
	    }
	    break;

	  default: /* This is presumed to be IPv6 */
	    if (bindaddr.v4.sin_family == AF_INET) {
	      /* But the address literal is not IPv6 ... */
	      rc = 1;
	    }
	    break;

	  }
	}
#endif
	if ( !rc ) {
	  CP->bindaddrs = realloc( CP->bindaddrs,
			       sizeof(bindaddr) * (CP->bindaddrs_count +2) );
	  CP->bindaddrs_types = realloc( CP->bindaddrs_types,
				     sizeof(int) * (CP->bindaddrs_count +2) );
	  CP->bindaddrs_ports = realloc( CP->bindaddrs_ports,
				     sizeof(int) * (CP->bindaddrs_count +2) );
	  if (!CP->bindaddrs || !CP->bindaddrs_types || !CP->bindaddrs_ports)
	    CP->bindaddrs_count = 0;
	  else {
	    CP->bindaddrs      [ CP->bindaddrs_count ] = bindaddr;
	    CP->bindaddrs_types[ CP->bindaddrs_count ] = bindtype;
	    CP->bindaddrs_ports[ CP->bindaddrs_count ] = bindport;
	    CP->bindaddrs_count += 1;
	  }
	}
#if 0
	type(NULL,0,NULL, "cfg_add_bindaddr('%s', v%d, type=%d port=%d) rc=%d",
	     param1, use_ipv6 ? 6 : 4, bindtype, bindport, rc);
#endif
	return rc;
}       

static void cfparam __((char *, int, const char *, int));
static void cfparam(str, size, cfgfilename, linenum)
     char *str;
     int size, linenum;
     const char *cfgfilename;
{
    char *name, *param1, *param2, *param3;
    char *str0 = str;

    name = strchr(str, '\n');	/* The trailing newline chopper ... */
    if (name)
	*name = 0;

    str = SKIPTEXT (str); /* "PARAM" */
    str = SKIPSPACE (str);
    name = str;
    str = SKIPTEXT (str);
    if (*str != 0)
	*str++ = 0;

    if (cistrcmp(name, "help") == 0) {
	int i = 0, helpmax = HELPMAX;
	while (helplines[i] != NULL && i < helpmax)
	    ++i;
	param2 = strchr(str, '\n');
	if (param2) *param2 = 0;
	helplines[i] = strdup(str);
	helplines[i + 1] = NULL;	/* This will always stay within the array... */
	return;
    }
    if (cistrcmp(name, "hdr220") == 0) {
	int i = 0, hdrmax = HDR220MAX;
	while (hdr220lines[i] != NULL && i < hdrmax)
	  ++i;
	param2 = strchr(str, '\n');
	if (param2) *param2 = 0;
	hdr220lines[i] = strdup(str);
	hdr220lines[i+1] = NULL;
	return;
    }
    if (cistrcmp(name, "sasl-mechanisms") == 0) {
      param2 = strchr(str, '\n');
      if (param2) *param2 = 0;
      CP->SASL_Auth_Mechanisms = strdup(str);
      return;
    }
    if (cistrcmp(name, "contact-pointer-message") == 0) {
      param2 = strchr(str, '\n');
      if (param2) *param2 = 0;
      CP->contact_pointer_message = strdup(str);
      return;
    }

    /* Do '$' expansions on the string */
    dollarexpand((unsigned char *)str, size - (str - str0));

    str = SKIPSPACE (str);

    param1 = *str ? str : NULL;

    str = SKIPTEXT (str);
    if (param1 && (*param1=='"' || *param1=='\'')) ++param1;
    if (*str != 0)
	*str++ = 0;
    str = SKIPSPACE (str);
    param2 = *str ? str : NULL;
    str = SKIPTEXT (str);
    if (param2 && (*param2=='"' || *param2=='\'')) ++param2;
    if (*str != 0)
	*str++ = 0;
    str = SKIPSPACE (str);
    param3 = *str ? str : NULL;
    str = SKIPTEXT (str);
    if (param3 && (*param3=='"' || *param3=='\'')) ++param3;
    if (*str != 0)
	*str++ = 0;

    if (cistrcmp(name, "newgroup") == 0) {
      ConfigParams_newgroup();
    }

    /* How many parallel clients a servermode smtpserver allows
       running in parallel, and how many parallel sessions can
       be coming from same IP address */

    else if (cistrcmp(name, "same-ip-source-parallel-max") == 0 && param1) {
	sscanf(param1, "%d", &MaxSameIpSource);
    } else if (cistrcmp(name, "MaxSameIpSource") == 0 && param1) {
	sscanf(param1, "%d", &MaxSameIpSource);
    } else if (cistrcmp(name, "MaxParallelConnections") == 0 && param1) {
	sscanf(param1, "%d", &MaxParallelConnections);
    } else if (cistrcmp(name, "max-parallel-connections") == 0 && param1) {
	sscanf(param1, "%d", &MaxParallelConnections);
    }

    /* TCP related parameters */

    else if   (cistrcmp(name, "ListenQueueSize") == 0   && param1) {
	sscanf(param1, "%d", &CP->ListenQueueSize);
    } else if (cistrcmp(name, "tcprcvbuffersize") == 0  && param1) {
	sscanf(param1, "%d", &CP->TcpRcvBufferSize);
    } else if (cistrcmp(name, "tcpxmitbuffersize") == 0 && param1) {
	sscanf(param1, "%d", &CP->TcpXmitBufferSize);
    }

    /* IP address and port binders */

#if 1 /* Should obsolete.. */
    else if (cistrcmp(name, "BindPort") == 0 && param1) {
      bindport = atoi(param1);
      if (bindport != 0 && bindport != 0xFFFFU)
	bindport_set = 1;
    } else if (cistrcmp(name, "BindAddress") == 0 && param1) {
      int rc = 0;
      if (use_ipv6)
	rc += cfg_add_bindaddr( CP, param1, 1, BINDADDR_ALL, 0 );
      rc += cfg_add_bindaddr( CP, param1, 0, BINDADDR_ALL, 0 );
      if (rc > 1)
	goto bad_cfg_line;
    }
#endif

    else if (cistrcmp(name, "BindSmtp") == 0 && param1) {
      int port = 25;
      int rc = 0;
      if (param2) port = atoi(param2);

      if (use_ipv6)
	rc += cfg_add_bindaddr( CP, param1, 1, BINDADDR_SMTP, port );
      rc += cfg_add_bindaddr( CP, param1, 0, BINDADDR_SMTP, port );
      if (rc > 1)
	goto bad_cfg_line;
    }
    else if (cistrcmp(name, "BindSmtpS") == 0 && param1) {
      int port = 465;
      int rc = 0;
      if (param2) port = atoi(param2);

      if (use_ipv6)
	rc += cfg_add_bindaddr( CP, param1, 1, BINDADDR_SMTPS, port );
      rc += cfg_add_bindaddr( CP, param1, 0, BINDADDR_SMTPS, port );
      if (rc > 1)
	goto bad_cfg_line;
    }
    else if (cistrcmp(name, "BindSubmit") == 0 && param1) {
      int port = 587;
      int rc = 0;
      if (param2) port = atoi(param2);

      if (use_ipv6)
	rc += cfg_add_bindaddr( CP, param1, 1, BINDADDR_SUBMIT, port );
      rc += cfg_add_bindaddr( CP, param1, 0, BINDADDR_SUBMIT, port );
      if (rc > 1)
	goto bad_cfg_line;
    }

    /* SMTP Protocol limit & policy tune options */

    else if (cistrcmp(name, "maxsize") == 0 && param1) {
	sscanf(param1, "%ld", &maxsize);
    } else if (cistrcmp(name, "min-availspace") == 0 && param1) {
	if (sscanf(param1, "%ld", &minimum_availspace) == 1) {
	  /* Minimum of minimum is 1000 kB ! */
	  if (minimum_availspace < 1000)
	    minimum_availspace = 1000;
	}
    } else if (cistrcmp(name, "RcptLimitCnt") == 0 && param1) {
	sscanf(param1, "%d", &CP->rcptlimitcnt);
	if (CP->rcptlimitcnt < 100) CP->rcptlimitcnt = 100;
    } else if (cistrcmp(name, "RcptLimitCount") == 0 && param1) {
	sscanf(param1, "%d", &CP->rcptlimitcnt);
	if (CP->rcptlimitcnt < 100) CP->rcptlimitcnt = 100;
    } else if (cistrcmp(name, "Rcpt-Limit-Count") == 0 && param1) {
	sscanf(param1, "%d", &CP->rcptlimitcnt);
	if (CP->rcptlimitcnt < 100) CP->rcptlimitcnt = 100;
#if 0
    } else if (cistrcmp(name, "accept-percent-kludge") == 0) {
	percent_accept = 1;
#endif
    } else if (cistrcmp(name, "reject-percent-kludge") == 0) {
	percent_accept = -1;
    } else if (cistrcmp(name, "allowsourceroute") == 0) {
      allow_source_route = 1;
    } else if (cistrcmp(name, "max-error-recipients") == 0 && param1) {
	sscanf(param1, "%d", &CP->MaxErrorRecipients);
    } else if (cistrcmp(name, "max-unknown-commands") == 0 && param1) {
	sscanf(param1, "%d", &unknown_cmd_limit);
    } else if (cistrcmp(name, "sum-sizeoption-value") == 0) {
      sum_sizeoption_value = 1;
    }

    else if (cistrcmp(name, "use-tcp-wrapper") == 0) {
	CP->use_tcpwrapper = 1;
    }

    else if (cistrcmp(name, "tarpit") == 0 && param3 /* 3 params */) {
	CP->tarpit_initial  = atof(param1);
	CP->tarpit_exponent = atof(param2);
	CP->tarpit_toplimit = atof(param3);
    }

    else if (cistrcmp(name, "deliverby") == 0) {
      if (param1)
	CP->deliverby_ok = atol(param1);
      else
	CP->deliverby_ok = 0;
    }

    /* Two parameter policydb option: DBTYPE and DBPATH */

    else if (cistrcmp(name, "policydb") == 0 && param2 /* 2 params */) {
	policydefine(&CP->policydb, param1, param2);
    }
#if 0
    else if (cistrcmp(name, "policydb-submit") == 0 && param2 /* 2 params */) {
	policydefine(&policydb_submit, param1, param2);
    }
#endif
    else if (cistrcmp(name, "contentfilter") == 0 && param1) {
      if (access(param1, X_OK) == 0)
	contentfilter = strdup(param1);
    }
    else if (cistrcmp(name, "contentfilter-maxpar") == 0 && param1) {
      contentfilter_maxctfs = atoi(param1);
      if (contentfilter_maxctfs < 1)
	contentfilter_maxctfs = 1;
    }
    else if (cistrcmp(name, "debug-contentfilter") == 0) {
      debug_content_filter = 1;
    }
    else if (cistrcmp(name, "perl-hook") == 0 && param1) {
      if (access(param1, X_OK) == 0)
	perlhookpath = strdup(param1);

    } else if (cistrcmp(name, "enable-router") == 0) {
      enable_router = 1;
    } else if (cistrcmp(name, "enable-router-maxpar") == 0 && param1) {
      enable_router_maxpar = atoi(param1);
      if (enable_router_maxpar < 1)
	enable_router_maxpar  = 1;

    /* A few facility enablers: (default: off) */

    } else if (cistrcmp(name, "debugcmd") == 0) {
      CP->debugcmdok = 1;
    } else if (cistrcmp(name, "no-debugcmd") == 0) {
      CP->debugcmdok = 0;
    } else if (cistrcmp(name, "expncmd") == 0) {
      CP->expncmdok = 1;
    } else if (cistrcmp(name, "no-expncmd") == 0) {
      CP->expncmdok = 0;
    } else if (cistrcmp(name, "vrfycmd") == 0) {
      CP->vrfycmdok = 1;
    } else if (cistrcmp(name, "no-vrfycmd") == 0) {
      CP->vrfycmdok = 0;

    } else if (cistrcmp(name, "smtp-auth") == 0) {
      CP->auth_ok = 1;
    } else if (cistrcmp(name, "no-smtp-auth") == 0) {
      CP->auth_ok = 0;
    } else if (cistrcmp(name, "no-smtp-auth-on-25") == 0) {
      CP->no_smtp_auth_on_25 = 1;
    } else if (cistrcmp(name, "smtp-auth-username-prompt") == 0 && param1) {
      CP->smtp_auth_username_prompt = strdup(param1);
    } else if (cistrcmp(name, "smtp-auth-password-prompt") == 0 && param1) {
      CP->smtp_auth_password_prompt = strdup(param1);
    } else if (cistrcmp(name, "auth-failrate") == 0 && param1) {
      CP->auth_failrate = atoi(param1);
      if (CP->auth_failrate < 3)
	CP->auth_failrate = 3;
    } else if (cistrcmp(name, "auth-login-also-without-tls") == 0) {
      CP->auth_login_without_tls = 1;
    } else if (cistrcmp(name, "smtp-auth-sasl") == 0) {
      CP->do_sasl = 1;
    } else if (cistrcmp(name, "no-smtp-auth-sasl") == 0) {
      CP->do_sasl = 0;
#if 1 /* Should obsolete.. */
    } else if (cistrcmp(name, "msa-mode") == 0) {
      msa_mode = 1;
#endif
    } else if (cistrcmp(name, "smtp-auth-pipe") == 0 && param1) {
      CP->smtpauth_via_pipe = strdup(param1);

    /* Store various things into 'rvcdfrom' header per selectors */

    } else if (cistrcmp(name, "rcvd-ident") == 0) {
      CP->log_rcvd_ident = 1;
    } else if (cistrcmp(name, "no-rcvd-ident") == 0) {
      CP->log_rcvd_ident = 0;
    } else if (cistrcmp(name, "rcvd-whoson") == 0) {
      CP->log_rcvd_whoson = 1;
    } else if (cistrcmp(name, "no-rcvd-whoson") == 0) {
      CP->log_rcvd_whoson = 0;
    } else if (cistrcmp(name, "rcvd-auth-user") == 0) {
      CP->log_rcvd_authuser = 1;
    } else if (cistrcmp(name, "no-rcvd-auth-user") == 0) {
      CP->log_rcvd_authuser = 0;
    } else if (cistrcmp(name, "rcvd-tls-mode") == 0) {
      CP->log_rcvd_tls_mode = 1;
    } else if (cistrcmp(name, "no-rcvd-tls-mode") == 0) {
      CP->log_rcvd_tls_mode = 0;
    } else if (cistrcmp(name, "rcvd-tls-peer") == 0) {
      CP->log_rcvd_tls_peer = 1;
    } else if (cistrcmp(name, "no-rcvd-tls-peer") == 0) {
      CP->log_rcvd_tls_peer = 0;

    /* Some Enhanced-SMTP facility disablers: (default: on ) */

    } else if (cistrcmp(name, "nopipelining") == 0) {
      CP->pipeliningok = 0;
    } else if (cistrcmp(name, "pipelining-ok") == 0) {
      CP->pipeliningok = 1;
    } else if (cistrcmp(name, "noenhancedstatuscodes") == 0) {
      CP->enhancedstatusok = 0;
    } else if (cistrcmp(name, "enhancedstatuscodes-ok") == 0) {
      CP->enhancedstatusok = 1;
    } else if (cistrcmp(name, "noenhancedstatus") == 0) {
      CP->enhancedstatusok = 0;
    } else if (cistrcmp(name, "enhancedstatus-ok") == 0) {
      CP->enhancedstatusok = 1;
    } else if (cistrcmp(name, "no8bitmime") == 0) {
      CP->mime8bitok = 0;
    } else if (cistrcmp(name, "8bitmime-ok") == 0) {
      CP->mime8bitok = 1;
    } else if (cistrcmp(name, "nochunking") == 0) {
      CP->chunkingok = 0;
    } else if (cistrcmp(name, "chunking-ok") == 0) {
      CP->chunkingok = 1;
    } else if (cistrcmp(name, "nodsn") == 0) {
      CP->dsn_ok = 0;
    } else if (cistrcmp(name, "dsn-ok") == 0) {
      CP->dsn_ok = 1;
    } else if (cistrcmp(name, "noehlo") == 0) {
      CP->ehlo_ok = 0;
    } else if (cistrcmp(name, "ehlo-ok") == 0) {
      CP->ehlo_ok = 1;
    } else if (cistrcmp(name, "noetrn") == 0) {
      CP->etrn_ok = 0;
    } else if (cistrcmp(name, "etrn-ok") == 0) {
      CP->etrn_ok = 1;
    } else if (cistrcmp(name, "no-multiline-replies") == 0) {
      CP->multilinereplies = 0;
    } else if (cistrcmp(name, "multiline-replies-ok") == 0) {
      CP->multilinereplies = 1;
    } else if (cistrcmp(name, "force-rcpt-notify-never") == 0) {
      CP->force_rcpt_notify_never = 1;
    } else if (cistrcmp(name, "no-force-rcpt-notify-never") == 0) {
      CP->force_rcpt_notify_never = 0;
    }

#ifdef HAVE_OPENSSL

    /* TLSv1/SSLv* options */

    else if (cistrcmp(name, "use-tls") == 0)
      CP->starttls_ok = 1;		/* Default: OFF */
    else if (cistrcmp(name, "no-use-tls") == 0)
      CP->starttls_ok = 0;		/* Default: OFF */

    else if (cistrcmp(name, "listen-ssmtp") == 0)
      CP->ssmtp_listen = 1;		/* Default: OFF */

    else if (cistrcmp(name, "outlook-tls-bug") == 0) {
      CP->detect_incorrect_tls_use = 1;	/* Default: OFF */

    } else if (cistrcmp(name, "tls-cert-file") == 0 && param1) {
      CP->tls_cert_file = strdup(param1);
      if (!CP->tls_key_file)	/* default the other */
	CP->tls_key_file = strdup(param1);

    } else if (cistrcmp(name, "tls-key-file")  == 0 && param1) {
      CP->tls_key_file = strdup(param1);
      if (!CP->tls_cert_file)	/* default the other */
	CP->tls_cert_file = strdup(param1);

    } else if (cistrcmp(name, "tls-dcert-file") == 0 && param1) {
      CP->tls_dcert_file = strdup(param1);
      if (!CP->tls_dkey_file)	/* default the other */
	CP->tls_dkey_file = strdup(param1);

    } else if (cistrcmp(name, "tls-dkey-file")  == 0 && param1) {
      CP->tls_dkey_file = strdup(param1);
      if (!CP->tls_dcert_file)	/* default the other */
	CP->tls_dcert_file = strdup(param1);

    } else if (cistrcmp(name, "tls-dh1024")  == 0 && param1) {
      CP->tls_dh1024_param = strdup(param1);

    } else if (cistrcmp(name, "tls-dh512")  == 0 && param1) {
      CP->tls_dh512_param = strdup(param1);

    } else if (cistrcmp(name, "tls-random-source")  == 0 && param1) {
      CP->tls_random_source = strdup(param1);

    } else if (cistrcmp(name, "tls-cipher-list")  == 0 && param1) {
      CP->tls_cipherlist = strdup(param1);

    } else if (cistrcmp(name, "tls-CAfile")    == 0 && param1) {
      CP->tls_CAfile = strdup(param1);

    } else if (cistrcmp(name, "tls-CApath")    == 0 && param1) {
      CP->tls_CApath = strdup(param1);

    } else if (cistrcmp(name, "tls-loglevel")  == 0 && param1) {
      sscanf(param1,"%d", & CP->tls_loglevel);

    } else if (cistrcmp(name, "tls-enforce-tls")==0 && param1) {
      sscanf(param1,"%d", & CP->tls_enforce_tls);

    } else if (cistrcmp(name, "tls-ccert-vd")  == 0 && param1) {
      sscanf(param1,"%d", & CP->tls_ccert_vd);

    } else if (cistrcmp(name, "tls-ask-cert")  == 0 && param1) {
      sscanf(param1,"%d", & CP->tls_ask_cert);

    } else if (cistrcmp(name, "tls-require-cert") == 0 && param1) {
      sscanf(param1,"%d", & CP->tls_req_cert);

    } else if (cistrcmp(name, "tls-use-scache") == 0) {
      CP->tls_use_scache = 1;
    } else if (cistrcmp(name, "tls-scache-name") == 0 && param1) {
      CP->tls_scache_name = strdup(param1);

    } else if (cistrcmp(name, "tls-scache-timeout") == 0 && param1) {
      sscanf(param1,"%d", & CP->tls_scache_timeout);

    } else if (cistrcmp(name, "report-auth-file")   == 0 && param1) {
      CP->reportauthfile = strdup(param1);

    } else if (cistrcmp(name, "lmtp-mode") == 0) {
      lmtp_mode = 1;
    }
#endif /* - HAVE_OPENSSL */


    /* Cluster-wide ETRN support for load-balanced smtp relay use */
    else if (cistrcmp(name, "etrn-cluster") == 0 && param3 /* 3 params */) {
      static int idx = 0;
      if (idx < MAX_ETRN_CLUSTER_IDX) {
	etrn_cluster[idx].nodename = strdup(param1);
	etrn_cluster[idx].username = strdup(param2);
	etrn_cluster[idx].password = strdup(param3);
	++idx;
      }
    }

    /* SPF related things */
    /* Generate SPF-Received header */
    else if (cistrcmp(name, "spf-received") == 0) {
      CP->use_spf=1;
      CP->spf_received=1;
    }
    /* Reject mail if SPF query result is equal or higher than threshold */
    else if (cistrcmp(name, "spf-threshold") == 0 && param1 /* 1 param */) {
      CP->use_spf=1;
      if (cistrcmp(param1, "fail") == 0) {
	CP->spf_threshold=1;	/* relaxed - they say: fail but we accept */
      } else if (cistrcmp(param1, "softfail") == 0) {
	CP->spf_threshold=2;	/* default - they don't assume real reject */
      } else if (cistrcmp(param1, "none") == 0) {
	CP->spf_threshold=3;	/* stricter - but allow all who don't publish */
      } else if (cistrcmp(param1, "neutral") == 0) {
	CP->spf_threshold=4;	/* draconian - SFP-less won't pass */
      } else if (cistrcmp(param1, "pass") == 0) {
	CP->spf_threshold=5;	/* extreme - allow only explicit 'pass' */
      } else {
	type(NULL,0,NULL, "Cfgfile '%s' line %d param %s has bad arg: '%s'",
		cfgfilename, linenum, name, param1);
	CP->spf_threshold=0;	/* always accept (even 'fail') */
      }
    }
    /* SPF localpolicy setting */
    else if (cistrcmp(name, "spf-localpolicy") == 0 && param1 /* 1 param */) {
        CP->use_spf=1;
        CP->spf_localpolicy=strdup(param1);
    }
    /* SPF localpolicy: whether to include default whitelist or not */
    else if (cistrcmp(name, "spf-whitelist-use-default") == 0 && param1 /* 1 param */) {
	CP->use_spf=1;
        if(cistrcmp(param1,"true") == 0) {
	  CP->spf_whitelist_use_default=1; /* 'include:spf.trusted-forwarder.org' added to localpolicy */
        } else if (cistrcmp(param1,"false") == 0) {
	  CP->spf_whitelist_use_default=0;
        } else {
            type(NULL,0,NULL, "Cfgfile '%s' line %d param %s has bad arg: '%s'",
                    cfgfilename, linenum, name, param1);
            CP->spf_whitelist_use_default=0;
        }
    }

    else {
    bad_cfg_line:;
      /* XX: report error for unrecognized PARAM keyword ?? */
      type(NULL,0,NULL, "Cfgfile '%s' line %d has bad PARAM keyword/missing parameters: '%s'", cfgfilename, linenum, name);
    }
}

struct smtpconf *
readcffile(name)
     const char *name;
{
    FILE *fp;
    struct smtpconf scf, *head, *tail = NULL;
    unsigned char c;
    char *cp, buf[1024], *s, *s0;
    int linenum = 0;

    if ((fp = fopen(name, "r")) == NULL)
	return NULL;
    head = NULL;
    buf[sizeof(buf) - 1] = 0;
    while (fgets(buf, sizeof buf, fp) != NULL) {
	++linenum;
	c = buf[0];
	if (c == '#' || (isascii(c) && isspace(c)))
	    continue;
	if (buf[sizeof(buf) - 1] != 0 &&
	    buf[sizeof(buf) - 1] != '\n') {
	  int cc;
	  while ((cc = getc(fp)) != '\n' &&
		 cc != EOF);	/* Scan until end-of-line */
	}
	buf[sizeof(buf) - 1] = 0;	/* Trunc, just in case.. */

	cp = buf;
	cp = SKIPSPACE (cp);
	if (strncmp(cp, "PARAM", 5) == 0) {
	    cfparam(cp, sizeof(buf) -(cp-buf), name, linenum);
	    continue;
	}
	scf.flags = "";
	scf.next = NULL;
	s0 = cp;
	cp = SKIPTEXT (cp);
	c = *cp;
	*cp = '\0';
	s0 = strdup(s0);
	for (s = s0; *s; ++s)
	    if (isascii(*s & 0xFF) && isupper(*s & 0xFF))
		*s = tolower(*s & 0xFF);
	scf.pattern = s0;
	scf.maxloadavg = 999;
	if (c != '\0') {
	    ++cp;
	    cp = SKIPSPACE (cp);
	    if (*cp && isascii((255 & *cp)) && isdigit((255 & *cp))) {
		/* Sanity-check -- 2 is VERY LOW */
		if ((scf.maxloadavg = atoi(cp)) < 2)
		    scf.maxloadavg = 2;
		cp = SKIPDIGIT (cp);
		cp = SKIPSPACE (cp);
	    }
	    scf.flags = strdup(cp);
	    if ((cp = strchr(scf.flags, '\n')) != NULL)
		*cp = '\0';
	}
	if (head == NULL) {
	    head = tail = (struct smtpconf *) emalloc(sizeof scf);
	    *head = scf;
	} else {
	    tail->next = (struct smtpconf *) emalloc(sizeof scf);
	    *(tail->next) = scf;
	    tail = tail->next;
	}
	configuration_ok = 1; /* At least something! */
    }
    fclose(fp);
    if (!called_getbindaddr) {
      if (use_ipv6)
	cfg_add_bindaddr( NULL, 1, BINDADDR_ALL, 0 );
      cfg_add_bindaddr( NULL, 0, BINDADDR_ALL, 0 );
    }
    CP->bindaddr_set = (CP->bindaddrs != NULL);
#if !(defined(HAVE_SPF_ALT_SPF_H) || defined(HAVE_SPF2_SPF_H))
    if (CP->use_spf) {
      type(NULL,0,NULL, "SPF parameters specified but SPF support not compiled in");
    }
#endif
    return head;
}

struct smtpconf *
findcf(h)
     const char *h;
{
    struct smtpconf *scfp;
    register char *cp, *s;
    int c;

#ifndef	USE_ALLOCA
    cp = (char*)emalloc(strlen(h) + 1);
#else
    cp = (char*)alloca(strlen(h) + 1);
#endif
    for (s = cp; *h != '\0'; ++h) {
	c = (*h) & 0xFF;
	if (isascii(c) && isalpha(c) && isupper(c))
	    *s++ = tolower(c);
	else
	    *s++ = c;
    }
    *s = '\0';
    for (scfp = cfhead; scfp != NULL; scfp = scfp->next) {
	if (strmatch(scfp->pattern, cp)) {
#ifndef USE_ALLOCA
	    free(cp);
#endif
	    return scfp;
	}
    }
#ifndef USE_ALLOCA
    free(cp);
#endif
    return NULL;
}
