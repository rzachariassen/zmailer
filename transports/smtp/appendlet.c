/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Copyright 1991-2003 by Matti Aarnio -- modifications, including MIME
 */

#include "smtp.h"

#define ALARM_BLOCKSIZE 2000 /* Not alarm() thing, but more for reports.. */


/*
 * appendlet - append letter to file pointed at by fd
 */

int
appendlet(SS, dp, convertmode, CT)
	SmtpState *SS;
	struct ctldesc *dp;
	CONVERTMODE convertmode;
	struct ct_data *CT;
{
	/* `convertmode' controls the behaviour of the message conversion:
	     _CONVERT_NONE (0): send as is
	     _CONVERT_QP   (1): Convert 8-bit chars to QUOTED-PRINTABLE
	     _CONVERT_MULTIPARTQP (2): Convert substructures to QP
	     _CONVERT_8BIT (3): Convert QP-encoded chars to 8-bit
	     _CONVERT_UNKNOWN (4): Turn message to charset=UNKNOWN-8BIT, Q-P..
	 */

	register int i, rc;
	int lastwasnl = 0;
	int ct_boundary_len = 999999;

	volatile int bufferfull = 0;
	char iobuf[ZBUFSIZ];
	Sfio_t *mfp = NULL;

	if (CT && CT->boundary)
	  ct_boundary_len = strlen(CT->boundary);

	SS->state  = 1;
	SS->column = -1;
	SS->alarmcnt = ALARM_BLOCKSIZE;
	SS->lastch = '\n'; /* WriteMIMELine() can decode-QP and then the
			      "lastwasnl" is no longer valid .. */

	/* AlarmJmp wraps the  appendlet()  to an all encompasing
	   wrapping which breaks out of the lower levels if the
	   timer does not get reset.. */

	gotalarm = 0;


#define MFPCLOSE	if (mfp != NULL) {				\
			  zsfsetfd(mfp,-1);	/* keep the fd      */	\
			  sfclose(mfp);		/* close the stream */	\
			}

	if (statusreport)
	  report(SS,"DATA %d/%d (%d%%)",
		   SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
#if 0 /* No, we aren't SYNCin now.. */
	sfsync(SS->smtpfp);
	if (gotalarm) {
	  sprintf(SS->remotemsg,"smtp; 500 (msgbuffer write timeout!  DATA %d/%d [%d%%])",
		  SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
	  return EX_IOERR;
	}
#endif


	if (ta_use_mmap <= 0) {
	  /* Using MALLOC()ed memory block */

	  /* Makeing sure we are properly positioned
	     at the begin of the message body */

	  if (lseek(dp->msgfd, (off_t)dp->msgbodyoffset, SEEK_SET) < 0L)
	    warning("Cannot seek to message body! (%m)", (char *)NULL);

	  lastwasnl = 1;	/* we are guaranteed to have a \n after
				   the header */

	  if (convertmode == _CONVERT_NONE) {
	    bufferfull = 0;

	    if (readalready > 0) {
	      i = readalready;

	      lastwasnl = (dp->let_buffer[i-1] == '\n');
	      rc = writebuf(SS, dp->let_buffer, i);

	      if (statusreport)
		report(SS,"DATA %d/%d (%d%%)",
		       SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
	      /* We NEVER get timeouts here.. We get anything else.. */
	      if (rc != i) {
		goto write_error_processing;
	      }
	      goto lastch_processing;
	    }

	    for (;;) {
	      /* Optimization:  If the buffer has stuff in it due to
		 earlier read in some of the check algorithms, we use
		 it straight away: */
	      i = read(dp->msgfd, (void*)(dp->let_buffer), dp->let_buffer_size);
	      if (i == 0) /*EOF*/
		break;
	      if (i < 0) {
		if (errno == EINTR || errno == EAGAIN)
		  continue; /* Restart in good POSIX style.. */
		strcpy(SS->remotemsg,
		       "smtp; 500 (Read error from message file!?)");
		return EX_IOERR;
	      }
	      readalready = i;
	      ++bufferfull;

	      lastwasnl = (dp->let_buffer[i-1] == '\n');
	      rc = writebuf(SS, dp->let_buffer, i);
	      if (statusreport)
		report(SS,"DATA %d/%d (%d%%)",
		       SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
	      /* We NEVER get timeouts here.. We get anything else.. */
	      if (rc != i) {

	      write_error_processing:;

		if (gotalarm) {
		  sprintf(SS->remotemsg,"smtp; 500 (msgbuffer write timeout!  DATA %d/%d [%d%%])",
			  SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
		  return EX_IOERR;
		}
		sprintf(SS->remotemsg,
			"smtp; 500 (msgbuffer write IO-error[1]! [%s] DATA %d/%d [%d%%])",
			strerror(errno),
			SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
		return EX_IOERR;
	      }
	    } /* .. end for() */

	    if (bufferfull > 1)
	      readalready = 0;  /* More than one bufferfull read.. */

	    /* End of "NO CONVERSIONS" mode, then ... */

	  } else {

	    /* ... various esoteric conversion modes:
	       We are better to feed writemimeline() with
	       LINES instead of blocks of data.. */

	    /* Classical way to read in things, one line at the time! */

	    mfp = sfnew(NULL, iobuf, sizeof(iobuf), dp->msgfd, SF_READ);
	    readalready = 0;

	    /* we are assuming to be positioned properly
	       at the start of the message body */
	    lastwasnl = 0;
	    for (;;) {

	      i = csfgets((void*)(dp->let_buffer), dp->let_buffer_size, mfp);
	      if (i <= 0)
		break; /* EOF, or such.. */

	      /* It MAY be malformed -- if it has a ZBUFSIZ*8 length
	       line in it, IT CAN'T BE STANDARD CONFORMANT MIME  :-/	*/

	      lastwasnl = (dp->let_buffer[i-1] == '\n');

	      /* XX: Detect multiparts !! */
	      if (CT && CT->boundary /* defined at all! */ &&
		  dp->let_buffer[0] == '-' &&
		  dp->let_buffer[1] == '-' &&
		  i > ct_boundary_len &&
		  memcmp(dp->let_buffer+2, CT->boundary, ct_boundary_len)==0){
		/* Begin/intermediate/end boundary line of something */
		
		/* XXX: Multipart part-switching line detected ? */

	      }

	      /* Ok, write the line -- decoding QP can alter
		 the "lastwasnl" */

	      rc = writemimeline(SS, dp->let_buffer, i, convertmode);

	      /* We NEVER get timeouts here.. We get anything else.. */
	      if (rc != i) {
		sprintf(SS->remotemsg,
			"500 (msgbuffer write IO-error[2]! [%s] DATA %d/%d [%d%%])",
			strerror(errno),
			SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
		MFPCLOSE;
		return EX_IOERR;
	      }
	    } /* End of line loop */

	    if (i == EOF && !sfeof(mfp)) {
	      strcpy(SS->remotemsg, "500 (Read error from message file!?)");
	      MFPCLOSE;
	      return EX_IOERR;
	    }
	    MFPCLOSE;

	  } /* ... end of conversion modes */

	} else { /* WITH MMAP()ED MEMORY BLOCK */

	  if (convertmode == _CONVERT_NONE) {
	    const char *p = dp->let_buffer + dp->msgbodyoffset;
	    i = dp->let_end - dp->let_buffer - dp->msgbodyoffset;

	    lastwasnl = (p[i-1] == '\n');
	    rc = writebuf(SS, p, i);
	    if (statusreport)
	      report(SS,"DATA %d/%d (%d%%)",
		     SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
	    /* We NEVER get timeouts here.. We get anything else.. */
	    if (rc != i) {
	      if (gotalarm) {
		sprintf(SS->remotemsg,"smtp; 500 (msgbuffer write timeout!  DATA %d/%d [%d%%])",
			SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
		return EX_IOERR;
	      }
	      sprintf(SS->remotemsg,
		      "smtp; 500 (msgbuffer write IO-error[1]! [%s] DATA %d/%d [%d%%])",
		      strerror(errno),
		      SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
	      return EX_IOERR;
	    }
	    /* End of "NO CONVERSIONS" mode, then ... */

	  } else {

	    /* ... various esoteric conversion modes:
	       We are better to feed writemimeline() with
	       LINES instead of blocks of data.. */

	    const char *s = dp->let_buffer + dp->msgbodyoffset;

	    /* we are assuming to be positioned properly
	       at the start of the message body */
	    lastwasnl = 0;
	    for (;;) {

	      const char *p = s, *s2 = s;
	      if (s >= dp->let_end) break; /* EOF */
	      i = 0;
	      while (s2 < dp->let_end && *s2 != '\n')
		++s2, ++i;
	      if ((lastwasnl = (*s2 == '\n')))
		++s2, ++i;
	      s = s2;
	      
	      /* XX: Detect multiparts !! */
	      if (CT && CT->boundary /* defined at all! */ &&
		  p[0] == '-' &&
		  p[1] == '-' &&
		  i > ct_boundary_len &&
		  memcmp(p+2, CT->boundary, ct_boundary_len)==0) {
		/* Begin/intermediate/end boundary line of something */
		
		/* XXX: Multipart part-switching line detected ? */

	      }

	      /* Ok, write the line -- decoding QP can alter the "lastwasnl" */
	      rc = writemimeline(SS, p, i, convertmode);

	      /* We NEVER get timeouts here.. We get anything else.. */
	      if (rc != i) {
		sprintf(SS->remotemsg,
			"500 (msgbuffer write IO-error[2]! [%s] DATA %d/%d [%d%%])",
			strerror(errno),
			SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
		return EX_IOERR;
	      }
	      s = s2; /* Advance one linefull.. */
	    
	    } /* End of line loop */
	    
	  } /* ... end of conversion modes */
	}

 lastch_processing:;

	/* we must make sure the last thing we transmit is a CRLF sequence */
	if (!lastwasnl || SS->lastch != '\n') {
	  if (writebuf(SS, "\n", 1) != 1) {
	    if (gotalarm) {
	      sprintf(SS->remotemsg,"500 (msgbuffer write timeout!  DATA %d/%d [%d%%])",
		      SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
	      return EX_IOERR;
	    }
	    sprintf(SS->remotemsg,
		    "500 (msgbuffer write IO-error[3]! [%s] DATA %d/%d [%d%%])",
		    strerror(errno),
		    SS->hsize, SS->msize, (SS->hsize*100+SS->msize/2)/SS->msize);
	    if (bufferfull > 1) readalready = 0;
	    return EX_IOERR;
	  }
	}

	if (bufferfull > 1)	/* not all in memory, need to reread */
	  readalready = 0;
#if 0
	if (sfsync(SS->smtpfp) != 0) {
	  return EX_IOERR;
	}
#endif

	return EX_OK;
}


#ifdef DO_CHUNKING

extern int ssputc __(( SmtpState *, int, Sfio_t * ));

int
ssputc(SS, ch, fp)
     SmtpState *SS;
     int ch;
     Sfio_t *fp;
{
  if (SS->chunkbuf == NULL) {
    if (sferror(fp)) return EOF;
    if (sfputc(fp, ch) < 0) return EOF;
    return 0;
  }
  if (SS->chunksize >= CHUNK_MAX_SIZE) {
    if (bdat_flush(SS, 0) != EX_OK) /* Not yet the last one! */
      return EOF;
  }
  if (SS->chunksize >= SS->chunkspace) {
    SS->chunkspace <<= 1; /* Double the size */
    SS->chunkbuf = realloc(SS->chunkbuf, SS->chunkspace);
    if (SS->chunkbuf == NULL)
      return EOF;
  }
  SS->chunkbuf[SS->chunksize] = ch;
  SS->chunksize += 1;
  return 0;
}

#else

#define ssputc(SS,ch,fp) sfputc((fp),(ch))

#endif


#if 0
# define VLSFPRINTF(x) if(SS->verboselog)fprintf x
#else
# define VLSFPRINTF(x)
#endif
/*
 * Writebuf() is like write(), except all '\n' are converted to "\r\n"
 * (CRLF), and the sequence "\n." is converted to "\r\n..".
 * writebuf() has a cousin: writemimeline(), which does some more esoteric
 * conversions on flight..
 */
int
writebuf(SS, buf, len)
	SmtpState *SS;
	const char *buf;
	int len;
{
	Sfio_t *fp = SS->smtpfp;
	register const char *cp;
	register int n;
	register int state;
	int alarmcnt;

	state  = SS->state;
	alarmcnt = SS->alarmcnt;
	for (cp = buf, n = len; n > 0 && !gotalarm; --n, ++cp) {
	  register char c = (*cp) & 0xFF;
	  ++SS->hsize;

	  if (--alarmcnt <= 0) {
	    alarmcnt = ALARM_BLOCKSIZE;
	    /* sfsync(fp); */

	    if (statusreport)
	      report(SS,"DATA %d/%d (%d%%)",
		     SS->hsize, SS->msize,
		     (SS->hsize*100+SS->msize/2)/SS->msize);
	  }

	  if (state && c != '\n') {
	    state = 0;
	    if (c == '.' && !SS->doing_chunking) {
	      if (ssputc(SS, c, fp) == EOF || ssputc(SS, c, fp) == EOF) {
		time(&endtime);
		notary_setxdelay((int)(endtime-starttime));
		notaryreport(NULL,FAILED,"5.4.2 (body write error, 1)",
			     "smtp; 500 (body write error, 1)");
		strcpy(SS->remotemsg, "write error 1");
		return EOF;
	      }
	      VLSFPRINTF((SS->verboselog,".."));
	    } else {
	      if (ssputc(SS, c, fp) == EOF) {
		time(&endtime);
		notary_setxdelay((int)(endtime-starttime));
		notaryreport(NULL,FAILED,"5.4.2 (body write error, 2)",
			     "smtp; 500 (body write error, 2)");
		strcpy(SS->remotemsg, "write error 2");
		return EOF;
	      }
	      VLSFPRINTF((SS->verboselog,"%c",c));
	    }
	  } else if (c == '\n') {
	    if (ssputc(SS, '\r', fp) == EOF || ssputc(SS, c, fp) == EOF) {
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.2 (body write error, 3)",
			   "smtp; 500 (body write error, 3)");
	      strcpy(SS->remotemsg, "write error 3");
	      return EOF;
	    }
	    VLSFPRINTF((SS->verboselog,"\r\n"));
	    state = 1;
	  } else {
	    if (ssputc(SS, c, fp) == EOF) {
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.2 (body write error, 4)",
			   "smtp; 500 (body write error, 4)");
	      strcpy(SS->remotemsg, "write error 4");
	      return EOF;
	    }
	    VLSFPRINTF((SS->verboselog,"%c",c));
	  }
	}
	SS->state    = state;
	SS->alarmcnt = alarmcnt;
	return len;
}


int
writemimeline(SS, buf, len, convertmode)
	SmtpState *SS;
	const char *buf;
	int len;
	CONVERTMODE convertmode;
{
	Sfio_t *fp = SS->smtpfp;
	register const char *cp;
	register int n;
	char *i2h = "0123456789ABCDEF";
	int qp_chrs = 0;
	int qp_val = 0;
	int qp_conv;
	int column;
	int alarmcnt;

	/* `convertmode' controls the behaviour of the message conversion:
	     _CONVERT_NONE (0): send as is
	     _CONVERT_QP   (1): Convert 8-bit chars to QUOTED-PRINTABLE
	     _CONVERT_MULTIPARTQP (2): Convert substructures to QP
	     _CONVERT_8BIT (3): Convert QP-encoded chars to 8-bit
	     _CONVERT_UNKNOWN (4): Turn message to charset=UNKNOWN-8BIT, Q-P..
	 */

	alarmcnt = SS->alarmcnt;
	column   = SS->column;

	qp_conv = (convertmode == _CONVERT_QP ||
		   convertmode == _CONVERT_UNKNOWN);

	if (buf == NULL) {		/* magic initialization */
	  /* No magics here.. we are linemode.. */
	  return 0;
	}
	SS->lastch = -1;
	for (cp = buf, n = len; n > 0; --n, ++cp) {
	  register int c = (*cp) & 0xFF;
	  ++column;
	  ++SS->hsize;

	  if (--alarmcnt <= 0) {
	    alarmcnt = ALARM_BLOCKSIZE;
	    /* sfsync(fp); */

	    if (statusreport)
	      report(SS,"DATA %d/%d (%d%%)",
		     SS->hsize, SS->msize,
		     (SS->hsize*100+SS->msize/2)/SS->msize);
	  }

	  if (convertmode == _CONVERT_8BIT) {
	    if (c == '=' && qp_chrs == 0) {
	      qp_val = 0;
	      qp_chrs = 2;
	      continue;
	    }
	    if (qp_chrs != 0) {
	      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
		n = 0;		/* We have the line-end wrapper mode */
		continue;	/* It should NEVER be present except at
				   the end of the line, thus we are safe
				   to do this ? */
	      }
	      --column;
	      if ((c >= '0' && c <= '9') ||
		  (c >= 'a' && c <= 'f') ||
		  (c >= 'A' && c <= 'F')) {
		/* The first char was HEX digit, assume the second one
		   to be also, and convert all three (=XX) to be a char
		   of given value.. */
		if (c >= 'a') c -= ('a' - 'A');
		if (c > '9') c -= ('A' - '9' - 1);
		qp_val <<= 4;
		qp_val |= (c & 0x0F);
	      }
	      --qp_chrs;
	      if (qp_chrs == 0)
		c = qp_val;
	      else
		continue;
	    }
	    SS->lastch = c;
	  } else if (qp_conv) {
	    if (column > 70 && c != '\n') {
	      ssputc(SS, '=',  fp);
	      ssputc(SS, '\r', fp);
	      ssputc(SS, '\n', fp);
	      SS->lastch = '\n';
	      VLSFPRINTF((SS->verboselog,"=\r\n"));
	      column = 0;
	    }
	    /* Trailing SPACE/TAB ? */
	    if (n < 3 && (c == ' ' || c == '\t')) {
	      ssputc(SS, '=', fp);
	      ssputc(SS, i2h[(c >> 4) & 15], fp);
	      ssputc(SS, i2h[(c)      & 15], fp);
	      SS->lastch = i2h[(c) & 15];
	      column += 2;
	      VLSFPRINTF((SS->verboselog,"=%02X",c));
	      continue;
	    }
	    /* Any other char which needs quoting ? */
	    if (c == '='  ||  c > 126 ||
		(column == 0 && (c == 'F' || c == '.')) ||
		(c != '\n' && c != '\t' && c < 32)) {

	      ssputc(SS, '=', fp);
	      ssputc(SS, i2h[(c >> 4) & 15], fp);
	      ssputc(SS, i2h[(c)      & 15], fp);
	      SS->lastch = i2h[(c) & 15];
	      column += 2;
	      VLSFPRINTF((SS->verboselog,"=%02X",c));
	      continue;
	    }
	  } /* .... end convertmode	*/

	  if (column == 0 && c == '.' && !SS->doing_chunking) {
	    if (ssputc(SS, c, fp) == EOF) {
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.2 (body write error, 5)",
			   "smtp; 500 (body write error, 5)");
	      strcpy(SS->remotemsg, "write error 5");
	      return EOF;
	    }
	    VLSFPRINTF((SS->verboselog,".."));
	  }

	  if (c == '\n') {
	    if (ssputc(SS, '\r', fp) == EOF) {
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.2 (body write error, 6)",
			   "smtp; 500 (body write error, 6)");
	      strcpy(SS->remotemsg, "write error 6");
	      return EOF;
	    }
	    VLSFPRINTF((SS->verboselog,"\r"));
	    column = -1;
	  }
	  if (ssputc(SS, c, fp) == EOF) {
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.2 (body write error, 7)",
			 "smtp; 500 (body write error, 7)");
	    strcpy(SS->remotemsg, "write error 7");
	    return EOF;
	  }
	  SS->lastch = c;
	  VLSFPRINTF((SS->verboselog,"%c",c));

	}
	SS->column   = column;
	SS->alarmcnt = alarmcnt;
	return len;
}


/* When data is clean 7-BIT, do:  *flag_ptr = (*flag_ptr) << 1  */
int 
check_7bit_cleanness(dp)
struct ctldesc *dp;
{
      if (ta_use_mmap > 0) {

	/* With MMAP()ed spool file this is sweet and simple.. */

	const register char *s = dp->let_buffer + dp->msgbodyoffset;
	while (s < dp->let_end)
	  if (128 & *s)
	    return 0;
	  else
	    ++s;
	return 1;

      } else {


	register int i;
	register int bufferfull;
	int lastwasnl;
	off_t mfd_pos;
	int mfd = dp->msgfd;

	/* can we use cache of message body data ? */
	if (readalready != 0) {
	  for (i=0; i<readalready; ++i)
	    if (128 & (dp->let_buffer[i]))
	      return 0;		/* Not clean ! */
	}

	/* make sure we are properly positioned at the start
	   of the message body */
	bufferfull = 0;

	mfd_pos = lseek(mfd, (off_t)dp->msgbodyoffset, SEEK_SET);
	
	while (1) {
	  i = read(mfd, (void*)(dp->let_buffer), dp->let_buffer_size);
	  if (i == 0)
	    break;
	  if (i < 0) {
	    /* ERROR ?!?!? */
	    if (errno == EINTR)
	      continue; /* Hickup... */
	    readalready = 0;
	    return 0;
	  }
	  lastwasnl = (dp->let_buffer[i-1] == '\n');
	  readalready = i;
	  bufferfull++;
	  for (i = 0; i < readalready; ++i)
	    if (128 & (dp->let_buffer[i])) {
	      lseek(mfd, mfd_pos, SEEK_SET);
	      readalready = 0;
	      return 0;		/* Not clean ! */
	    }
	}
	/* Got to EOF, and still it is clean 7-BIT! */
	lseek(mfd, mfd_pos, SEEK_SET);
	if (bufferfull > 1)	/* not all in memory, need to reread */
	  readalready = 0;

	/* Set indication! */
	return 1;
      }
}
