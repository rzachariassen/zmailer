#!/bin/sh
#
# usenet newsgroup1 ... newsgroupn
#
# sendmail-compatible usenet transport agent.
#                   Jean-Francois Lamy (lamy@ai.toronto.edu), 89-06-02
#
# The arguments are the newsgroups to which the article should be posted. A
# complete message, including To:, From: and From_ line expected on stdin.
# This assumes of course that the necessary magic has been done so that
# the mailer recognizes newsgroup name and decides to use the usenet transport
# agent on them.
#
# Notes:
#
# - this script should ultimately result in the invocation of a real
#   "inews" that deals with moderated newsgroups and invokes relaynews.
#   This version calls nntp, which results in calling a real inews on
#   the news server.
#   
# - The news program invoked by this script should trust From: lines
#   (otherwise workstation name hiding, full-name id generation and
#   all other smarts done by the mailer will be lost)
#
# - newsgroup "postnews" is ignored, and is used so one can mail
#   to a postnews alias a message with a Newsgroups: header, with
#   postnews aliased to postnews@usenet, where usenet is a fake host
#   handled by this transport agent.
#
# - Normally a From_ line of site!user and a From: line of user@site
#   should be produced. If your sendmail cannot be coerced into rewriting
#   envelope and headers differently you will need to kludge it here.
#
# ZMailer notes:
#
# - The default router.cf does the appropriate things, provided that
#   scheduler.cf contains:
#	usenet/*	1m	10 0 0	root	daemon	sm -c $channel usenet
#   sm.cf contains:
#	usenet	m	/local/lib/mail/bin/usenet	usenet $u
#      (adjust this to reflect the actual location of the installed copy of
#       this script, of course)
#   hosts.transport contains a line with:
#       usenet usenet!  
#   and that the aliases file contains aliases of the form
#       gradnews: gradnews@usenet
#      for all newsgroup names that don't have embedded ".").

exec 3>&1
exec >>/var/log/usenet 2>&1
date

# this version forwards the article via NNTP
. /etc/zmailer.conf  # Read  INEWSBIN, and NNTPSERVER

: ${NNTPSERVER:="news.funet.fi"}
export NNTPSERVER
# make sure this does not end up calling this script again!
: ${INEWSBIN:=/usr/local/bin/inews}	# inews of INN

# temp files
tmp=/usr/tmp/usenet.$$
hdrs=$tmp.hdrs
from=$tmp.from
body=$tmp.body
msgs=$tmp.msgs
rmlist="$hdrs $from $body $msgs"

orgflag=0
org="`cat /usr/lib/news/organi?ation`"
[ "$org" ] || orgflag=1  # do not print empty Organization: header

for i in $@
do
	groups="${groups+$groups,}$i"
done

awk "
BEGIN			{ subject = 0; body = 0; skipping = 0 ;
			  newsgroups = 0; distribution = 0;
			  organization = $orgflag; }
body == 1		{ print > thebody ; next }
/^[ \\t]*$/		{ np = split(path,parts,\"!\");
			  if (!organization && np == 1)
			      print \"Organization: $org\";
			  if (!newsgroups) print \"Newsgroups: $groups\";
			  if (!subject) print \"Subject: (none)\"; 
			  print > thebody ; body = 1; next
			}
/^To:|^X-To:|^Cc:|^Apparently-To:|^Original-To:/ {skipping = 1 ; next }
/^X400[^: \\t]*:/	{ skipping = 1; next }
/^Received:/		{ skipping = 1; next }
/^Newsgroups:/		{ newsgroups = 1; skipping = 0; 
			  printf(\"%s\",\$0);
		        if (\"$groups\" != \"\" && \"$groups\" != \"postnews\")
			     printf(\",%s\\n\",\"$groups\");
			  else printf(\"\\n\");
			  next }
/^Organi[sz]ation:/	{ organization = 1; skipping = 0; print; next }
/^Distribution:/	{ distribution = 1; skipping = 0; print; next }
/^Subject:/		{ subject = 1; skipping = 0; print; next }
/^X-NewsReferences:/	{ \$1 = \"References:\" ; 
			  skipping = 0; print; next }
/^From |^Return-Path:/	{ print \$2 > from ; path = \$2 ; skipping = 1; next }
/^[ \\t]/		{ if (skipping) next }
/^[A-Za-z-]*:[ \\t]*$/	{ next }
			{ print }
" from="$from" thebody="$body" - > $hdrs

# assemble article, get rid of route format and tabs in headers.
if [ -s $from ]; then
   echo -n $groups " -- ";cat $from
   (echo -n "Path: "; cat $from
    sed -e 's/^From:[ 	]*\(.*\)  *<\(.*\)>/From: \2 \(\1\)/' \
        -e 's/^\([^:]*:\)[	 ]*/\1 /' $hdrs 
    cat $body ) | $INEWSBIN -h >> $msgs 2>&1
    rc=$?
    if [ -s $msgs ] ; then
       cat $msgs
       cat $msgs 1>&3
       rm $rmlist
       exit $rc # remote protocol error
    else
       echo ok.
    fi
fi
rm $rmlist
exit 0
