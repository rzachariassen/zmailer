#!/bin/sh

LSCMD="ls -l --full-time"
AWKARG='{printf "%s %2s %s %s  %12s <A HREF=\"%s\">%s</A>\n",$7,$8,$9,$10,$5,$11,$11}'

cat <<EOF
<HTML>
<HEAD><TITLE>ZMailer manual test dump index</TITLE></HEAD>
<BODY>
<H1>ZMailer manual test dump index:</H1>
<PRE>
<HR>
EOF
$LSCMD  *.ps.gz | awk "$AWKARG"
cat <<EOF
<HR>
EOF
$LSCMD  zmanual.html | awk "$AWKARG"
$LSCMD *.html | egrep -v "zmanual.html|index.html" | awk "$AWKARG"
cat <<EOF
<HR>
EOF
$LSCMD *.css  | awk "$AWKARG"
cat <<EOF
<HR>
EOF
$LSCMD *.gif  | awk "$AWKARG"
cat <<EOF
<HR>
</PRE>
</BODY></HTML>
EOF
