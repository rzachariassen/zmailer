#! /bin/sh
#
#
#

F="man-index.html"

cat <<EOF  > $F
<HTML>
<HEAD><TITLE>ZMailer man-pages</TITLE></HEAD>
<BODY BGCOLOR=white>

<H1>ZMailer man-pages of `TZ=UTC date`</H1>

<P>
<BLOCKQUOTE>
<TABLE>
<TR><TH ALIGN=LEFT>HTML</TH><TH>&nbsp;</TH><TH ALIGN=LEFT>PDF</TH></TR>
<TR><TD COLSPAN=3><P>&nbsp;</P></TD></TR>
EOF

nn=""
c1=""
c2=""

T="index.tmp.$$"
> $T

for x in *.html; do
  if [ $x != "man-index.html" ]; then
    basename $x .html >> $T
  fi
done
for x in *.pdf; do
    basename $x .pdf >> $T
done
bases="`sort $T | uniq`"
rm $T

mm="<TD>&nbsp;&nbsp;&nbsp;&nbsp;</TD>"

for x in $bases; do

    if [ -f "$x.html" ]; then
      hh="<TR><TD><A HREF=\"./$x.html\">$x</A></TD>$mm"
    else
      hh="<TR><TD>&nbsp;</TD>$mm"
    fi

    if [ -f "$x.pdf" ]; then
      echo "$hh<TD><A HREF=\"./$x.pdf\">$x</A></TD></TR>" >> $F
    else
      echo "$hh<TD>&nbsp;</TD></TR>" >> $F
    fi

done

cat <<EOF  >> $F
</TABLE>
</BLOCKQUOTE>
</BODY>
</HTML>
EOF

