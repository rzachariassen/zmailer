#! /bin/sh
#
#
#

F="man-index.html"

cat <<EOF  > $F
<HTML>
<HEAD><TITLE>ZMailer man-pages</TITLE></HEAD>
<BODY>

<H1>ZMailer man-pages of `TZ=UTC date`</H1>

<P>

<TABLE>
EOF

nn=""
c1=""
c2=""

for x in `ls *.html *.pdf`
do

    n="`echo $x|cut -d. -f-2`"

    if [ "x$n" != "x$nn" -a -n "$nn" ]; then
	echo "<TR>$c1$c2</TR>" >> $F
	#c1=""
	#c2=""
    fi
    nn="$n"

    case "$x" in
    *.html)
	c1="<TD><A HREF=\"$x\">$x</A></TD>"
	;;
    *.pdf)
	c2="<TD><A HREF=\"$x\">$x</A></TD>"
	;;
    esac

done

if [ -n "$c1" ]; then
    echo "<TR>$c1$c2</TR>" >> $F
fi

cat <<EOF  >> $F
</TABLE>
</BODY>
</HTML>
EOF

