#! /bin/sh

#set -x

echo "<HTML><HEAD><TITLE>"
echo "$1"
echo "</TITLE></HEAD><BODY BGCOLOR=white><PRE>"
groff -t -man -Tascii "$1" | \
    perl -ne '
        select STDERR; $| = 1;
	s{&}{&amp;}og;
	#s{<}{&lt;}og;
	#s{>}{&gr;}og;
	s{_\010<}{<I>&lt;</I>}og;
	s{<\010<}{<B>&lt;</B>}og;
	s{_\010>}{<I>&gt;</I>}og;
	s{>\010>}{<B>&gt;</B>}og;
	#s{_\010&}{<I>&amp;</I>}og;
	#s{&\010&}{<B>&amp;</B>}og;
	while(m/(.)\010(.)/o) {
	  if ($1 eq $2) {
	    s{(.)\010(.)}{<B>$1</B>}o;
	  } elsif ($1 eq "_") {
	    s{(.)\010(.)}{<I>$2</I>}o;
	  } elsif ($1 eq "+" && $2 eq "o") {
            s{(.)\010(.)}{<B>o</B>}o;
	  } else {
	    printf STDERR "UNEXPECTED PATTERN: (%s)\\010(%s); str=\"%s\"\n",$1,$2,$0;
	    last;
	  }
	}
	s{</B><B>}{}og;
	s{</I><I>}{}og;
	s{</U><U>}{}og;
	s{</I><B>_</B><I>}{_}og;
        print STDOUT;'
echo "</PRE></BODY></HTML>"
