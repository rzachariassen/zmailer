<HTML>
<HEAD>
</HEAD>
<BODY>
<H1>Monitoring VGER's ZMailer MTA</H1>
<H2>Live counter snapshot</H2>
<P>
Below various counter values may be zero,
that may mean that:
<UL>
<LI>That counter has not had use
<LI>There is no code to count that counter (yet)
</UL>
Various gauges may or may not be zero, all depending...
<P>
Volumes are in kilobytes ("-kB" suffix), all others are
single events.
<P>
Gauges are marked with "-G" suffix, all others are counters.
<P>
ZMailer has several subsystems:
<UL>
<LI> SYS: non-subsystem data
<LI> SS: Smtpserver
<LI> RT: Router
<LI> SC: scheduler
<LI> TA: transport agents of which there is particular interest to "outgoing SMTP".
</UL>
<P>

<FONT SIZE="-1">
<PRE>
<?php


$fh = popen('/opt/mail/bin/mailq -M','r');
while (!feof ($fh)) {
    $buffer = fgets($fh, 4096);
    echo $buffer;
}
pclose ($fh);

?>
</PRE>
</FONT>

<P>
</BODY>
</HTML>