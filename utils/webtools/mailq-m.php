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
Some day there will be a man-page: <A HREF="http://zmailer.org/man/mailq-m.5.html">mailq-M(5)</A>
<P>
ZMailer has several subsystems:
<UL>
<LI> SYS: non-subsystem data
<LI> SS: Smtpserver
<LI> RT: Router
<LI> SC: scheduler
<LI> TA-*: transport agents:
 <UL>
  <LI> TA-SMTP: Outgoing SMTP 
  <LI> TA-SMCM: Sendmail-Compatible-Mailer
  <LI> TA-MBOX: Delivery to std UNIX mailboxes, and to pipes
  <LI> TA-HOLD: Routing produced 'deferred' results, addresses go to 'hold' for latter retry
  <LI> TA-ERRM: Messages/recipients routed directly to an error channel
  <LI> TA-EXPI: Messages/recipients, which sysadmin decided to expire from the outgoing queue via special tool
  <LI> TA-RERT: Messages/recipients, which sysadmin decided to reroute from the outgoing queue via special tool
 </UL>
</UL>
<P>

<FONT SIZE="-1">
<PRE>
<?php


# This does work also with:   mailq -QQQQ
# ... but requires that the scheduler is running.

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
