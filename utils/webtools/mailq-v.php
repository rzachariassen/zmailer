<?php # -*- perl -*- # Hi Emacs, edit as if it is perl... ?>
<HTML>
<HEAD>
<TITLE>ZMailer's mailq -v in various forms</TITLE>
</HEAD>
<BODY>
<H1>System ZMailer's "mailq -v" in various forms</H1>

<P>
 <A HREF="mailq-q.php?QA=3">Long-duration queue entries</A>
&nbsp;
 <A HREF="mailq-q.php?A=1">Queues with retries</A>
&nbsp;
 <A HREF="mailq-q.php">Full queue print</A>

<P>
 Explanations for the queue printout are at ZMailer's
 <A HREF="http://www.zmailer.org/man/mailq.1.html">mailq(1)</A> man-page.
<P>

<?php

$CHAN = $HTTP_GET_VARS["C"];
$HOST = $HTTP_GET_VARS["H"];

if ($CHAN == "" || $HOST == "") {

    printf("<B>BAD INPUT</B>\n");

} else {

    echo ("<FONT SIZE=\"-1\">\n");
    echo ("<PRE>\n");

# special processing to get queue-detail printout parameters..

    $CHAN = escapeshellarg($CHAN);
    $HOST = escapeshellarg($HOST);

    $patterns[0] = "/&/";
    $patterns[1] = "/>/";
    $patterns[2] = "/</";
    $patterns[3] = "/@/";

    $replacements[0] = "&amp;";
    $replacements[1] = "&gt;";
    $replacements[2] = "&lt;";
    $replacements[3] = "&#64;";


    $fh = popen("/opt/mail/bin/mailq -v -c ".$CHAN." -h ".$HOST, 'r');

    while (!feof ($fh)) {
        $buffer = fgets($fh, 4096);
	
	print preg_replace($patterns, $replacements, $buffer);
    }

    pclose($fh);
}

?>

</PRE>
</FONT>

<P>

</BODY>
</HTML>
