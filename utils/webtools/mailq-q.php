<HTML>
<HEAD>
<TITLE>ZMailer's mailq -Q in various forms</TITLE>
</HEAD>
<BODY>
<H1>System ZMailer's "mailq -Q" in various forms</H1>

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

# Present shrunken version ?
$QAmode = 0;
$Amode  = 0;

if ($HTTP_GET_VARS["QA"] == "3") {
  $QAmode = 1;
}
if ($HTTP_GET_VARS["A"] == "1") {
  $Amode = 1;
}

if ($QAmode) {
  echo ("<H2>Selected listing of queues with soon to expire entries</H2>");
} elseif ($Amode) {
  echo ("<H2>Selected listing of queues with retried entries</H2>");
} else {
  echo ("<H2>Unabridged queue listing</H2>");
  echo ("<UL>");
  echo ("<LI><FONT COLOR=BLUE>BLUE</FONT> lines have QA over 3d0h, potential for expiring!");
  echo ("<LI><FONT COLOR=RED>RED</FONT> lines have too high value for HA=");
  echo ("</UL>");
}


 $mailq_v_base_url = "mailq-v.php";



?>


<FONT SIZE="-1">
<PRE>


<?php

# special processing to get queue-detail printout parameters..


function print_queue_line ($line) {
    $arrret=array();

    global $mailq_v_base_url;

    if (preg_match("/^(  *)([^\/]+)\/([^\/]+)(\/.*)\$/", $line, $arrret)) {
        printf ("%s<A HREF=\"%s?C=%s&H=%s\">%s/%s</A>%s\n",
		$arrret[1],
		$mailq_v_base_url,
		$arrret[2],$arrret[3],
		$arrret[2],$arrret[3],
		$arrret[4] 		);
    } else {
	echo $line;
    }
}


$fh = popen('/opt/mail/bin/mailq -Q','r');

while (!feof ($fh)) {
    $buffer = fgets($fh, 4096);

    if ($QAmode) {
      if (preg_match('/ QA=[3-9]d| QA=[1-9][0-9]d/',$buffer)) {
	print_queue_line($buffer);
      }
      if (preg_match('/^[\tA-Za-z]/',$buffer)) {
	print_queue_line($buffer);
      }
    } elseif ($Amode) {
      if (preg_match('/ A=[^0]/',$buffer)) {
	print_queue_line($buffer);
      }
      if (preg_match('/^[\tA-Za-z]/',$buffer)) {
	print_queue_line($buffer);
      }
    } else {
      if (preg_match('/ HA=\{([0-9]{5}|[2-9][0-9]{3})\}s /',$buffer)) {
	printf("<FONT COLOR=RED>");
	print_queue_line($buffer);
	printf("</FONT>");
      } else {
	if (preg_match('/ QA=[3-9]d| QA=[1-9][0-9]d/',$buffer)) {
	  printf("<FONT COLOR=BLUE>");
	  print_queue_line($buffer);
	  printf("</FONT>");
	} else {
	  print_queue_line($buffer);
	}
      }
    }
}

pclose($fh);

?>

</PRE>
</FONT>

<P>

</BODY>
</HTML>
