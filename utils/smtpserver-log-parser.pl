#! /usr/bin/perl -T
#
# A parser to glob in smtpserver's log (via 'tail -f', for example)
# and to print out those sessions which have errors logged in them.
#

#
# NEW servers make log which has two kinds of session termination
# conditions:
#    #####w \t 221 ...
#    #####- \t ...
#
# That is, either a "w"-line with code 221, or a "-"-line.
#


#
#  You wonder why this utility was written ?
#  Well, "technical monitoring with tail -f" is something which propably
#  is not allowed for people in Telecom Carrier business in Finland.
#  
#


#
#  We collect streams of inputs of all pids; we discard
#  such sessions which end happily without presenting
#  any instance of $haserror.
#

%pidstore    = (); # Key: $pid.".".$sernro
%sernrostore = (); # Key: $pid
%iserr       = (); # key: $pid


while (<STDIN>) {
    $line = $_;
    chomp $line;

    #print "line='".$line."'\n";

    if ($line =~ m/^([0-9]*)([^0-9].*)$/) {
	$pid  = $1;
	$rest = $2;
    } else {
	$pid = "**";
	$rest = "**";
    }

    #print "pid='".$pid."'\n";
    #print "rest='".$rest."'\n";

    $isend = 0;
    if ($rest =~ m/^-/) {
	$isend = 1;
    }
    if ($rest =~ m/^w\t221/) {
	$isend = 1;
    }

    $haserror = 0;
    if ($rest =~ m/^w\t[45]/) {
	$haserror = 1;
    }

    if (!defined($sernrostore{$pid})) {
	# New PID
	$sernrostore{$pid} = 1;
	$iserr{$pid} = 0;
    }


    if ($haserror) {
	$iserr{$pid} = 1;

	local($hi,$i);
	$hi = $sernrostore{$pid};
	for ($i = 1; $i < $hi; ++$i) {
	    $key = $pid.".".$i;
	    printf "%s\n",$pidstore{$key};
	    delete $pidstore{$key};
	}
	$sernrostore{$pid} = 0;
    }

    if (!$iserr{$pid}) {
	$key = $pid.".".$sernrostore{$pid};
	$sernrostore{$pid} += 1;
	$pidstore{$key} = $line;
    } else {
	printf "%s\n",$line;
    }

    if ($isend) {
	local($hi,$i);
	$hi = $sernrostore{$pid};
	for ($i = 1; $i < $hi; ++$i) {
	    $key = $pid.".".$i;
	    delete $pidstore{$key};
	}
	delete $sernrostore{$pid};
	delete $iserr{$pid};
    }
}
