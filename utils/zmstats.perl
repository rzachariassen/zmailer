#!/usr/local/bin/perl
# From Matti Aarnio <mea@utu.fi>
eval "exec /usr/local/bin/perl -S $0 $*"
    if $running_under_some_shell;
			# this emulates #! processing on NIH machines.
			# (remove #! line above if indigestible)

select(STDERR); $| = 1;
select(STDOUT); $| = 1;

eval "\$.$1.\$2;" while $ARGV[0] =~ /^([A-Za-z_]+=)(.*)/ && shift;
			# process any FOO=bar switches

$tmpfile="/tmp/zmstat$$";

open(____tmpfile_uid_, ">$tmpfile.uid") ||
  die "Cannot create file \"$tmpfile.uid\"";

open(____tmpfile_gid_, ">$tmpfile.gid") ||
  die "Cannot create file \"$tmpfile.gid\"";

open(____tmpfile_with_, ">$tmpfile.with") ||
  die "Cannot create file \"$tmpfile.with\"";

open(____tmpfile_rcvd_, ">$tmpfile.rcvd") ||
  die "Cannot create file \"$tmpfile.rcvd\"";

open(____tmpfile_sender_, ">$tmpfile.sender") ||
  die "Cannot create file \"$tmpfile.sender\"";

$[ = 1;			# set array base to 1
$, = " ";		# set output field separator
$\ = "\n";		# set output record separator

$key{"uid"} = "uid";
$key{"gid"} = "gid";
$key{"size"} = "size";
$key{"headersize"} = "headersize";
$key{"bodysize"} = "bodysize";
$key{"delay"} = "delay";
$key{"resent"} = "resent";
$key{"trusted"} = "trusted";
$key{"external"} = "external";
$key{"rcvdfrom"} = "rcvdfrom";
$key{"with"} = "with";
$value{"size"} = 0;
foreach $i (keys %value) {
    $value{$i} = 0;
}

while (<>) {
    chop;	# strip record separator
    @Fld = split(" ", $_, 9999);
    if (/ file: /) {
	$S = substr($_, index($_, " file: ") + 7, 999999);
	$i = index($S, " ") + 1;
	$S = substr($S, $i, index($S, " =>") - $i);
	$i = index($S, "<");
	if ($i > 0) {
	    $S = substr($S, $i + 1, 999999);
	}
	$i = index($S, ":");
	if ($i > 0) {
	    $S = substr($S, $i + 1, 999999);
	}
	$i = index($S, ">");
	if ($i > 0) {
	    $S = substr($S, 1, $i - 1);
	}
	$sender = $S;
    }
    if (/ info: /) {
	$count += 1;
	for ($i = 1; $i < $#Fld; ++$i) {
	    if (defined $key{$Fld[$i]}) {
		$value{$key{$Fld[$i]}} = $Fld[$i + 1];
		if ($key{$Fld[$i]} eq "external") {
		    ++$i;
		}
	    }
	}
	$uid{$value{"uid"}} += 1;
	$gid{$value{"gid"}} += 1;
	$size += $value{"size"};
	$bytes{$value{"uid"}} += $value{"size"};
	$grbytes{$value{"gid"}} += $value{"size"};
	$headersize += $value{"headersize"};
	$bodysize += $value{"bodysize"};
	$delay += $value{"delay"};
	$resent{$value{"resent"}} += 1;
	$trusted{$value{"trusted"}} += 1;
	if (defined $value{"rcvdfrom"} != 0) {
	    $rcvdfrom{$value{"rcvdfrom"}} += 1;
	    # If the message was local
	    ;
	}
	$price = 0.40;
	if ($value{"size"} > 10000) {
	    $price += 0.10 * ($value{"size"} - 10000) / 1000;
	}
	if ($value{"external"} == 0) {
	    $cost{$value{"uid"}} += $price;
	    $grcost{$value{"gid"}} += $price;
	}
	elsif ($value{"rcvdfrom"} != 0) {
	    $external += 1;
	    $cost{$value{"rcvdfrom"}} += $price;
	    $rbytes{$value{"rcvdfrom"}} += $value{"size"};
	}
	else {
	    $external += 1;
	}
	$postage{$sender} += $price;
	$pcount{$sender} += 1;
	$pbytes{$sender} += $value{"size"};
	if ($value{"with"} != 0) {
	    $with{$value{"with"}} += 1;
	    $wbytes{$value{"with"}} += $value{"size"};
	    $wcost{$value{"with"}} += $price;
	}
	foreach $i (keys %value) {
	    $value{$i} = 0;
	}
    }
}

print "size = " . $size . " avg = " . $size / $count;
print "headersize = " . $headersize . " avg = " . $headersize / $count;
print "bodysize = " . $bodysize . " avg = " . $bodysize / $count;
print "avg delay = " . $delay / $count;
print "resent yes = " . $resent{"yes"} . " no = " . $resent{"no"};
print "trusted yes = " . $trusted{"yes"} . " no = " . $trusted{"no"};
print "external = " . $external;
print $_;
foreach $i (keys %uid) {
    printf ____tmpfile_uid_ "%d\t%d\t%d\t%8.2f\n", $i, $uid{$i}, $bytes{$i},

      $cost{$i};
}
foreach $i (keys %gid) {
    printf ____tmpfile_gid_ "%d\t%d\t%d\t%8.2f\n", $i, $gid{$i}, $grbytes{$i},

      $grcost{$i};
}
foreach $i (keys %with) {
    printf ____tmpfile_with_ "%s\t%d\t%d\t%8.2f\n", $i, $with{$i},

      $wbytes{$i}, $wcost{$i};
}
foreach $i (keys %rcvdfrom) {
    printf ____tmpfile_rcvd_ "%s\t%d\t%d\t%8.2f\n", $i, $rcvdfrom{$i},

      $rbytes{$i}, $cost{$i};
}
foreach $i (keys %postage) {
    printf ____tmpfile_sender_ "%s\t%d\t%d\t%8.2f\n", $i, $pcount{$i},

      $pbytes{$i}, $postage{$i};
}

close(____tmpfile_uid_);
close(____tmpfile_gid_);
close(____tmpfile_with_);
close(____tmpfile_rcvd_);
close(____tmpfile_sender_);

print "UID\nKey\tmap{key}\tbytes\tcost\n";
system("cat $tmpfile.uid | sort +3nr ");
print "\nGID\nKey\tmap{key}\tbytes\tcost\n";
system("cat $tmpfile.gid | sort +3nr ");
print "\nWITH\nKey\tmap{key}\tbytes\tcost\n";
system("cat $tmpfile.with | sort +3nr ");
print "\nReceived From\nKey\tmap{key}\tbytes\tcost\n";
system("cat $tmpfile.rcvd | sort +3nr ");
print "\nPostage\nKey\tmap{key}\tbytes\tcost\n";
system("cat $tmpfile.sender | sort +3nr ");

unlink("$tmpfile.uid");
unlink("$tmpfile.gid");
unlink("$tmpfile.with");
unlink("$tmpfile.rcvd");
unlink("$tmpfile.sender");
