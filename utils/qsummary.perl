From nic.funet.fi!zmailer-owner Sat Aug 27 01:43:31 1994
Received: from nic.funet.fi ([128.214.248.6]) by utu.fi with SMTP id <165739-4>; Sat, 27 Aug 1994 01:43:26 +0300
Received: from yonge.cs ([128.100.1.8]) by nic.funet.fi with SMTP id <91180-2>; Sat, 27 Aug 1994 01:43:05 +0300
Received: from Princeton.EDU ([128.112.128.1]) by yonge.cs.toronto.edu with SMTP id <62525>; Fri, 26 Aug 1994 18:25:55 -0400
Received: from yo.Princeton.EDU by Princeton.EDU (5.65b/2.111/princeton)
	id AA22910; Fri, 26 Aug 94 18:25:46 -0400
Received: by yo.Princeton.EDU (4.1/princeton-Client)
	id AA07428; Fri, 26 Aug 94 18:25:44 EDT
Message-Id: <9408262225.AA07428@yo.Princeton.EDU>
To:	zmailer@cs.toronto.edu
Subject: qsummary script
Organization: Princeton University, Network Systems, Class. 56
X-Mailer: exmh version 1.4.1 7/21/94
Date:	Sat, 27 Aug 1994 01:25:43 +0300
From:	"Michael R. Gettes" <gettes@Princeton.EDU>
Status: O

The following script shows a summary of the zmailer queues.
It shows the hosts queued, number of msgs and recipients per host queue.
It identifies active hosts (a connection or resolution is in progress).
specifying "-d pattern" like "-d princeton" would show detailed info
(what you would see from mailq -s) on any host containing princeton.
You can also restrict your view without the -d option as well. You
need perl to run it, of course. Alter the $mailqcmd to reflect the path
to your mailq command for zmailer. Enjoy!

/mrg

#!/usr/local/bin/perl -s

# -d show detail info on a destination (by pattern)
# The total line shows total number of hosts, msgs and recips
# The A found on some lines shows active connections

$mailqcmd = "mailq -d";

$detailed = 0;
$detailed = 1 if defined($d);
$match = ".*";
$match = @ARGV[0] if @ARGV[0] ne "";
$sort_field = "+1";
$sort_field = "+2" if defined($r);      # a -r means to sort by recipients
open(MAILQ,"$mailqcmd |") || die "open: $mailqcmd: $!\n";
if (!$detailed) {
        open(OUTPUT,"|sort -rn $sort_field +0d") || die "open: sort: $!\n";
} else {
        open(OUTPUT,">-");
}
select(STDOUT); $|=1;
$got_hosts = 1;
$got_channels = 2;
$got_vertices = 3;
$got = 0;
$host_count = 0;
while (<MAILQ>) {
        ($got = $got_vertices, next) if /^vertices:$/oi;
        ($got = $got_channels, next) if /^channels:$/oi;
        (print(STDOUT "\n"), $got = $got_hosts, next) if /^hosts:$/oi;
        if ($got == $got_vertices) {
                ($vertex,$msg,$recips,@msgs) = split;
                $vertex =~ s/:$//;
                $recips =~ s/;$//;
                $vertices{$vertex} = $recips;
                $recips = join(' ',@msgs);
                $recips =~ s/.*#//;
                $recips =~ s/connect: Connection // if /connect:/o;
                $vertall{$vertex} = sprintf("%-10s %s", $msg, $recips);
        }
        if ($got == $got_channels) {
                ($channel,$msgs) = split;
                @msgs = split(/[>]+/,$msgs);
                printf(STDOUT "%-10s\t\t%7d\n", $channel, $#msgs);
                next;
        }
        next unless $got == $got_hosts;
        ($host,$msgs) = split;
        next unless $host =~ /$match/oi;
        $host =~ s/:$//;
        @msgs = split(/[>]+/,$msgs);
        $recips = 0;
        foreach (@msgs) {
                $recips += $vertices{$_};
        }
        $rec_count += $recips;
        $msg_count += $#msgs;
        $active = "";
        $active = "A" if $vertall{@msgs[1]} =~ /^(\S+)\s+(\S+)\s*$/o;
        if ($host =~ /^ns:/) {
                printf(STDOUT "%-40s\t%s\t%5d%9d\n", $host, $active, $#msgs, 
$recips);
        } else {
                printf(OUTPUT "%-40s\t%s\t%5d%9d\n", $host, $active, $#msgs, 
$recips);
                if ($detailed) {
                        foreach (@msgs) {
                                printf(OUTPUT "\t%s\n", $vertall{$_}) if $_ ne 
"";
                        }
                }
        }
        $host_count++;
}
close(MAILQ);
&separate() unless $detailed;
close(OUTPUT);
printf(STDOUT "\n%-40s\t%5d%8d%9d\n", "Total Queued:", $host_count, 
$msg_count, $rec_count);

sub separate {
        $x = STDOUT;
        $x = OUTPUT if $detailed;
        printf($x "%-40s\t\t%5s%9s\n", " ", "Msgs", "Recips");
}


