#!/usr/bin/perl

# Original email accompanying letter at the end
# THIS REQUIRES SOME EDITING, AND IS INTENTIONALLY RENDERED INOPERABLE!
# YOU NEED TO EDIT FOLLOWING ITEMS:

# you MUST change the hostname below
$proxyhost = "www-cache.utu.fi";
# you probably must change the port number.  3128 is the default for squid.
$proxyport = 80;

# you probably must change this directory too
$zmailerdir = "/opt/mail";

# Who is using this.
$fromaddr = "postmaster\@utu.fi";


# Written by Arnt Gulbrandsen <agulbra@troll.no> and copyright 1996 Troll
# Tech AS, Postboks 6133 Etterstad, 0602 Oslo, Norway, fax +47 22646949.
#
# Use, modification and distribution is allowed without limitation,
# warranty, or liability of any kind.

# This script requires perl 5.


use FileHandle;
use Socket;

($j, $j, $proto) = getprotobyname("tcp");

($name, $j, $j, $j, $hisaddr) = gethostbyname($proxyhost);
if ($name eq "") {
    die "can't find address for web proxy\n";
}

# you probably must change the port number.  3128 is the default for squid.
$squid = pack('S n a4 x8', &AF_INET, $proxyport, $hisaddr);


sub urlget {
    local( $_, $/ );
    my( $url ) = @_;

    $_ = $url;

    undef $/;

    $SIG{'ALRM'} = \&timeout;
    alarm( 20 );
    if (!(socket(SOCKET, &AF_INET, &SOCK_STREAM, $proto))) {
	print "couldn't create socket\n";
    } elsif (!connect(SOCKET, $squid)) {
	die "connection to $_ failed (for $url): $!\n";
    } else {
	my ( $head, $body );
	alarm(0);
	SOCKET->autoflush(1);
	print SOCKET "GET $url HTTP/1.0\r\nFrom: $fromaddr\r\n\r\n";
	$head = <SOCKET>;
	$head =~ s/\r+\n/\n/gs;

	$body = $head;
	$head =~ s/\n+\n.*/\n/s;
	$body =~ s/.*?\n\n//s;

	if ( $head =~ /^\S+\s+200\s+/s ) {
	    undef %relocated;
	    return $body;
	} elsif ( $head =~ /^\S+\s+30[12]\s+/ &&
		 $head =~ /\nLocation:\s*(http:.*?)\n/s ) {
	    $_ = $1;
	    if ( defined($relocated{$url}) ) {
		print STDERR "looping redirect for $url (to $_)\n";
		return undef;
	    }
	    $relocated{$url} = $_;
	    print STDERR "redirect to $_ for $url\n",
	    return &urlget( $_ );
	} elsif ( $head =~ /^\S+\s+304\s+/ ) {
	    print STDERR $url, " not modified\n";
	    return undef;
	} else {
	    print $url, "\n", $head;
	    return undef;
	}
    }
}


undef $/;

#$_ = &urlget( "http://www.idot.aol.com/preferredmail/" ) ||
#    die "can't open PreferredMail list, stopped";
#
#s/^.*<multicol.*?>//si;
#s-</multicol.*$--si;
#
#foreach $domain ( split( /\s+/, $_ ) ) {
#    $reason{lc $domain} .= " PreferredMail";
#}

$_ = &urlget( "http://www.webeasy.com:8080/spam/spam_download_table" ) ||
    die "can't open webeasy list, stopped";

s/@(\S+)/@\L$1\E/gs;
s-^@--s;
s-\n@-\n-gs;

foreach $domain ( split( /\s+/, $_ ) ) {
    $reason{$domain} .= " Webeasy";
}


if ( open( O, "> $zmailerdir/db/smtp-policy.spam" ) ) {
    foreach ( sort keys %reason ) {
	if ( /^([-a-z0-9]+\.)+[a-z]{2,3}$/ ) {
	    print O  "\043", $reason{$_},
	             ":\n.$_ = _bulk_mail\n";
	} elsif ( /^\S+@([-a-z0-9]+\.)+[a-z]{2,3}$/ ) {
	    print O "\043", $reason{$_},
	             ":\n$_ = _bulk_mail\n";
	}
    }
}


#From:	Arnt Gulbrandsen <agulbra@troll.no>
#To:	Matti Aarnio <mea@nic.funet.fi>
#Cc:	zmailer@nic.funet.fi
#Subject: Re: DSN bug
#Date:	21 Oct 1997 00:21:57 +0200
#
#Matti Aarnio <mea@nic.funet.fi>
#> /Matti Aarnio -- in process of doing 2.99.49p8 release.
#
#Cool.  Could you perhaps put this little ditty in contrib?  It needs
#perl and some trivial changes to policy-builder.sh, so I don't think
#it should be in the default setup.
#
#It's a script to read four spam databases, combine them, and write the
#result in a format zmailer can accept.
#
#--Arnt (who made sure that there was no more unread zmailer mail this time)
