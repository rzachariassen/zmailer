#! /usr/bin/perl

# CPAN module: Net-DNS-0.12
use Net::DNS;

$res = new Net::DNS::Resolver;

$IP = $ARGV[0];
if (!defined($IP)) {
    printf "rbl-check.pl: IP.ADDRESS.TO.LOOKUP\n";
    exit(64);
}

printf "Net::DNS version: %s; IP = %s\n", Net::DNS->version, $IP;

$revIP = $IP;
$revIP =~ s/^([0-9]*)\.([0-9]*)\.([0-9]*)\.([0-9]*)$/\4.\3.\2.\1/;

printf "IP = %s\n", $IP;

@ZONES = ('.rbl.maps.vix.com', '.dul.maps.vix.com',
	  '.ok.orbs.org',      '.relays.orbs.org',
	  '.rss.mail-abuse.net');

foreach $zone (@ZONES) {
    printf "query zone: '%s'\n", $revIP.$zone;

    $query = $res->query($revIP . $zone, "A");
    next unless (defined $query);
    foreach $rr ($query->answer) {
	$rr->print;
    }
    $query = $res->query($revIP . $zone, "TXT");
    next unless (defined $query);
    foreach $rr ($query->answer) {
	$rr->print;
    }
}

1;
