#!/usr/bin/perl

####  A tool to convert STATUS LOG file reference data
####  into  spoolids.

$T = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123abcdefghijklmnopqrstuvwxyz4567890-=';

sub taspoolid {
    my ($mtime, $inodenum) = @_;
    my (@tt) = gmtime($mtime);
    $tt[5] += 1900;
    my($sp) =
	'S' .
	sprintf("%ld", $inodenum) .
	substr($T, ($tt[5] >> 12) & 63,  1) . # YEAR
	substr($T, ($tt[5] >>  6) & 63,  1) .
	substr($T, ($tt[5]      ) & 63,  1) .
	substr($T, $tt[4],   1) .  # MON
	substr($T, $tt[3]-1, 1) .  # MDAY
	substr($T, $tt[2],   1) .  # HOUR
	substr($T, $tt[1],   1) .  # MIN
	substr($T, $tt[0],   1);   # SEC
    return ($sp);
}


while (<>) {
    chomp;
    if (m/^S/o) { printf "%s\n", $_; next; }
    @l = split(' ',$_);
    $m = shift @l;
    $i = shift @l;
    printf("%s %s\n", taspoolid($m, $i+0), join(' ',@l));
}

1;

