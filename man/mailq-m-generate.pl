#! /usr/bin/perl

#
# Script to generate the mailq-m  man-page from source material embedded in
# scheduler/mailq.inc  file
#

#use strict; no strict "subs";
use integer;
use Fcntl;
use IO::Handle;
use POSIX;
use Carp;


$fn = $ARGV[0];

# PERL 5.6+ syntax... 
open SRCFILE, "<",$fn || die "Can't open file: $fn; $!";



SRCFILE->autoflush(0);
my $oldinsep = $/;
$/ = undef; # Slurp everything into one long line
my $srcdata = SRCFILE->getline;
$/ = $oldinsep; # Restore the separator

close SRCFILE;


print '.\" t
.\" THIS FILE IS GENERATED WITH  mailq-m-generate.pl  FROM  mailq.inc
.ds ]W "ZMailer 2.99"
.nr X
';

printf ".TH MAILQ-M 5 \"%s\"\n", strftime("%Y-%b-%d",localtime());

print '.SH NAME
"mailq \-M" \- output format description
.SH SYNOPSIS
Lots of odd variables and counters
.PP
These are generated from inline XMLishly tagged
descriptions in file
.I "scheduler/mailq.inc" 
.SH DESCRIPTION
';

for (;;) {
    if ($srcdata =~ m{.*?<VAR>(.*?)</VAR>(.*)$}s) {
	my $thisvar = $1;
	$srcdata = $2;

	if ($thisvar =~ m{\s*<NAME>\s*(.*)\s*</NAME>\s*<DESC>\s*(.*)\s*</DESC>\s*}s) {
	    printf ".IP \"%s\"\n", $1;
	    printf ".RS\n";
	    my $l = $2; chomp $l;chomp $l;chomp $l;
	    printf "%s\n",$l;
	    printf ".RE\n";
	} elsif ($thisvar =~ m{\s*<HEAD>\s*(.*)\S*</HEAD>\s*<DESC>\s*(.*)\s*</DESC>\s*}) {
	    my $l = $1; chomp $l;chomp $l;chomp $l;
	    printf ".SS \"%s\"\n",$l;
	    my $l = $2; chomp $l;chomp $l;chomp $l;
	    printf "%s\n",$l;
        }
    } else {
	last; ## No more vars ...
    }
}




print '.SH SEE ALSO
.IR mailq (1),
.PP
.SH AUTHOR
This document authored and copyright by:
.RS 3em
Matti Aarnio <mea@nic.funet.fi>
.RE
';

exit 0;

