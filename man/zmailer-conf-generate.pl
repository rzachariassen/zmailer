#! /usr/bin/perl

#
# Script to generate the zmailer.conf.5  man-page from source material
# embedded in   SiteConfig   file
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

$srcdata = '';
while (<SRCFILE>) {
    $_ =~ s/^(#|\s)+//go;
    $srcdata .= $_;
}

close SRCFILE;


print '\'\" t
.\" THIS FILE IS GENERATED WITH  zmailer-conf-generate.pl  FROM  SiteConfig
.ds ]W "ZMailer 2.99"
.nr X
';

printf ".TH ZMAILER.CONF 5zm \"%s\"\n", strftime("%Y-%b-%d",localtime());

print '.SH NAME
zmailer.conf  \-  file format
.SH SYNOPSIS
These are generated from inline XMLishly tagged
descriptions in generated file:
.IR "SiteConfig" .
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
	    next;
	}
	if ($thisvar =~ m{\s*<HEAD>\s*(.*)\s*</HEAD>\s*<DESC>\s*(.*?)\s*</DESC>\s*}s) {
	    my $l = $1; chomp $l;chomp $l;chomp $l;
	    printf ".SH \"%s\"\n",$l;
	    my $l = $2; chomp $l;chomp $l;chomp $l;
	    printf "%s\n",$l;
	    next;
        } elsif ($thisvar =~ m{\s*<DESC>\s*(.*)\s*</DESC>\s*}s) {
	    my $l = $1; chomp $l;chomp $l;chomp $l;
	    printf "%s\n",$l;
        }
    } else {
	last; ## No more vars ...
    }
}




print '.SH SEE ALSO
.IR zmailer (1zm),
.PP
.SH AUTHOR
This document authored and copyright by:
.RS 3em
Matti Aarnio <mea@nic.funet.fi>
.RE
';

exit 0;
