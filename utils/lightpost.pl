From mea@nic.funet.fi Thu Dec 12 16:52:22 1996
Received: from nic.funet.fi ([128.214.248.6]) by mea.tmt.tele.fi with ESMTP id <231475-115>; Thu, 12 Dec 1996 16:52:13 +0200
Received: by nic.funet.fi id <65253-28416>; Thu, 12 Dec 1996 16:51:28 +0200
Received: from antares.utu.fi ([130.232.1.2]) by nic.funet.fi with ESMTP id <68304-17185>; Fri, 8 Nov 1996 09:35:43 +0200
Received: by utu.fi id <30933-1151>; Fri, 8 Nov 1996 09:35:23 +0200
Subject: ZMailer message submission in PERL..
From:	Matti Aarnio <mea@utu.fi>
To:	zmailer@nic.funet.fi
Date:	Fri, 8 Nov 1996 09:35:23 +0200 (EET)
X-Mailer: ELM [version 2.4 PL25]
MIME-Version: 1.0
Content-Type:	text/plain; charset=US-ASCII
Content-Transfer-Encoding: 7BIT
Message-Id: <96Nov8.093523+0200_eet.30933-1151+358@utu.fi>
Sender: mea@nic.funet.fi
Return-Path: <mea@nic.funet.fi>
Content-Length:  2423
Status: RO

I asked for a PERL-version of the posting, and this I got back.
In commentary letter Janne Edelman said (in finnish) about:

"This reads in from stdin, and sends to all addresses given as
 parameters.  Even though this sends all messages individually,
 it would be trivial to use more envelope 'to '-lines.  Should
 add sometimes.

 The input text must have RFC822 headers in it.

 ... and of course I could have answered directly to the person
 originating the question, but I am a bit tired at this late at
 night..."

I THINK this needs Perl5, though I am not sure.

/Matti Aarnio


#!/usr/bin/perl
#
#  LightPost for ZMailer
#  Version 0.1
#  Copyright (c) 1996 Janne Edelman
#  You may copy and use this piece of software under GPL
#
#####
#
#  Usage: lightpost [-t] email@address [ email@address ... ] < file
#
#  File must contain full headers with From, To, Subject, etc.
#  This script does NOT check the file at any way.
#
#  This script only adds the envelope at the begining of outgoing email
#  and allows mass postings with the same content.
#
#  With -t option the To header is changed to same as given email address
#
#####

if( ! -r '/etc/zmailer.conf') {
  die "Can't open zmailer.conf\n";
}

open(ZMAILER,'</etc/zmailer.conf');
while(<ZMAILER>) {
  chomp;
  split(/=/);
  $ZMAILER{$_[0]}=$_[1];
}
close ZMAILER;

require 'getopts.pl';
Getopts('t');

$part='header';

while(<STDIN>) {
  if($_ eq "\n") { $part='body' }
  push(@$part,$_);
}

foreach $hl ('Message-Id:','X-Mailer:','Cc:','Bcc:') {
  @header=strip_header($hl,@header);
}

if($opt_t) {
  @header=strip_header('To:',@header);
}

$outfile = $ZMAILER{'POSTOFFICE'} . "/public/lightpost.$$";
$time=time;
$hostname=`hostname`; chomp $hostname;
$domainname=`domainname`; chomp $domainname;
foreach $address (@ARGV) {
  $count++;
  open(OUT,">$outfile");
  select(OUT);
  print "to $address\n";
  print "env-end\n"; # added by [mea]
  if($opt_t) {
    print "To: $address\n";
  }
  print @header;
  print "Message-Id: <${time}.${count}.LP\@${hostname}.${domainname}>\n";
  print "X-Mailer: LightPost for Zmailer\n";
  print @body;
  select(STDOUT);
  close OUT;
  $inode=(stat($outfile))[1];
  $newfile=$ZMAILER{'POSTOFFICE'} . "/router/$inode";
  rename($outfile, $newfile);
}
print "$count messages send\n";
exit(0);

sub strip_header {
  return grep(!/^$_[0]/i, @_[1..$#_]);
}


	Janne K Edelman - PGP public key: finger edelman/pgp@tuug.utu.fi

