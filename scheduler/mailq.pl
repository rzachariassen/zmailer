#!/usr/bin/perl
#
# PERL module for connecting to ZMailer scheduler's MAILQ port
#

package ZMailer::MAILQ;

use integer;
use strict;
use IO::Handle '_IOLBF';
use IO::Socket;
use MD5;

use Getopt::Std;

%main::opts = {};
$main::Q = undef;

getopt('Q:',\%main::opts);
if ($main::opts{'Q'}) {
    $main::Q = $main::opts{'Q'};
}

local($main::s);

$main::s = & ZMailer::MAILQ::new('127.0.0.1','174');

$main::s->setdebug(1);
 
#if (!defined $main::s) {
#    printf("ZMailer::MAILQ::new() yielded UNDEF\n");
#} else {
#    printf("ZMailer::MAILQ::new() yielded connection, salt='%s'\n", $main::s->{salt});
#}

$main::s->login("nobody","nobody");

#printf("login responce: '%s'\n",$main::s->{resp});


local($main::rc,@main::rc) = $main::s->showcmd("SHOW QUEUE THREADS");
printf "SHOW QUEUE THREADS:\n%s\n",join("\n",@main::rc);

#local($main::rc,@main::rc) = $main::s->showcmd("SHOW SNMP");
#printf "SHOW SNMP:\n%s\n",join("\n",@main::rc);

#local($main::rc,@main::rc) = $main::s->etrncmd("ETRN mea.tmt.tele.fi");
#printf "ETRN mea.tmt.tele.fi:\n%s\n",join("\n",@main::rc);

$main::s->bye();

exit 0;

# --------------------  ZMailer::MAILQ::  -----------------------

sub new {
    my($host,$port) = @_;
    my($sock,$in,$out);

    $sock = IO::Socket::INET->new(PeerAddr => $host,
				  PeerPort => $port,
				  Proto    => 'tcp');
    $in  = new IO::Handle->fdopen($sock,"r");
    $out = new IO::Handle->fdopen($sock,"w");
    $sock->close(); undef $sock;

    my($self);
    $self = {
	in   => $in,
	out  => $out,
	seq  => 0,
	salt => '',
    };
    bless $self;

    my $line = $self->{in}->getline();
    chomp $line;

    # printf("input line: '%s'\n",$line);

    if ($line ne 'version zmailer 2.0') {
	printf "Not ZMailer mailq version 2.0 server!\n";
	undef $self;
	return undef;
    }

    my $line = $self->{in}->getline();
    chomp $line;

    $self->{salt} = $line;

    return $self;
}

sub setdebug {
    my $self = shift;
    my ($val) = @_;

    if ($val != 0) {
	$self->{debug} = 1;
    } else {
	undef $self->{debug};
    }
};

#sub DESTROY {
#    my $self = shift;
#    undef $self->{in};
#    undef $self->{out};
#    undef $self;
#};

sub sendcmd {
    my $self = shift;
    my ($cmd) = @_;
    my $line;

    $line = sprintf("%s\r\n",$cmd);
    if (defined $self->{debug}) {
	printf "sendcmd() cmd='%s'\n",$cmd;
    }
    $self->{out}->write($line,length($line));
    $self->{out}->flush();
    $line = $self->{in}->getline();
    chomp $line;
    $self->{resp} = $line;
    if (defined $self->{debug}) {
	printf "sendcmd() resp='%s'\n",$line;
    }
    return (substr($line,0,1) , substr($line,1));
};

sub login {
    my $self = shift;
    my($user,$pass) = @_;

    my $auth = MD5->hexhash($self->{salt} . $pass);
    my $cmd = sprintf('AUTH %s %s', $user, $auth);
    return $self->sendcmd($cmd);
}

sub bye {
    my $self = shift;

    my $cmd = "QUIT";
    return $self->sendcmd($cmd);
}

sub showcmd {
    #
    # Show-cmds return either an error ($rc = "-") or
    # a multiline response.
    # We collect here that multiline stuff.
    #
    my $self = shift;
    my ($rc,$rest) = $self->sendcmd(@_);

    if ($rc eq '-') { return ($rc); }

    my (@lines) = ();
    while (1) {
	my $line = $self->{in}->getline();
	chomp $line;

	printf("showcmd() line='%s'\n",$line) if (defined $self->{debug});

	if ($line ne '.') {
	    $line = substr($line,1) if (substr($line,0,2) eq '..');
	    push(@lines,$line);
	} else {
	    last;
	}
    }
    return ('+', @lines);
}

sub etrncmd {
    #
    # ETRN-cmds return a single-line response.
    #
    my $self = shift;
    return $self->sendcmd(@_);
}

1;
