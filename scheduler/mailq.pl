#!/usr/bin/perl
#
# PERL module for connecting to ZMailer scheduler's MAILQ port
#

package ZMailer::MAILQ;

use integer;
#use strict;
use IO::Handle '_IOLBF';
use IO::Socket;
use MD5;

%main::opts = {};
$main::Q = undef;
$main::chan = '';
$main::host = '';

& ZMailer::MAILQ::getopts('vQU:K:',\%main::opts);

$main::opts{'Q'} = 'undef' if (!defined $main::opts{'Q'});

# printf "Option v: %s\n",$main::opts{'v'};
# printf "Option Q: %s\n",$main::opts{'Q'};

local($main::s);

$main::host = $ARGV[0];
$main::host = '127.0.0.1' unless (defined $main::host);

$main::s = & ZMailer::MAILQ::new($main::host,'174');

# $main::s->setdebug(1);

if (defined $main::opts{'U'}) {
    local($user,$passwd) = split(/[\/:,]/, $main::opts{'U'});
    $main::s->login($user,$passwd);
} else {
    $main::s->login("nobody","nobody");
}

if ($main::s->{resp} =~ m/^-/) {
    printf("login responce: '%s'\n",$main::s->{resp});
}

if ($main::opts{'K'} ne '') {
    local($main::rc,@main::rc) = $main::s->sendcmd("KILL MSG " . $main::opts{'K'});
    printf "%s\n",join("\n",@main::rc);
    exit 0;
} elsif ($main::opts{'Q'} == 3) {
    local($main::rc,@main::rc) = $main::s->showcmd("SHOW SNMP");
    $main::s->bye();
    printf "SHOW SNMP:\n%s\n",join("\n",@main::rc);
    exit 0;
} elsif ($main::opts{'Q'} == 2) {
    local($main::rc,@main::rc) = $main::s->showcmd("SHOW QUEUE SHORT");
    $main::s->bye();
    printf "SHOW QUEUE SHORT:\n%s\n",join("\n",@main::rc);
    exit 0;
} elsif ($main::opts{'Q'} == 1) {
    local($main::rc,@main::rc) = $main::s->showcmd("SHOW QUEUE THREADS");
    $main::s->bye();
    printf "SHOW QUEUE THREADS:\n%s\n",join("\n",@main::rc);
    exit 0;
}

local($main::rc,@main::rc) = $main::s->showcmd("SHOW QUEUE THREADS");
# printf "SHOW QUEUE THREADS: rc=%s\n",$main::rc;
foreach $main::l (@main::rc) {
    # printf("%s\n",$main::l);
    if ($main::l =~ m/^    /o) {
	local(@main::rc2);
	($main::chan,$main::host,$main::rc) = split('/',$main::l);
	$main::chan =~ s/[ \t]+//g;
	($main::rc,@main::rc2) = $main::s->showcmd("SHOW THREAD ${main::chan} ${main::host}");
	# printf("SHOW THREAD ${main::chan} ${main::host}\n\t%s\n",
	#         join("\n\t",@main::rc2));

	printf "%s/%s:\n",$main::chan,$main::host;
	foreach $main::ll (@main::rc2) {
	    & mqprintv2($main::ll, $main::opts{'v'});
	}
    }
}


#local($main::rc,@main::rc) = $main::s->etrncmd("ETRN mea.tmt.tele.fi");
#printf "ETRN mea.tmt.tele.fi:\n%s\n",join("\n",@main::rc);

$main::s->bye();

exit 0;

sub mqprintv2 {
    local($ll, $vv) = @_;

    local(@ll) = split("\t",$ll);

# Fields are:
#
#     SHOW THREAD channel host
#              Reports details usable to implement  mailq-v1  like
#              interface.  The details are TAB separated fields in
#              a line until an LF.  Fields are:
#
#                 0) filepath under $POSTOFFICE/transport/
#                 1) error address in brackets
#                 2) recipient line offset within the control file
#                 3) message expiry time (time_t)
#                 4) next wakeup time (time_t)
#                 5) last feed time (time_t)
#                 6) count of attempts at the delivery
#                 7) "retry in NNN" or a pending on "channel"/"thread"
#                 8) possible diagnostic message from previous delivery attempt
#

    printf "\t%s: diag: %s\n", $ll[0], $ll[8];

}


# --------------------  ZMailer::MAILQ::  -----------------------

sub getopts {
    local($argumentative, $hash) = @_;
    local(@args,$_,$first,$rest);
    local($errs) = 0;
    local @EXPORT;

    @args = split( / */, $argumentative );
    while(@ARGV && ($_ = $ARGV[0]) =~ /^-(.)(.*)/) {
        ($first,$rest) = ($1,$2);
        $pos = index($argumentative,$first);
        if($pos >= 0) {
            if(defined($args[$pos+1]) and ($args[$pos+1] eq ':')) {
                shift(@ARGV);
                if($rest eq '') {
                    ++$errs unless @ARGV;
                    $rest = shift(@ARGV);
                }
		$$hash{$first} = $rest;
            } else {
		$$hash{$first} += 1;

                if($rest eq '') {
                    shift(@ARGV);
                }
                else {
                    $ARGV[0] = "-$rest";
                }
            }
        }
        else {
            warn "Unknown option: $first\n";
            ++$errs;
            if($rest ne '') {
                $ARGV[0] = "-$rest";
            }
            else {
                shift(@ARGV);
            }
        }
    }
    $errs == 0;
}



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
