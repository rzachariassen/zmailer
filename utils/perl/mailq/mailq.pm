package ZMailer::mailq;

use 5.008;
use strict;
use warnings;

require Exporter;
use IO::Handle '_IOLBF';
use IO::Socket;
use Digest::MD5 qw(md5_hext);

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use ZMailer::mailq ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '1.00';

# --------------------  ZMailer::mailq::  -----------------------

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

    my $auth = md5_hex($self->{salt} . $pass);
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

	last if (length($line) == 0);

	chomp $line;

#	printf("showcmd() line='%s'\n",$line) if (defined $self->{debug});

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



# Preloaded methods go here.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

ZMailer::mailq - Perl extension for interaction with the scheduler

=head1 SYNOPSIS

  use ZMailer::mailq;

  # Connect to server
    $zmq = ZMailer::mailq::new('hostname','174');

  # Debug flag value
    ( $rc, $text ) = $zmq->setdebug(1);

  # Login to the scheduler server
    ( $rc, $text ) = $zmq->login('nobody','nobody');

  # Bye bye to the server
    ( $rc, $text ) = $zmq->bye();

  # Examples of SHOW commands: (see ZMailer's scheduler(8)
  # man-page about  "MAILQv2 PROTOCOL")
  ( $rc,@lines ) = $zmq->showcmd("SHOW SNMP");
  ( $rc,@lines ) = $zmq->showcmd("SHOW QUEUE SHORT");
  ( $rc,@lines ) = $zmq->showcmd("SHOW QUEUE THREADS");
  ( $rc,@lines ) = $zmq->showcmd("SHOW THREAD $channel $host");

=head1 ABSTRACT

  ZMailer scheduler's management protocol interface: 'mailq'.

=head1 DESCRIPTION

  This is part of ZMailer MTA software suite

  These routines can be used to build tools to monitor, and
  manage scheduler queue in ZMailer.

  The '$rc' value is '+' or '-' (ok/fail), and $text or @lines
  is the real response.

=head2 EXPORT

None by default.

=head1 SEE ALSO

ZMailer's  scheduler(8)

=head1 AUTHOR

Matti Aarnio, E<lt>mea@nic.funet.fiE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2003 by Matti Aarnio

This is part of ZMailer MTA software suite

=cut
