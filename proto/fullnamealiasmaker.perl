#
#	This utility is provided as a sample implementation
#	without any guarantees of its fitness to your uses.
#
#	Originally for utu.fi, and then butchered for  nic.funet.fi
#

#!/usr/local/bin/perl
#
#  Combines various   /etc/passwd  files from multiple hosts, 
#  into complete all encompassing database for mailer.
#

#
# Order of host names in following data is important.
#
# Host LATER in list overrides whatever hosts before have defined.
#
@HOSTS = ("nic");
@FILES = ();

%uid2emailu = ();
%uid2email = ();
%email2uid = ();
%realname2email = ();

umask 0177;
chdir "/etc";

{
	if (open($PWFILE,"< passwd")) {
#printf("Opened  passwd.$host  $polaris\n");
	    local($line,@pwd,@realnames,$realname);
	    while($line = <$PWFILE>) {
		next if $line =~ /^#/;
		@pwd = split(/:/,$line);
		# $pwd[0]  is userid
		# $pwd[4]  is real.name
		@realnames = & gen_realnames($pwd[4]);
		local($uu) = "$pwd[0]";
#printf("Real names for user $pwd[0]: ".join('/',@realnames)."\n");
		$uid2emailu{$pwd[0]} = $uu;
		$uid2email{$pwd[0]} = $uu;
		$email2uid{$uu} = $pwd[0];
		for $realname (@realnames) {
			$realname2email{$realname} = $uu;
		}
	    }
	    close($PWFILE);
	}
}
{
	local($dummy,$REALNAMES,$UID2EMAIL,$EMAIL2UID);
	local($key,$value);
	unlink("passwd.email2uid");
	open($EMAIL2UID,"> passwd.email2uid");
	while(($key,$value) = each %email2uid) {
		printf $EMAIL2UID "$key\t\t$value\n";
	}
	unlink("passwd.uid2email");
	open($UID2EMAIL,"> passwd.uid2email");
	while(($key,$value) = each %uid2email) {
		printf $UID2EMAIL "$key\t\t$value\n";
	}
	unlink("passwd.realnames");
	open($REALNAMES,"> passwd.realnames") || die "can't open passwd.realnames";
	select($REALNAMES);
	while(($key,$value) = each %realname2email) {
		printf "$key\t\t$value\n"
			unless ($key eq '' || $key =~ /^-/ || !($key =~ /\./));
	}

	close($REALNAMES);
	close($EMAIL2UID);
	close($UID2EMAIL);
	umask 022;
	system("sort passwd.realnames >/p/lib/mail/db/fullnames.nic");
	system("/p/lib/mail/bin/makedb /etc/fullnames /etc/fullnames");
	system("sort passwd.uid2email >/p/lib/mail/db/fullname-uids.nic");
}
exit(0);


#
# Generic parser routines
#

sub gen_realnames {
#	@realnames = & gen_realnames("$pwd[1] $pwd[0]");
	local(@realnames) = ();
	local($realname) = $_[0];
	local($scandname);
	local(@rn,@srn) = split(/[,\/><]/,$realname);
	$realname = $rn[0];		# Chop off extra comments
	$realname =~ tr/A-]/a-}/;	# All lowercase, including scandic names!
	$realname =~ s/\.//g;		# Chop off '.'sss
	$scandname = $realname;
	$realname =~ tr/{}|/aao/;	# Turn scandic name to its "stripped" version
	
	@rn = split(' ',$realname);	# Yield components of name
	@srn = split(' ',$scandname);	# Yield components of name
	if ($realname ne $scandname) {
	    # Scandic version is different, yield permutations
	    if ($#srn >= 2) {
		@realnames =(@realnames,join('.',@srn));
		@realnames =(@realnames,join('.',$srn[0],$srn[$#srn]));
		@realnames =(@realnames,join('.',$srn[0],$srn[1],$srn[$#srn]));
		@realnames =(@realnames,join('.',$srn[0],substr($srn[1],0,1),$srn[$#srn]));
	    } else {
	    	@realnames =(@realnames,join('.',@srn));
	    }
	}
	if ($#rn >= 2) {
	    @realnames =(@realnames,join('.',@rn));
	    @realnames =(@realnames,join('.',$rn[0],$rn[$#rn]));
	    @realnames =(@realnames,join('.',$rn[0],$rn[1],$rn[$#rn]));
	    @realnames =(@realnames,join('.',$rn[0],substr($rn[1],0,1),$rn[$#rn]));
	} else {
	    @realnames =(@realnames,join('.',@rn));
	}
	return @realnames;
}
