#!/usr/bin/perl
#
#  Combines various   /etc/passwd  files from multiple hosts, and
#  also  /net/kontu/disk0/admin/kayttajat  data into complete
#  all encompassing database for mailer.
#

#
# Order of host names in following data is important.
# Kontu is handled separately.
#
# Host LATER in list overrides whatever hosts before have defined.
#
@HOSTS = (`uname -n`);
@FILES = ();
$PWFILE="PWFILE";

%uid2emailu = ();
%uid2email = ();
%email2uid = ();
%realname2email = ();

umask 0177;
chdir "/opt/mail/db";

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
{
	local($dummy,$REALNAMES,$UID2EMAIL,$EMAIL2UID)=(0,1,2,3);
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
	system("sort passwd.realnames > fullnames");
	system("/p/mail/bin/makedb ndbm fullnames fullnames");
	system("sort passwd.uid2email > fullname-uids");
}
exit(0);


#
# Generic parser routines
#
sub parse_kayttajat {
  # Return an @array of elts much in password style:
  # First_names:Last_name:kontu_uname:kontu_group:unix_uname:unix_group:rest

	local ($fn) = $_[0];
	local ($INPFILE);
	local ($retval);
	open($INPFILE,"< $fn");
	local ($line);
	while ($line = <$INPFILE>) {
		chop($line);
		local($lastname,@namepart)=split(' ',substr($line,0,31));
		local($vmsuser)=substr($line,31,12);
		local($unixuser)=substr($line,44,8);
		local($vmsgroup)=substr($line,53,9);
		local($unixgroup)=substr($line,62,8);
		local($rest)=substr($line,79);
		$lastname  =~ s/,//;
		$vmsuser   =~ s/ //g;
		$vmsgroup  =~ s/ //g;
		$unixuser  =~ s/ //g;
		$unixgroup =~ s/ //g;
		$rest      =~ s/ //g;
		local($kayttajat)="$lastname:@namepart:$vmsuser:$vmsgroup:$unixuser:$unixgroup:$rest";
		@kayttajat=(@kayttajat,$retval);
	}
	close($INPFILE);
}

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
