#!/usr/bin/perl

################ extra "mailq -QQQQ" tracking parameters
################ to be output for system asking for the data
################ 
################ This was written one particular Sun SPARC Solaris
################ system in mind, where most traffic is at the special-
################ cased disk (a Fibre Channel storage box), and
################ a bit more generic set is summation of about 30
################ kernel parameters.

################ By Matti Aarnio <mea@nic.funet.fi>

##########
########## Enable this usage by adding  ZENV  variable pointing
########## to theinstallation location of this script:
##########    SCHEDULER_M_EXTRA=
##########

open KSTAT, '-|', "/usr/bin/kstat -p" || die "POPEN of 'kstat -p' failed!  $!";

#sd:30:sd30:nread        89243253248
#sd:30:sd30:nwritten     11337490944
#sd:30:sd30:reads        3115833
#sd:30:sd30:writes       957377

my $n, $l;

%cpustat = ();

while (<KSTAT>) {
	chomp;
	split(/\t/);

	$n = $_[0];
	$v = $_[1];

	#printf "'%s'\t\t'%s'\n",$n,$v;

	SWITCH: {
		if ($n eq 'sd:30:sd30:nread') {
			printf "SYS.SOLARIS.disk.sd30.nread      %s\n", $v;
			last SWITCH;
		}
		if ($n eq 'sd:30:sd30:reads') {
			printf "SYS.SOLARIS.disk.sd30.reads      %s\n", $v;
			last SWITCH;
		}
		if ($n eq 'sd:30:sd30:nwritten') {
			printf "SYS.SOLARIS.disk.sd30.nwritten   %s\n", $v;
			last SWITCH;
		}
		if ($n eq 'sd:30:sd30:writes') {
			printf "SYS.SOLARIS.disk.sd30.writes     %s\n", $v;
			last SWITCH;
		}

	$_ = $n;

		if (m/^cpu_stat:.:cpu_stat.:(bawrite)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(bread)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(bwrite)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(fspgin)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(fspgout)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(idle)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(idlethread)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(intr)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(intrblk)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(intrthread)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(inv_swtch)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(kernel)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(lread)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(lwrite)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(maj_fault)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(mutex_adenters)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(namei)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(nthreads)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(outch)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgfrec)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgin)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgout)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgpgin)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgpgout)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgrec)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgrrun)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgswapin)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pgswapout)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(phread)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(phwrite)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(physio)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(procovf)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(prot_fault)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(pswitch)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(readch)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(rw_rdfails)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(rw_wrfails)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(softlock)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(syscall)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(sysexec)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(sysfork)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(sysread)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(sysvfork)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(syswrite)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(trap)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(ufsdirblk)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(ufsiget)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(user)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(wait)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(wait_io)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(wait_pio)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(wait_swap)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(writech)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(xcalls)$/o) {
			$cpustat{$1} += $v;
			last SWITCH;
		}
		if (m/^cpu_stat:.:cpu_stat.:(zfod)$/o) {
			$cpustat{$1} += $v;

			#printf "n='%s'     v='%s'     \$1='%s'\n",$n,$v,$1;

			last SWITCH;
		}

	}
}
close(KSTAT);


foreach my $key (keys %cpustat) {
	printf "SYS.SOLARIS.cpustat.%-10s  %10d\n", $key, $cpustat{$key};
}

exit 0;

