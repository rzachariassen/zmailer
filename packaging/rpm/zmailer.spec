#
# Thu May 11 23:09:06 CEST 2000
#

%define name zmailer
%define version 2.99.53pre1
%define release 3

Summary: Mailer for extreme performance demands, secure mail delivery agent.
Name: %{name}
Version: %{version}
Release: %{release}
Copyright: Freely usable, see /usr/doc/%{name}-%{version}/README
Group: System Environment/Daemons
Provides: smtpdaemon
Packager: Xose Vazquez <xose@wanadoo.es>
URL: http://www.zmailer.org
Source0: ftp://ftp.funet.fi/pub/unix/mail/zmailer/src/%{name}-%{version}.tar.gz
Source1: zmailer.init
Source2: zmailer.logrotate
Source3: zmailer.cron
Source4: zmailer.pam
Source5: README-RPM
BuildRoot: /var/tmp/%{name}-%{version}-root
Prereq: /sbin/chkconfig
Conflicts: sendmail qmail postfix smail exim

%description
This is a package that implements an internet message transfer agent
called ZMailer.  It is intended for gateways or mail servers or other
large site environments that have extreme demands on the abilities of
the mailer.  It was motivated by the problems of the Sendmail design
in such situations. ZMailer is one of the mailers able to deal with
huge quantities of mail and is more efficient any other mailer, qmail
included, mostly due to its excellent queueing algorithms.

Most users don't need this package -- for most users, sendmail or exim 
or smail will suffice.

%package doc
Summary: Documentation about the Zmailer Mail Transport Agent program.
Group: Documentation

%description doc
The zmailer-doc package contains documentation about the Zmailer
Mail Transport Agent (MTA) program, including desing notes, 
the ZMailer manual, and a few papers written about ZMailer.
The papers are available in PostScript, tex, html, txt and sgml.

Install the zmailer-doc package if you need documentation about
Zmailer.

Get the latest version of the Zmailer Manual from the zmailer web.

%prep
# unpack zmalier (and patch it).
%setup -q 

# build zmailer
%build
CFLAGS="$RPM_OPT_FLAGS" \
	./configure --prefix=/usr/lib/zmailer \
	--libdir=/usr/lib \
	--includedir=/usr/include/zmailer \
	--with-zconfig=/etc/zmailer/zmailer.conf \
	--with-mailbox=/var/spool/mail \
	--with-postoffice=/var/spool/postoffice \
	--with-mailshare=/etc/zmailer \
	--with-mailvar=/etc/zmailer \
	--with-mailbin=/usr/lib/zmailer \
	--with-logdir=/var/log/zmailer \
        --with-sendmailpath=/usr/sbin/sendmail \
        --with-rmailpath=/usr/bin/rmail \
        --with-system-malloc \
	--with-ta-mmap
# do you need ssl ?
#	--with-openssl-include=/usr/include/openssl \
#	--with-openssl-lib=/usr/lib \
#
# and ldap ?
#	--with-ldap-include-dir=/usr/local/include \
#	--with-ldap-library-dir=/usr/local/lib

# Do you have SMP ?
if [ -x /usr/bin/getconf ] ; then
	NRPROC=$(/usr/bin/getconf _NPROCESSORS_ONLN)
		if [ $NRPROC -eq 0 ] ; then
			NRPROC=1
		fi
else
	NRPROC=1
fi

make -j $NRPROC

%install
#rm -rf $RPM_BUILD_ROOT
make install prefix=$RPM_BUILD_ROOT

# install man pages
make MANDIR=$RPM_BUILD_ROOT/usr/man -C man install

# make install man do not create a man3 dir
rm -rf $RPM_BUILD_ROOT/usr/man/man3
mkdir -p $RPM_BUILD_ROOT/usr/man/man3
install -m644 $RPM_BUILD_DIR/zmailer-%{version}/man/*.3 \
        $RPM_BUILD_ROOT/usr/man/man3

# doc stuff
install -m644 $RPM_SOURCE_DIR/README-RPM \
	$RPM_BUILD_DIR/zmailer-%{version}

# ps man pages
mkdir -p $RPM_BUILD_DIR/zmailer-%{version}/man-ps
install -m644 $RPM_BUILD_DIR/zmailer-%{version}/man/*.ps \
	$RPM_BUILD_DIR/zmailer-%{version}/man-ps

# strip only binary files
strip `file $RPM_BUILD_ROOT/usr/lib/zmailer/* | awk -F':' '/not stripped/ { print $1 }'`
strip `file $RPM_BUILD_ROOT/usr/lib/zmailer/ta/* | awk -F':' '/not stripped/ { print $1 }'`

# install SYSV init stuff
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 $RPM_SOURCE_DIR/zmailer.init \
        $RPM_BUILD_ROOT/etc/rc.d/init.d/zmailer

for I in 0 1 6; do
	mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc$I.d
        ln -sf ../init.d/zmailer \
		$RPM_BUILD_ROOT/etc/rc.d/rc$I.d/K30zmailer
done
for I in 2 3 4 5; do
	mkdir -p $RPM_BUILD_ROOT/etc/rc.d/rc$I.d
        ln -sf ../init.d/zmailer \
		$RPM_BUILD_ROOT/etc/rc.d/rc$I.d/S80zmailer 
done

touch $RPM_BUILD_ROOT/etc/mail.conf

# install log rotation stuff
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
install -m644 $RPM_SOURCE_DIR/zmailer.logrotate \
	$RPM_BUILD_ROOT/etc/logrotate.d/zmailer

# install cron stuff
mkdir -p $RPM_BUILD_ROOT/etc/cron.d/
install -m644 $RPM_SOURCE_DIR/zmailer.cron \
	 $RPM_BUILD_ROOT/etc/cron.d/zmailer

# install pam support
mkdir -p $RPM_BUILD_ROOT/etc/pam.d
install -m644 $RPM_SOURCE_DIR/zmailer.pam \
	$RPM_BUILD_ROOT/etc/pam.d/smtpauth-login

# OBSOLETE, now we run post-install.sh, this is the BEST ?
# post-install.sh break the %files and when you make
#  rpm -i(after rpm -e) or -U show errors

# config files
#
#for I in aliases fqdnaliases localnames routes smtp-policy.relay \
#	smtp-policy.src ; do 
#ln -sf proto/$I \
#	$RPM_BUILD_ROOT/etc/zmailer/db/$I
#done
#
#for I in scheduler.conf sm.conf smtpserver.conf ; do
#ln -sf proto/$I \
#	$RPM_BUILD_ROOT/etc/zmailer/$I
#done 

#mv $RPM_BUILD_ROOT/etc/zmailer/cf/proto/* \
#	$RPM_BUILD_ROOT/etc/zmailer/cf/
#ln -sf cf/TELE-FI.cf \
#	$RPM_BUILD_ROOT/etc/zmailer/router.cf

# zmailer control script in the PATH is more coooooool :-)
ln -sf ../lib/zmailer/zmailer $RPM_BUILD_ROOT/usr/sbin/zmailer

# sendmail compatible stuff
ln -sf zmailer/sendmail $RPM_BUILD_ROOT/usr/lib/sendmail
ln -sf ../lib/zmailer/sendmail $RPM_BUILD_ROOT/usr/sbin/sendmail
ln -sf ../lib/zmailer/rmail $RPM_BUILD_ROOT/usr/bin/rmail

for I in mailq newaliases vacation; do
	ln -sf ../lib/zmailer/$I \
	$RPM_BUILD_ROOT/usr/bin/$I
done

%pre
# ####################
# pre-install section

# is zmailer running ?
if ps auxw | egrep 'router|scheduler|smtpserver' | grep -v egrep \
	>> /dev/null ; then
	/usr/lib/zmailer/zmailer kill
	echo "1" > /var/run/.zmailer_was_run
fi

%post
# #####################
# post-install section

# get source zmailer configuration.
. /etc/zmailer/zmailer.conf

/sbin/chkconfig --add zmailer

# mail.conf stuff
if ( [ -s /etc/mail.conf ] && grep -c '^hostname' /etc/mail.conf ) >> /dev/null ; then
	:
else
#	mv -f /etc/mail.conf /etc/mail.conf.rpmsave
	echo "# Where am I?" > /etc/mail.conf
	[ -z "`hostname -d`" ] || echo "orgdomain=`hostname -d`" >> /etc/mail.conf
	echo "# Who am I?" >> /etc/mail.conf
	[ -z "`hostname -d`" ] || echo "mydomain=`hostname -d`" >> /etc/mail.conf
	echo "# Who do I claim to be?" >> /etc/mail.conf
	[ -z "`hostname -f`" ] || echo "hostname=`hostname -f`" >> /etc/mail.conf
fi

# make zmailer group
if grep -c "^zmailer:" /etc/group >> /dev/null ; then
        :
else
        # Use 'mail' group for zmailer...
        echo "zmailer::12:root,daemon,uucp" >> /etc/group
fi

# port to mailer transport queue
if grep -c "^mailq" /etc/services >> /dev/null ; then
        :
else
        echo "mailq           174/tcp                         # Mailer transport queue" >> /etc/services
fi

# post-install.sh break the %files and when you make
# rpm -i or -U zmailer, you get a pile of errors.
# I don't know if the best solution is run post-install.sh
# or made by hand like in "config files"
echo " "
$MAILBIN/post-install.sh -OLDSTYLE

echo "localhost" > /etc/zmailer/db/localnames
echo "`hostname -f`" >> /etc/zmailer/db/localnames
echo "`hostname`" >> /etc/zmailer/db/localnames
echo "`hostname -d`" >> /etc/zmailer/db/localnames
echo "localhost.`hostname -d`" >> /etc/zmailer/db/localnames

(cd /etc/ && ln -sf zmailer/db/aliases .)

# rebuild the zmailer aliases database
$MAILBIN/newaliases
# recreates the FQDN alias map
$MAILBIN/newfqdnaliases

# notices
echo " "  
echo "     If you are running PROCMAIL as your local delivery agent"
echo "     read /usr/doc/zmailer-doc-%{version}/doc/guides/procmail "
echo " "
echo "     Read the /usr/doc/zmailer-%{version}/README-RPM file."
echo " "
echo "     If you need docs, install the zmailer-doc-%{version} file"
echo " "
echo "     Visit the www.zmailer.org site to get a new version of"
echo "     the Zmailer Manual and take a look to the news"
echo " "
echo "     A mailing list is avaliable at nic.funet.fi"
echo " "

# Yes, it was running. Startup zmailer again
if [ -s /var/run/.zmailer_was_run ] >> /dev/null ; then
        /etc/rc.d/init.d/zmailer start
        rm -f /var/run/.zmailer_was_run
fi

%preun
# ######################
# pre-uninstall section

# stop zmailer if it is running
if ps auxw | egrep 'router|scheduler|smtpserver' | grep -v egrep \
        >> /dev/null ; then
        /usr/lib/zmailer/zmailer kill
fi

# delete the pid files
for i in scheduler smtpserver router ; do
	if [ -f /var/spool/postoffice/.pid.$i ] ; then
		rm -f /var/spool/postoffice/.pid.$i
	fi
done

/sbin/chkconfig --del zmailer

%postun
# ######################
# post-uninstall section

echo " "
echo "     Look at /var/log/zmailer/ to delete the zmailer logs,"
echo "     /var/spool/postoffice/ where are the zmailer big work"
echo "     dirs and /etc/zmailer where are the config files"
echo " "

%clean
#rm -rf $RPM_BUILD_ROOT
#rm -rf /usr/src/redhat/BUILD/zmailer-%{version}

%changelog

* Sat Apr 1 2000 Xose Vazquez <xose@wanadoo.es>

- New version for Zmailer-2.99.53, too many changes.

* Wed Oct 13 1999 Xose Vazquez <xose@ctv.es>

- Zmailer-2.99.52 install strip bin files, wonderful.
- delete the strip section.

* Fri Aug 6  1999 Xose Vazquez <xose@ctv.es>

- split zmailer, the doc is a independent rpm

* Thu Jul 29 1999 Xose Vazquez <xose@ctv.es>

- based on zmailer-%{version}/contrib/zmailer49.spec
- this is the first version, is all ok ?


%files
%defattr(-,root,root)

#/etc/aliases
/etc/mail.conf

%attr(644,root,root)/etc/pam.d/smtpauth-login
%config %attr(755,root,root) /etc/cron.d/zmailer
%config /etc/logrotate.d/zmailer
%config /etc/rc.d/init.d/zmailer
%config(missingok) /etc/rc.d/rc0.d/K30zmailer
%config(missingok) /etc/rc.d/rc1.d/K30zmailer
%config(missingok) /etc/rc.d/rc2.d/S80zmailer
%config(missingok) /etc/rc.d/rc3.d/S80zmailer
%config(missingok) /etc/rc.d/rc4.d/S80zmailer
%config(missingok) /etc/rc.d/rc5.d/S80zmailer
%config(missingok) /etc/rc.d/rc6.d/K30zmailer
%config(noreplace) /etc/zmailer/cf/*
%config(noreplace) /etc/zmailer/db/*
/etc/zmailer/forms
/etc/zmailer/fqlists
/etc/zmailer/lists
%config(noreplace) /etc/zmailer/proto/*

#%config(noreplace) /etc/zmailer/router.cf
#%config(noreplace) /etc/zmailer/scheduler.conf
#%config(noreplace) /etc/zmailer/sm.conf
#%config(noreplace) /etc/zmailer/smtpserver.conf

%config /etc/zmailer/vacation.msg
%config /etc/zmailer/zmailer.conf
/usr/bin/*

#/usr/include/zmailer/zmailer.h
#/usr/lib/libzmailer.a

/usr/lib/sendmail
/usr/lib/zmailer
/usr/man/*/*
/usr/sbin/*

%dir /var/log/zmailer
%attr(2755,root,root) %dir /var/spool/postoffice/
%attr(700,root,root) /var/spool/postoffice/TLSclntcache/
%attr(700,root,root) /var/spool/postoffice/TLSsrvrcache/
%attr(750,root,root) /var/spool/postoffice/deferred/
%attr(750,root,root) /var/spool/postoffice/freezer/
%attr(750,root,root) /var/spool/postoffice/postman/
%attr(1777,root,root) /var/spool/postoffice/public/
%attr(750,root,root) %dir /var/spool/postoffice/queue/
%attr(755,root,root)  /var/spool/postoffice/queue/*
%attr(1777,root,root) /var/spool/postoffice/router/
%attr(755,root,root) /var/spool/postoffice/transport/

%doc ChangeLog INSTALL MANIFEST Overview README* TODO contrib/README.debian

#doc package files
%files doc
%doc doc/* man-ps

# EOF
