Summary: Mailer for extreme performance demands, secure mail delivery agent
Name: zmailer
Version: 2.99.52
Release: 1
Group: Networking/Daemons
Packager: Matti Aarnio <mea@nic.funet.fi>
URL: http://www.zmailer.org 
Source: ftp://ftp.funet.fi/pub/unix/mail/zmailer/src/zmailer-%{version}.tar.gz
Source1: zmailer.init
Source2: zmailer.logrotate
Source3: zmailer.cron
Source4: zmailer.pam
Source5: README-RPM
License: Freely usable, see /usr/doc/zmailer-%{version}/README
BuildRoot: /var/tmp/zmailer-%{version}-root
Prereq: /sbin/chkconfig
Provides: smtpdaemon
Conflicts: sendmail qmail

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
Summary: ZMailer documentation. 
Group: Networking/Daemons

%description doc
This package includes desing notes, the ZMailer manual, and a few
papers written about ZMailer. The papers are available in PostScript,
tex, html, txt and sgml.

%prep
# unpack zmailer (and patch it).
%setup -q 

# build zmailer
%build
CFLAGS="$RPM_OPT_FLAGS" \
	./configure --prefix=/opt/zmailer \
	--libdir=/usr/lib \
	--includedir=/usr/include/zmailer \
	--with-zconfig=/opt/zmailer/zmailer.conf \
	--with-mailbox=/var/spool/mail \
        --with-postoffice=/var/postoffice \
	--with-logdir=/var/log/mail \
        --with-sendmailpath=/usr/sbin/sendmail \
        --with-rmailpath=/usr/sbin/rmail \
        --with-system-malloc \
	--with-tcp-wrappers \
	--with-ta-mmap 
make

%install
rm -rf $RPM_BUILD_ROOT
make install prefix=$RPM_BUILD_ROOT

# install man pages
make MANDIR=$RPM_BUILD_ROOT/usr/man -C man install

## make install do not install authuser.3 
##install -m644 $RPM_BUILD_DIR/zmailer-%{version}/man/authuser.3 \
##        $RPM_BUILD_ROOT/usr/man/man3

install -m644 $RPM_SOURCE_DIR/README-RPM \
	$RPM_BUILD_DIR/zmailer-%{version}

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

# install log rotation stuff
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
install -m644 $RPM_SOURCE_DIR/zmailer.logrotate \
	$RPM_BUILD_ROOT/etc/logrotate.d/zmailer

# install cron stuff
mkdir -p $RPM_BUILD_ROOT/etc/cron.daily/
install -m644 $RPM_SOURCE_DIR/zmailer.cron \
	 $RPM_BUILD_ROOT/etc/cron.daily/zmailer

# install pam support
mkdir -p $RPM_BUILD_ROOT/etc/pam.d
install -m644 $RPM_SOURCE_DIR/zmailer.pam \
	$RPM_BUILD_ROOT/etc/pam.d/smtpauth-login

#|# sendmail compatible stuff
#|ln -sf /opt/zmailer/bin/sendmail $RPM_BUILD_ROOT/usr/lib/sendmail
#|
#|for I in rmail sendmail; do
#|ln -sf ../lib/zmailer/$I $RPM_BUILD_ROOT/usr/sbin/$I
#|done
#|
#|mkdir -p $RPM_BUILD_ROOT/usr/bin/
#|for I in mailq newaliases vacation; do
#|ln -sf ../lib/zmailer/$I \
#|	$RPM_BUILD_ROOT/usr/bin/$I
#|done

%preun
# stop zmailer if it is running
if ps auxw | egrep 'router|scheduler|smtpserver' | grep -v egrep \
	>> /dev/null ; then
        /usr/lib/zmailer/zmailer kill
	echo "1" > /var/run/.zmailer_was_run
fi

%post
/sbin/chkconfig --add zmailer

MAILBIN=/opt/zmailer/bin
echo "localhost" >> /opt/zmailer/db/localnames

# mail.conf stuff
if [ -s /opt/zmailer/mail.conf ] >> /dev/null ; then
	:
else
	touch /opt/zmailer/mail.conf
fi
if grep -c -v '^#' /opt/zmailer/mail.conf >> /dev/null ; then
        :
else
        [ -z "`hostname -d`" ] || echo "orgdomain=`hostname -d`" >> /opt/zmailer/mail.conf
        [ -z "`hostname -d`" ] || echo "mydomain=`hostname -d`" >> /opt/zmailer/mail.conf
        [ -z "`hostname -f`" ] || echo "hostname=`hostname -f`" >> /opt/zmailer/mail.conf
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
        echo "mailq		174/tcp			# Mailer transport queue" >> /etc/services
fi

# rebuild the zmailer aliases database
$MAILBIN/newaliases

# recreates the FQDN alias map
$MAILBIN/newfqdnaliases

echo "`hostname -f`" >> /opt/zmailer/db/proto/localnames
echo "`hostname`" >> /opt/zmailer/db/proto/localnames
echo "`hostname -d`" >> /opt/zmailer/db/proto/localnames
echo "localhost.`hostname -d`" >> /opt/zmailer/db/proto/localnames

# start it back up again, after an upgrade
if [ -s /var/run/.zmailer_was_run ] >> /dev/null ; then
        /etc/rc.d/init.d/zmailer start
        rm -f /var/run/.zmailer_was_run
fi

# notices
echo " "  
echo "     If you are running PROCMAIL as your local delivery agent"
echo "     read /usr/doc/zmailer-doc-%{version}/doc/guides/procmail "
echo " "
echo "     This zmailer.spec links tcp wrapper code into scheduler."
echo "     To allow the mailq command to work you must specify allowed"
echo "     ip-addresses domains in /etc/hosts.allow file."
echo "     Read the README-RPM file. "
echo " " 


%clean
# rm -rf $RPM_BUILD_ROOT

%changelog

* Sun Mar  5 2000 Matti Aarnio <mea@nic.funet.fi>

- Adapting this RPM specs file for  vger.redhat.com

* Wed Oct 13 1999 Xose Vazquez <xose@ctv.es>

-  Zmailer-2.99.52 install strip bin files, wonderful.
-  delete the strip section.

* Fri Aug 6  1999 Xose Vazquez <xose@ctv.es>

-  split zmailer, the doc is a independent rpm

* Thu Jul 29 1999 Xose Vazquez <xose@ctv.es>

-  based on zmailer-%{version}/contrib/zmailer49.spec
-  this is the first version, is all ok ?


%files
%defattr(-,root,root)
/etc/aliases
%attr(644,root,root)/etc/pam.d/smtpauth-login
%config %attr(755,root,root) /etc/cron.daily/zmailer
%config /etc/logrotate.d/zmailer
%config /etc/rc.d/init.d/zmailer
%config(missingok) /etc/rc.d/rc0.d/K30zmailer
%config(missingok) /etc/rc.d/rc1.d/K30zmailer
%config(missingok) /etc/rc.d/rc2.d/S80zmailer
%config(missingok) /etc/rc.d/rc3.d/S80zmailer
%config(missingok) /etc/rc.d/rc4.d/S80zmailer
%config(missingok) /etc/rc.d/rc5.d/S80zmailer
%config(missingok) /etc/rc.d/rc6.d/K30zmailer
%config(noreplace) /opt/zmailer/cf/*
%config(noreplace) /opt/zmailer/db/*
/opt/zmailer/forms
/opt/zmailer/fqlists
/opt/zmailer/lists
%config(noreplace) /opt/zmailer/proto/*
%config(noreplace) /opt/zmailer/router.cf
%config(noreplace) /opt/zmailer/scheduler.conf
%config(noreplace) /opt/zmailer/sm.conf
%config(noreplace) /opt/zmailer/smtpserver.conf
%config /opt/zmailer/vacation.msg
%config /opt/zmailer/zmailer.conf
/usr/bin/*
/usr/include/zmailer/zmailer.h
/usr/lib/libzmailer.a
/usr/lib/sendmail
/usr/lib/zmailer
# man pages
/usr/man/*/*
/usr/sbin/*
%dir /var/log/mail
%attr(2755,root,root) %dir /var/spool/postoffice/
%attr(750,root,root) /var/spool/postoffice/deferred/
%attr(750,root,root) /var/spool/postoffice/freezer/
%attr(750,root,root) /var/spool/postoffice/postman/
%attr(1777,root,root) /var/spool/postoffice/public/
%attr(750,root,root) %dir /var/spool/postoffice/queue/
%attr(755,root,root)  /var/spool/postoffice/queue/*
%attr(1777,root,root) /var/spool/postoffice/router/
%attr(755,root,root) /var/spool/postoffice/transport/
%doc  ChangeLog INSTALL MANIFEST Overview README* TODO contrib/README.debian README-RPM

%files doc
%doc doc

# EOF
