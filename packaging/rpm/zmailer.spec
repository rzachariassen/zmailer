#
# Mon Apr 19 23:52:42 CEST 2001
#

%define name zmailer
%define version 2.99.55
%define release 4

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
Conflicts: sendmail postfix qmail exim smail
NoSource: 0

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
./configure --prefix=/usr \
	--with-zconfig=/etc/zmailer/zmailer.conf \
	--mandir=/usr/man \
	--libdir=/usr/lib \
	--includedir=/usr/include/zmailer \
	--with-mailbox=/var/spool/mail \
	--with-postoffice=/var/spool/postoffice \
	--with-mailshare=/etc/zmailer \
	--with-mailvar=/etc/zmailer \
	--with-mailbin=/usr/lib/zmailer \
	--with-logdir=/var/log/zmailer \
        --with-sendmailpath=/usr/sbin/sendmail \
        --with-rmailpath=/usr/bin/rmail \
	--with-vacationpath=/usr/bin/vacation \
        --with-system-malloc \
	--with-ta-mmap

# do you need ssl ?
#	--with-openssl \
#	--with-openssl-prefix=/usr \
#	--with-openssl-include=/usr/include/openssl \
#	--with-openssl-lib=/usr/lib \
#
# ldap ?
#	--with-ldap-prefix=/usr \
#	--with-ldap-include-dir=/usr/include/ldap \
#	--with-ldap-library-dir=/usr/lib \
#
# IPv6 ?
#	--with-ipv6 \
#
# whoson ?
#	--with-whoson \
#
# and yp/nis ?
#	--with-yp \
#	--with-yp-lib=/usr/lib \
#
# look ./configure --help and doc/guides/configure for more options

make
make -C man groff
make -C man html

%install
rm -rf $RPM_BUILD_ROOT
make install prefix=$RPM_BUILD_ROOT

# install man pages
make MANDIR=$RPM_BUILD_ROOT/usr/man -C man install

# doc stuff
install -m644 $RPM_SOURCE_DIR/README-RPM \
	$RPM_BUILD_DIR/zmailer-%{version}

# ps and html man pages
for i in ps html ; do
mkdir -p $RPM_BUILD_DIR/zmailer-%{version}/man-$i
install -m644 $RPM_BUILD_DIR/zmailer-%{version}/man/*.$i \
	$RPM_BUILD_DIR/zmailer-%{version}/man-$i
done

# install SYSV init stuff
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 $RPM_SOURCE_DIR/zmailer.init \
        $RPM_BUILD_ROOT/etc/rc.d/init.d/zmailer

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

# change zmailer.h file, --includedir= in zmailer don't work ok
if ! [ -f $RPM_BUILD_ROOT/usr/include/zmailer/zmailer.h ]  ; then
	mkdir -p $RPM_BUILD_ROOT/usr/include/zmailer
	install -m644 $RPM_BUILD_ROOT/usr/include/zmailer.h \
	  $RPM_BUILD_ROOT/usr/include/zmailer/zmailer.h
fi
	
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

touch $RPM_BUILD_ROOT/etc/mail.conf

%pre
# ####################
# pre-install section

# get source zmailer configuration.
if [ -f /etc/zmailer/zmailer.conf ] ; then
        . /etc/zmailer/zmailer.conf
fi

# Source function library.
. /etc/rc.d/init.d/functions

# is zmailer running ?

if ( status scheduler || status router || status smtpserver ) | grep -v stop 2> /dev/null ; then
	if [ -f $MAILBIN/zmailer ] ; then
		$MAILBIN/zmailer kill
		$MAILBIN/zmailer bootclean
	else 
		for i in scheduler router smtpserver ; do 
		killproc $i > /dev/null
		rm -rf /var/spool/postoffice/.pid.* 2> /dev/null
		done
	fi
	echo "running" > /var/run/.zmailer_was_run
fi

# make zmailer group

if ! grep -q "^zmailer:" /etc/group ; then
        # Use 'mail' group for zmailer...
        echo "zmailer:x:12:root,daemon,uucp" >> /etc/group
fi

%post
# #####################
# post-install section

# put SYSV init stuff
/sbin/chkconfig --add zmailer

# get source zmailer configuration.
. /etc/zmailer/zmailer.conf

# mail.conf stuff
if ! ( [ -s /etc/mail.conf ] && grep -c '^hostname' /etc/mail.conf ) > /dev/null ; then
	echo "# Where am I?" > /etc/mail.conf
	[ -z "`hostname -d`" ] || echo "orgdomain=`hostname -d`" >> /etc/mail.conf
	echo "# Who am I?" >> /etc/mail.conf
	[ -z "`hostname -d`" ] || echo "mydomain=`hostname -d`" >> /etc/mail.conf
	echo "# Who do I claim to be?" >> /etc/mail.conf
	[ -z "`hostname -f`" ] || echo "hostname=`hostname -f`" >> /etc/mail.conf
fi

ln -sf /etc/mail.conf /etc/zmailer/mail.conf

# port to mailer transport queue
if ! grep -q "^mailq" /etc/services > /dev/null ; then
        echo "mailq           174/tcp                         # Mailer transport queue" >> /etc/services
fi

(cd /etc/ && ln -sf zmailer/db/aliases .)

# run post-install script
# rebuild the zmailer aliases database, recreates the FQDN alias map,
# smtp-policy-db builder, create the postoffice dir ....... and more.
$MAILBIN/post-install -OLDSTYLE

# SECURITY NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# plain text passwd !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
chown root:root /etc/zmailer/scheduler.auth
chmod 600 /etc/zmailer/scheduler.auth

if ! ( [ -f /etc/zmailer/db/localnames ] && \
        grep -c "^localhost" /etc/zmailer/db/localnames ) > /dev/null ; then
        echo "localhost" >> /etc/zmailer/db/localnames
        echo "`hostname -f`" >> /etc/zmailer/db/localnames
        echo "`hostname`" >> /etc/zmailer/db/localnames
        echo "`hostname -d`" >> /etc/zmailer/db/localnames
        echo "localhost.`hostname -d`" >> /etc/zmailer/db/localnames
fi

$MAILBIN/zmailer newdb > /dev/null
$MAILBIN/policy-builder.sh -n > /dev/null

# notices
echo " "  
echo "       If you are running PROCMAIL as your local delivery agent"
echo "       read /usr/doc/zmailer-doc-%{version}/doc/guides/procmail."
echo "       If you need docs, install the zmailer-doc-%{version}."
echo "       Visit the www.zmailer.org site to get a new version of"
echo "       the Zmailer Manual and take a look to the news."
echo "       A mailing list is avaliable at zmailer@nic.funet.fi"
echo "       Use <mailserver@nic.funet.fi> to subscribe yourself to"
echo "       the list by sending it a message with body content:"
echo "                subscribe zmailer Your Name"
echo " "

# Yes, it was running. Startup zmailer again
if [ -s /var/run/.zmailer_was_run ] > /dev/null ; then
        /etc/rc.d/init.d/zmailer start
fi
rm -f /var/run/.zmailer_was_run

%preun
# ######################
# pre-uninstall section

# get source zmailer configuration.
. /etc/zmailer/zmailer.conf

# stop zmailer if it is running
if ( /etc/rc.d/init.d/zmailer status | grep -v stop ) > /dev/null ; then
        $MAILBIN/zmailer kill
	$MAILBIN/zmailer bootclean
fi

# delete SYSV init stuff
/sbin/chkconfig --del zmailer

# delete zmailer group
groupdel zmailer || : #"WARNING: failed to remove group zmailer"

%postun
# ######################
# post-uninstall section

echo " "
echo "     Look at /var/log/zmailer to delete the zmailer logs,"
echo "     /var/spool/postoffice where are the zmailer big work"
echo "     dirs and /etc/zmailer where are the config files."
echo "     Look for the zmailer group in /etc/group and delete it."
echo " "

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/zmailer-%{version}

%changelog

* Mon Apr 16 2001 Xose Vazquez <xose@wanadoo.es>

- minor changes for Zmailer-2.99.55
- bugs in Zmailer-2.99.55 :
- --includedir= in configure don't work
- /etc/mail.conf don't work, made a link to /etc/zmailer/mail.conf
- make -j x, it is like linux kernel ;-) , broken

* Fri Feb 23 2001 Xose Vazquez <xose@wanadoo.es>

- new version for Zmailer-2.99.55

* Sat Dec 16 2000 Xose Vazquez <xose@wanadoo.es>

- minor changes for Zmailer-2.99.54patch1

* Sat Dec 2 2000 Xose Vazquez <xose@wanadoo.es>

- new version for Zmailer-2.99.54

* Wed Jul 19 2000 Xose Vazquez <xose@wanadoo.es>

- new version for Zmailer-2.99.53

* Fri Jun 30 2000 Xose Vazquez <xose@wanadoo.es>

- minor changes

* Sat Apr 1 2000 Xose Vazquez <xose@wanadoo.es>

- new version for Zmailer-2.99.53pre1, too many changes.

* Wed Oct 13 1999 Xose Vazquez <xose@ctv.es>

- Zmailer-2.99.52 install strip bin files, wonderful.
- delete the strip section.

* Fri Aug 6  1999 Xose Vazquez <xose@ctv.es>

- split zmailer, the doc is an independent rpm

* Thu Jul 29 1999 Xose Vazquez <xose@ctv.es>

- based on zmailer-%{version}/contrib/zmailer49.spec
- this is the first version, is all ok ?

# ##################
# package files

%files
%defattr(-,root,root)

/etc/mail.conf

/etc/pam.d/smtpauth-login
/etc/cron.d/zmailer
/etc/logrotate.d/zmailer
/etc/rc.d/init.d/zmailer

%config(missingok) /etc/zmailer/cf/proto/*
%config(missingok) /etc/zmailer/db/proto/*
%config(missingok) /etc/zmailer/forms/proto/*
%dir /etc/zmailer/fqlists
%dir /etc/zmailer/lists
%config(missingok) /etc/zmailer/proto/*
/etc/zmailer/vacation.msg
/etc/zmailer/zmailer.conf

/usr/bin/mailq
/usr/bin/newaliases
/usr/bin/rmail
/usr/bin/vacation

/usr/include/zmailer/zmailer.h

/usr/lib/libzmailer.a
/usr/lib/sendmail
/usr/lib/zmailer

/usr/man

/usr/sbin/sendmail
/usr/sbin/zmailer

%dir /var/log/zmailer
%attr(2755,root,root) %dir /var/spool/postoffice

%doc ChangeLog INSTALL MANIFEST Overview README* TODO contrib/README.debian

# ##################
# doc package files

%files doc
%doc doc/* man-ps man-html

# EOF
