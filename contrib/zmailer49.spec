Summary: High performance, secure mail delivery agent
Name: zmailer
Version: 2.99.49p9
Release: 1
Source: ftp://ftp.funet.fi/pub/unix/mail/zmailer/zmailer-2.99.49p9.tar.gz
Patch: zmailer-initscript.patch
Copyright: GPL
Group: Daemons
Provides: smtpdaemon
#BuildRoot: /tmp/zmailer-root
%description
This is a package that implements an internet message transfer agent
called ZMailer. It is intended for gateways or mail servers or other large
site environments that have extreme demands on the abilities of the
mailer. It was motivated by the problems of the Sendmail design in such
situations.

%prep
%setup -n zmailer-2.99.49p9
%patch -p1

%build
CFLAGS="-O2" ./configure --prefix=/usr \
	--with-mailbox=/var/spool/mail \
	--with-logdir=/var/log/mail \
	--with-zconfig=/etc/zmailer/zmailer.conf \
	--with-mailshare=/etc/zmailer \
	--with-tcp-wrappers=/usr \
	--with-system-malloc \
	--with-sendmailpath=/usr/sbin/sendmail \
	--with-rmailpath=/usr/sbin/rmail \
	--with-mailbin=/usr/sbin \
	--with-mailshare=/usr/etc/zmailer \
	--with-mailvar=/etc/zmailer \
	--with-postoffice=/var/spool/postoffice \
	--with-ta-mmap
make

%install
make install

strip /usr/sbin/mailrm \
	/usr/sbin/newaliases \
	/usr/sbin/newfqdnaliases \
	/usr/sbin/zmailer \
	/usr/sbin/rmail \
	/usr/sbin/sendmail \
	/usr/sbin/router \
	/usr/sbin/mailq \
	/usr/sbin/scheduler \
	/usr/sbin/smtpserver \
	/usr/sbin/ta/errormail \
	/usr/sbin/ta/mailbox \
	/usr/sbin/ta/hold \
	/usr/sbin/ta/sm \
	/usr/sbin/ta/smtp \
	/usr/sbin/mprobe \
	/usr/sbin/makendbm \
	/usr/sbin/ndbmlook \
	/usr/sbin/vacation.sh \
	/usr/sbin/vacation \
	/usr/sbin/vacation.exe || :

make -C man install
ln -sf zmailer/db/aliases /etc/aliases
mv /etc/zmailer/db/localnames /etc/zmailer/db/localnames-dist
echo "localhost" > /etc/zmailer/db/localnames
ln -sf ../sbin/sendmail /usr/lib/sendmail
mkdir -p /var/log/mail
ln -s cf/SMTP+UUCP.cf /usr/etc/zmailer/router.cf

cat > /etc/mail.conf <<EOF
# Where am I?
#orgdomain=domain
# Who am I?
#hostname=host.subdomain.$orgdomain
# Who do I claim to be?
#mydomain=subdomain.$orgdomain
EOF
install -m755 utils/zmailer.init.sh /etc/rc.d/init.d/zmailer.init
for I in 0 1 6; do
	ln -sf ../init.d/zmailer.init /etc/rc.d/rc$I.d/K20zmailer
done
for I in 2 3 5; do
	ln -sf ../init.d/zmailer.init /etc/rc.d/rc$I.d/S80zmailer
done
. /etc/zmailer/zmailer.conf
cat << EOF > /etc/cron.daily/zmailer.cleanup
#!/bin/sh
. /etc/zmailer/zmailer.conf
$MAILBIN/zmailer cleanup
EOF
cat << EOF > /etc/cron.daily/zmailer.resubmit
#!/bin/sh
. /etc/zmailer/zmailer.conf
$MAILBIN/zmailer resubmit
EOF
chmod 755 /etc/cron.daily/zmailer.cleanup /etc/cron.daily/zmailer.resubmit

%post
if grep -c "^hostname=" /etc/mail.conf; then
	:
else
	[ -z "`hostname -d`" ] || echo "orgdomain=`hostname -d`" >> /etc/mail.conf
	[ -z "`hostname -d`" ] || echo "mydomain=`hostname -d`" >> /etc/mail.conf
	[ -z "`hostname -f`" ] || echo "hostname=`hostname -f`" >> /etc/mail.conf
fi
if grep -c "^zmailer:" /etc/group; then
	:
else
	# Use 'mail' group for zmailer...
	echo "zmailer::12:root,daemon,uucp" >> /etc/group
fi
if grep -c "^mailq " /etc/services; then
	:
else
	echo "mailq       174/tcp	# Mailer transport queue" >> /etc/services
fi
/usr/sbin/newaliases
/usr/sbin/newfqdnaliases
echo "`hostname -f`" >> /etc/zmailer/db/localnames
echo "`hostname`" >> /etc/zmailer/db/localnames
echo "`hostname -d`" >> /etc/zmailer/db/localnames
echo "localhost.`hostname -d`" >> /etc/zmailer/db/localnames
if [ "$1" != 1 ]; then
	# Start it back up again, after an upgrade
	/etc/rc.d/init.d/zmailer.init start
fi

%preun
/etc/rc.d/init.d/zmailer.init stop

%files
/usr/sbin/mailrm
/usr/sbin/newaliases
/usr/sbin/newfqdnaliases
/usr/sbin/zmailer
/usr/sbin/rmail
/usr/sbin/sendmail
/usr/sbin/router
/usr/sbin/mailq
/usr/sbin/scheduler
/usr/sbin/smtpserver
/usr/sbin/mprobe
/usr/sbin/makendbm
/usr/sbin/ndbmlook
/usr/sbin/vacation.sh
/usr/sbin/vacation
/usr/sbin/vacation.exe
%dir /usr/sbin/ta
/usr/sbin/ta/errormail
/usr/sbin/ta/mailbox
/usr/sbin/ta/hold
/usr/sbin/ta/sm
/usr/sbin/ta/smtp
/usr/lib/sendmail
/usr/lib/libzmailer.a
/usr/include/zmailer.h
/usr/man/man8/errormail.8
/usr/man/man8/hold.8
/usr/man/man3/zmailer.3
/usr/man/man8/mailbox.8
/usr/man/man1/mailq.1
/usr/man/man1/mailrm.1
/usr/man/man1/newaliases.1
/usr/man/man1/rmail.1
/usr/man/man1/vacation.1
/usr/man/man8/router.8
/usr/man/man8/scheduler.8
/usr/man/man8/sendmail.8
/usr/man/man8/sm.8
/usr/man/man8/smtp.8
/usr/man/man8/smtpserver.8
/usr/man/man1/ssl.1
/usr/man/man1/zmailer.1
/usr/man/man1/zmsh.1
%dir /etc/zmailer
%config /etc/zmailer/zmailer.conf
%dir /etc/zmailer/lists
%dir /etc/zmailer/db
%config /etc/zmailer/db/*
/etc/aliases
%dir /var/log/mail
/var/spool/postoffice
%dir /var/spool/mail
%dir /usr/etc/zmailer
%config /usr/etc/zmailer/router.cf
%config /usr/etc/zmailer/scheduler.conf
%config /usr/etc/zmailer/sm.conf
%config /usr/etc/zmailer/vacation.msg
%dir /usr/etc/zmailer/forms
%config /usr/etc/zmailer/forms/*
%dir /usr/etc/zmailer/cf
%config /usr/etc/zmailer/cf/*
%doc BUGS ChangeLog INSTALL README* Overview doc
%config /etc/mail.conf
%config /etc/cron.daily/zmailer.cleanup
%config /etc/cron.daily/zmailer.resubmit
%config /etc/rc.d/init.d/zmailer.init
/etc/rc.d/rc0.d/K20zmailer
/etc/rc.d/rc1.d/K20zmailer
/etc/rc.d/rc6.d/K20zmailer
/etc/rc.d/rc2.d/S80zmailer
/etc/rc.d/rc3.d/S80zmailer
/etc/rc.d/rc5.d/S80zmailer
