#
# Thu Sep 27 12:14:35 CEST 2001 <xose@wanadoo.es>
#

%define _Zsysconfdir	%{_sysconfdir}/zmailer
%define _Zincludedir	%{_includedir}/zmailer
%define _Zlibdir 	%{_libdir}/zmailer
%define _Zlogdir	%{_localstatedir}/log/zmailer
%define _Zmaildir	%{_localstatedir}/spool/mail
%define _Zpostoffdir	%{_localstatedir}/spool/postoffice

Summary: Mailer for extreme performance demands, secure mail delivery agent.
Summary(pt_BR): Mailer for extreme performance demands, secure mail delivery agent.
Summary(es): Mailer para demandas de rendimiento extremas, agente de entrega de correo seguro.
Name: zmailer
Version: 2.99.55
Release: 5
Copyright: Freely usable, see %{_defaultdocdir}/%{name}-%{version}/README
Group: System Environment/Daemons
Provides: smtpdaemon
Packager: Xose Vazquez <xose@wanadoo.es>
URL: http://www.zmailer.org
Source0: ftp://ftp.funet.fi/pub/unix/mail/zmailer/src/%{name}-%{version}.tar.gz
Source1: %{name}.init
Source2: %{name}.logrotate
Source3: %{name}.cron
Source4: %{name}.pam
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prereq: chkconfig
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

%description -l pt_BR
This is a package that implements an internet message transfer agent
called ZMailer.  It is intended for gateways or mail servers or other
large site environments that have extreme demands on the abilities of
the mailer.  It was motivated by the problems of the Sendmail design
in such situations. ZMailer is one of the mailers able to deal with
huge quantities of mail and is more efficient any other mailer, qmail
included, mostly due to its excellent queueing algorithms.
 
Most users don't need this package -- for most users, sendmail or exim
or smail will suffice.

%description -l es
Este paquete implementa un agente de tranferencia de mensajes llamado
Zmailer. Es apropiado para pasarelas de correo o servidores de correo
u otros grandes entornos que tienen demandas de correo extremas.
Su desarrollo fue motivado por los problemas de diseño de Sendmail en
estas situaciones. Zmailer es uno de los mailers capaces de gestionar
elevadas cantidades de correo y es mas eficiente que otros mailers,
qmail incluido, debido a sus excelentes algoritmos de cola.

La mayoria de usuarios no necesitan de este paquete -- a la mayoria,
les bastara sendmail o exim o smail.

%package doc
Summary: Documentation about the Zmailer Mail Transport Agent program.
Summary(pt_BR): Documentation about the Zmailer Mail Transport Agent program.
Summary(es): Documentacion sobre el programa Zmailer Mail Transport Agent.
Group: Documentation

%description doc
The %{name}-doc package contains documentation about the Zmailer
Mail Transport Agent (MTA) program, including desing notes, 
the ZMailer manual, and a few papers written about ZMailer.
The papers are available in PostScript, tex, html, txt and sgml.

Install the %{name}-doc package if you need documentation about
Zmailer.

Get the latest version of the Zmailer Manual from the zmailer web.

%description doc -l pt_BR
The %{name}-doc package contains documentation about the Zmailer
Mail Transport Agent (MTA) program, including desing notes, 
the ZMailer manual, and a few papers written about ZMailer.
The papers are available in PostScript, tex, html, txt and sgml.

Install the %{name}-doc package if you need documentation about
Zmailer.

Get the latest version of the Zmailer Manual from the zmailer web.

%description doc -l es
El paquete %{name}-doc contiene documentacion sobre el programa
Zmailer Mail Transport Agent (MTA), incluyendo notas de diseño,
el manual de Zmailer, y unos poco articulos sobre Zmailer. Los 
articulos estan disponibles en PostScript, tex, html, txt and sgml.

Instale el paquete %{name}-doc si necesita documentacion sobre
Zmailer.

Obtenga la ultima version del Manual de Zmailer de la web de zmailer.

%prep

# unpack (and patch it).
%setup -q 
#patch0 -p1 -b .orig

# rebuild configure to the autoconf of the system
autoconf

# build it
%build
CFLAGS="%{optflags}" \
./configure --prefix=%{_prefix} \
	--libdir=%{_libdir} \
	--includedir=%{_Zincludedir} \
	--with-zconfig=%{_Zsysconfdir}/zmailer.conf \
	--with-mailbox=%{_Zmaildir} \
	--with-postoffice=%{_Zpostoffdir} \
	--with-mailshare=%{_Zsysconfdir} \
	--with-mailvar=%{_Zsysconfdir} \
	--with-mailbin=%{_Zlibdir} \
	--with-logdir=%{_Zlogdir} \
	--with-sendmailpath=%{_sbindir}/sendmail \
	--with-vacationpath=%{_bindir}/vacation \
	--with-rmailpath=%{_bindir}/rmail \
	--mandir=%{_mandir} \
	--with-system-malloc \
	--with-ta-mmap \
# do you need SSL ?
#	--with-openssl \
# IPv6 ?
#	--with-ipv6 \
# LDAP ?
#	--with-ldap-library-dir= %{_lib} \
#	--with-ldap-include-dir= %{_includedir} \
# whoson ?
#	--with-whoson \
# and YP/NIS ?
#	--with-yp \
# look ./configure --help and doc/guides/configure for more options

make
make -C man groff
make -C man html

%install
rm -rf %{buildroot}
make install prefix=%{buildroot}

# install man pages, --mandir= don't work
make MANDIR=%{buildroot}%{_mandir} -C man install

# copy ps and html man pages
for i in ps html ; do
mkdir -p %{_builddir}/%{name}-%{version}/man-$i
install -m644 %{_builddir}/%{name}-%{version}/man/*.$i \
	%{_builddir}/%{name}-%{version}/man-$i
done

# install SYSV init stuff
mkdir -p %{buildroot}%{_initrddir}
install -m755 %{_sourcedir}/%{name}.init \
        %{buildroot}%{_initrddir}/%{name}

# install log rotation stuff
mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
install -m644 %{_sourcedir}/%{name}.logrotate \
	%{buildroot}%{_sysconfdir}/logrotate.d/%{name}

# install cron stuff
mkdir -p %{buildroot}%{_sysconfdir}/cron.d
install -m644 %{_sourcedir}/%{name}.cron \
	%{buildroot}%{_sysconfdir}/cron.d/%{name}

# install pam support
mkdir -p %{buildroot}%{_sysconfdir}/pam.d
install -m644 %{_sourcedir}/%{name}.pam \
	%{buildroot}%{_sysconfdir}/pam.d/smtpauth-login

# change zmailer.h file, --includedir= don't work
if ! [ -f %{buildroot}%{_Zincludedir}/zmailer.h ]  ; then
	mkdir -p %{buildroot}%{_Zincludedir}
	install -m644 %{buildroot}%{_includedir}/zmailer.h \
	  %{buildroot}%{_Zincludedir}/zmailer.h
fi

%pre
# ####################
# pre-install section

# RedHat source function library.
. %{_initrddir}/functions

# is zmailer running ?

rm -f %{_localstatedir}/run/.%{name}_was_run

if ( status scheduler || status router || status smtpserver ) | grep -v stop 2> /dev/null ; then
	if [ -f %{_initrddir}/%{name} ] ; then
		%{_initrddir}/%{name} stop
	else
		for i in scheduler router smtpserver ; do 
		killproc $i > /dev/null
		rm -rf %{_Zpostoffdir}/.pid.* 2> /dev/null
		done
	fi
	echo "running" > %{_localstatedir}/run/.%{name}_was_run
fi

# make zmailer group

if ! grep -q "^zmailer:" %{_sysconfdir}/group ; then
        # Use 'mail' group for zmailer...
        echo "zmailer:x:12:root,daemon,uucp" >> %{_sysconfdir}/group
fi

# port to mailer transport queue
if ! grep -q "^mailq" %{_sysconfdir}/services > /dev/null ; then
        echo "mailq           174/tcp                         # Mailer transport queue" >> %{_sysconfdir}/services
fi

%post
# #####################
# post-install section

# SYSV init
chkconfig --add %{name}

# run post-install script
# rebuild the zmailer aliases database, recreates the FQDN alias map,
# smtp-policy-db builder, create the postoffice dir ....... and more.
%{_Zlibdir}/post-install -OLDSTYLE

# mail.conf stuff
if ! ( [ -s %{_Zsysconfdir}/mail.conf ] && grep -c '^hostname' %{_Zsysconfdir}/mail.conf ) > /dev/null ; then
	echo "# Where am I?" > %{_Zsysconfdir}/mail.conf
	[ -z "`hostname -d`" ] || echo "orgdomain=`hostname -d`" >> %{_Zsysconfdir}/mail.conf
	echo "# Who am I?" >> %{_Zsysconfdir}/mail.conf
	[ -z "`hostname -d`" ] || echo "mydomain=`hostname -d`" >> %{_Zsysconfdir}/mail.conf
	echo "# Who do I claim to be?" >> %{_Zsysconfdir}/mail.conf
	[ -z "`hostname -f`" ] || echo "hostname=`hostname -f`" >> %{_Zsysconfdir}/mail.conf
fi

# localnames stuff
if ! ( [ -f %{_Zsysconfdir}/db/localnames ] && \
        grep -c "^localhost" %{_Zsysconfdir}/db/localnames ) > /dev/null ; then
        echo "localhost" >> %{_Zsysconfdir}/db/localnames
        echo "`hostname -f`" >> %{_Zsysconfdir}/db/localnames
        echo "`hostname`" >> %{_Zsysconfdir}/db/localnames
        echo "`hostname -d`" >> %{_Zsysconfdir}/db/localnames
        echo "localhost.`hostname -d`" >> %{_Zsysconfdir}/db/localnames
fi

# SECURITY NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# scheduler.auth is a plain text passwd !!!!!!!!!!!!!!!!!!!!!!!!!!!!
chown root:root %{_Zsysconfdir}/scheduler.auth
chmod 600 %{_Zsysconfdir}/scheduler.auth

# zmailer control script in the PATH is more coooooool :-)
ln -sf %{_Zlibdir}/zmailer %{_sbindir}/zmailer

# sendmail compatible stuff
ln -sf %{_Zlibdir}/sendmail %{_libdir}/sendmail
ln -sf %{_Zlibdir}/sendmail %{_sbindir}/sendmail

for i in mailq newaliases rmail vacation; do
	ln -sf %{_Zlibdir}/$i %{_bindir}/$i
done
ln -sf %{_Zsysconfdir}/db/aliases %{_sysconfdir}/aliases

# rebuild the zmailer databases
%{_Zlibdir}/zmailer newdb > /dev/null
%{_Zlibdir}/policy-builder.sh -n > /dev/null

# notices
cat << EOF

	If you are running PROCMAIL as your local delivery agent
	read %{_defaultdocdir}/%{name}-doc-%{version}/doc/guides/procmail.
	If you need docs, install the %{name}-doc-%{version}.
	Visit the www.zmailer.org site to get a new version of
	the Zmailer Manual and take a look to the news.
	A mailing list is avaliable at zmailer@nic.funet.fi
	Use <mailserver@nic.funet.fi> to subscribe yourself to
	the list by sending it a message with body content:
		subscribe zmailer Your Name

EOF

# Yes, it was running. Startup zmailer again
if [ -s %{_localstatedir}/run/.%{name}_was_run ] > /dev/null ; then
        %{_initrddir}/%{name} start
	rm -f %{_localstatedir}/run/.%{name}_was_run
fi

%preun
# ######################
# pre-uninstall section

# stop zmailer if it is running
if ( %{_initrddir}/%{name} status | grep -v stop ) > /dev/null ; then
	%{_initrddir}/%{name} stop
fi

# delete SYSV init stuff
chkconfig --del %{name}

%postun
# ######################
# post-uninstall section

# delete zmailer group
groupdel zmailer 2> /dev/null || echo "WARNING: failed to remove group zmailer"

# delete links
rm -f  %{_sbindir}/zmailer %{_sbindir}/sendmail %{_libdir}/sendmail \
	%{_sysconfdir}/aliases %{_sysconfdir}/mail.conf 
for i in mailq newaliases rmail vacation; do
        rm -f %{_bindir}/$i
done	

cat << EOF

	Look at %{_Zlogdir} to delete the zmailer logs,
	%{_Zpostoffdir} where are the zmailer big work
	dirs and %{_Zsysconfdir} where are the config files.
	Look for the zmailer group in %{_sysconfdir}/group and delete it.

EOF

%clean
rm -rf %{buildroot}
rm -rf %{_builddir}/zmailer-%{version}

%changelog

* Sat Sep 22 2001 Xose Vazquez <xose@wanadoo.es>

- update the rpm with macros for rpm-4 
  and a lot of changes, I think that this 
  is a new spec from top to botton

* Mon Apr 16 2001 Xose Vazquez <xose@wanadoo.es>

- minor changes for Zmailer-2.99.55
- bugs in Zmailer-2.99.55 :
- --includedir= in configure don't work
- /etc/mail.conf don't work, made a link to /etc/mail.conf
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

%{_sysconfdir}/pam.d/smtpauth-login
%{_sysconfdir}/cron.d/zmailer
%{_sysconfdir}/logrotate.d/zmailer
%{_initrddir}/zmailer

%config(missingok) %{_Zsysconfdir}/cf/proto/*
%config(missingok) %{_Zsysconfdir}/db/proto/*
%config(missingok) %{_Zsysconfdir}/forms/proto/*
%dir %{_Zsysconfdir}/fqlists
%dir %{_Zsysconfdir}/lists
%config(missingok) %{_Zsysconfdir}/proto/*
%{_Zsysconfdir}/vacation.msg
%{_Zsysconfdir}/zmailer.conf

%{_Zincludedir}/zmailer.h

%{_libdir}/libzmailer.a
%{_Zlibdir}

%{_mandir}

%dir %{_Zlogdir}
%attr(2755,root,root) %dir %{_Zpostoffdir}

%doc ChangeLog INSTALL MANIFEST Overview README* TODO contrib/README.debian

# ##################
# doc package files

%files doc
%doc doc/* man-ps man-html

# EOF
