#
# Sun Apr 27 03:53:45 CEST 2003 <xose at wanadoo es>
#
# TODO:
#	- maybe, adaptation for Red Hat alternatives
#	- maybe, creation of postoffice dirs manually 
# 	  not with post-install script
#

# allow --with <feature> at rpm command line build
# <features> = ssl, ldap, sasl2, ipv6, tcp-w, whoson, yp
# e.g. --with ssl --with ldap

%define _Zsysconfdir	%{_sysconfdir}/zmailer
%define _Zincludedir	%{_includedir}/zmailer
%define _Zlibdir 	%{_libexecdir}/zmailer
%define _Zlogdir	%{_localstatedir}/log/zmailer
%define _Zmaildir	%{_localstatedir}/spool/mail
%define _Zpostoffdir	%{_localstatedir}/spool/postoffice

%define zmailer_ver	2.99.56
%define spec_rel	4
%define zmailer_gid	499

Summary: Mailer for extreme performance demands, secure mail delivery agent.
Summary(pt_BR): Servidor de e-mail para demandas extremas de performance e segurança.
Summary(es): Agente de entrega de correo seguro para demandas de rendimiento extremas.
Name: zmailer
Version: %{zmailer_ver}
Release: %{spec_rel}
License: Freely usable, see %{_defaultdocdir}/%{name}-%{version}/README
Group: System Environment/Daemons
Provides: MTA smtpd smtpdaemon %{_bindir}/newaliases %{_bindir}/mailq %{_bindir}/rmail %{_bindir}/vacation %{_sbindir}/sendmail
Packager: Xose Vazquez <http://www.zmailer.org/buglog.html>
URL: http://www.zmailer.org
Source0: ftp://ftp.funet.fi/pub/unix/mail/zmailer/src/%{name}-%{version}.tar.gz
Source1: %{name}.init
Source2: %{name}.logrotate
Source3: %{name}.cron
Source4: %{name}.pam
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prereq: chkconfig
Obsoletes: sendmail postfix qmail exim smail vacation masqmail nullmailer courier-mta ssmtp
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
ZMailer. Es apropiado para pasarelas de correo o servidores de correo
u otros grandes entornos que tienen demandas de correo extremas.
Su desarrollo fue motivado por los problemas de diseño de Sendmail en
tales situaciones. ZMailer es uno de los mailers capaces de gestionar
elevadas cantidades de correo y es mas eficiente que otros programas,
qmail incluido, debido a sus excelentes algoritmos de colas.

La mayoria de usuarios no necesitan de este paquete -- les bastara 
sendmail o exim o smail.

%package doc
Summary: Documentation about the ZMailer Mail Transport Agent program.
Summary(pt_BR): Documentation about the ZMailer Mail Transport Agent program.
Summary(es): Documentacion sobre el programa ZMailer Mail Transport Agent.
Group: Documentation

%description doc
The %{name}-doc package contains documentation about the ZMailer
Mail Transport Agent (MTA) program, including desing notes, 
the ZMailer manual, and a few papers written about ZMailer.
The papers are available in PostScript, tex, html, txt and sgml.

Install the %{name}-doc package if you need documentation about
ZMailer.

Get the latest version of the ZMailer Manual at www.zmailer.org

%description doc -l pt_BR
The %{name}-doc package contains documentation about the ZMailer
Mail Transport Agent (MTA) program, including desing notes, 
the ZMailer manual, and a few papers written about ZMailer.
The papers are available in PostScript, tex, html, txt and sgml.

Install the %{name}-doc package if you need documentation about
ZMailer.

Get the latest version of the ZMailer Manual at www.zmailer.org

%description doc -l es
El paquete %{name}-doc contiene documentacion sobre el programa
ZMailer Mail Transport Agent (MTA), incluyendo notas de diseño,
el manual de ZMailer, y unos cuantos articulos sobre ZMailer. Los 
articulos estan disponibles en PostScript, tex, html, txt and sgml.

Instale el paquete %{name}-doc si necesita documentacion sobre
ZMailer.

Obtenga la ultima version del Manual de ZMailer en www.zmailer.org

%package devel
Summary: Development files for ZMailer.
Summary(pt_BR): Development files for ZMailer.
Summary(es): Ficheros de desarrollo de ZMailer.
Group: Development/Libraries

%description devel
The header files and libraries for developing applications that use
the ZMailer Mail Transport Agent.

Install the %{name}-devel package if you want to develop applications
which will use ncurses.

%description devel -l pt_BR
The header files and libraries for developing applications that use
the ZMailer Mail Transport Agent.

Install the %{name}-devel package if you want to develop applications
which will use ncurses.

%description devel -l es
Fichero de cabezera y biblioteca para desarrollar aplicaciones que
usen el ZMailer Mail Transport Agent.

Instale el paquete %{name}-devel si quiere desarrollar aplicaciones
que usen ZMailer Mail Transport Agent.

%prep

# unpack (and patch it).
%setup -q 
#patch0 -p1 -b .orig

# rebuild configure with system autoconf
#autoconf

# build it
%build
umask 022
CFLAGS="%{optflags}" \
./configure --prefix=%{_prefix} \
	--mandir=%{_mandir} \
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
	--with-nntpserver=news \
	--with-system-malloc \
	%{?_with_ssl:--with-openssl} \
	%{?_with_ldap:--with-ldap-prefix={_prefix}} \
	%{?_with_sasl2:--with-sasl2} \
	%{?_with_ipv6:--with-ipv6} \
	%{?_with_tcp-w:--with-tcp-wrappers} \
	%{?_with_whoson:--with-whoson={_libdir}} \
	%{?_with_yp:--with-yp} \
	--with-ta-mmap

make
make -C man groff
make -C man html

%install
umask 022
rm -rf %{buildroot}
mkdir -p %{buildroot}
make install prefix=%{buildroot}

# install man pages, --mandir= is broken
make MANDIR=%{buildroot}/%{_mandir} -C man install

# inn has a sm.8 manpage too
mv %{buildroot}%{_mandir}/man8/sm.8 \
	%{buildroot}%{_mandir}/man8/sm-z.8

# copy ps and html man pages
for i in ps html ; do
mkdir -p %{_builddir}/%{name}-%{version}/man-$i
install -m644 %{_builddir}/%{name}-%{version}/man/*.$i \
	%{_builddir}/%{name}-%{version}/man-$i
done

# install SYSV init stuff
mkdir -p %{buildroot}/%{_initrddir}
install -m755 %{_sourcedir}/%{name}.init \
        %{buildroot}/%{_initrddir}/%{name}

# install log rotation stuff
mkdir -p %{buildroot}/%{_sysconfdir}/logrotate.d
install -m644 %{_sourcedir}/%{name}.logrotate \
	%{buildroot}/%{_sysconfdir}/logrotate.d/%{name}

# install cron stuff
mkdir -p %{buildroot}/%{_sysconfdir}/cron.d
install -m644 %{_sourcedir}/%{name}.cron \
	%{buildroot}/%{_sysconfdir}/cron.d/%{name}

# install pam support
mkdir -p %{buildroot}/%{_sysconfdir}/pam.d
install -m644 %{_sourcedir}/%{name}.pam \
	%{buildroot}/%{_sysconfdir}/pam.d/smtpauth-login

# put into the bin_directories links to exec files
mkdir -p %{buildroot}/%{_sbindir} %{buildroot}/%{_bindir}

( cd %{buildroot}/usr

ln -sf ../libexec/zmailer/zmailer sbin/zmailer

ln -sf ../libexec/zmailer/sendmail sbin/sendmail

ln -sf ../libexec/zmailer/sendmail lib/sendmail

for i in mailq newaliases rmail vacation; do
	ln -sf ../libexec/zmailer/$i bin/$i
done

cd ../etc
ln -sf zmailer/db/aliases aliases
)

# delete not useful files
rm -fr %{buildroot}/%{_Zsysconfdir}/ChangeLog \
	%{buildroot}/%{_Zsysconfdir}/guides \
	%{buildroot}/%{_Zsysconfdir}/config.status

%pre
# ####################
# pre-install section

# rpm source function library.
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
	# Use 'zmailer_gid' group for zmailer
	echo "zmailer:x:%{zmailer_gid}:root,daemon,uucp" >> %{_sysconfdir}/group
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
# (rebuild the zmailer aliases database, recreates the FQDN alias map,
# smtp-policy-db builder, create the postoffice dirs and more...)
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
        echo "`hostname -a`" >> %{_Zsysconfdir}/db/localnames
        echo "`hostname -s`" >> %{_Zsysconfdir}/db/localnames
        echo "localhost.`hostname -d`" >> %{_Zsysconfdir}/db/localnames
fi

# SECURITY NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# scheduler.auth has a plain text passwd !!!!!!!!!!!!!!!!!!!!!!!!!!!
chown root:root %{_Zsysconfdir}/scheduler.auth
chmod 600 %{_Zsysconfdir}/scheduler.auth

# rebuild the zmailer databases
%{_Zlibdir}/zmailer newdb > /dev/null
%{_Zlibdir}/policy-builder.sh -n > /dev/null

# notices
cat << EOF

	If you are running PROCMAIL as your local delivery agent
	read %{_defaultdocdir}/%{name}-doc-%{version}/guides/procmail.
	If you need docs, install %{name}-doc-%{version} package.
	Visit the www.zmailer.org site to get a new version of
	the ZMailer Manual and take a look to news.
	A mailing list is avaliable at zmailer@nic.funet.fi
	Use <mailserver@nic.funet.fi> to subscribe yourself to
	the list by sending it a message with body content:
		subscribe zmailer Your Name

EOF

# Yes, it was running
if [ -s %{_localstatedir}/run/.%{name}_was_run ] > /dev/null ; then
# Doesn't run it again, because may be the configuration files was changed
#        %{_initrddir}/%{name} start
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
groupdel zmailer || echo "WARNING: failed to remove group zmailer"

cat << EOF

	Look at %{_Zlogdir} to delete the zmailer logs,
	%{_Zpostoffdir} where the zmailer big work dirs
	are and %{_Zsysconfdir} where the config files are.
	Look for the zmailer group in %{_sysconfdir}/group 
	and delete it.

EOF

%clean
rm -rf %{buildroot}
rm -rf %{_builddir}/%{name}-%{version}

# ##################
# package files

%files
%defattr(-,root,root)

%config %{_sysconfdir}/pam.d/smtpauth-login
%config %{_sysconfdir}/cron.d/%{name}
%config %{_sysconfdir}/logrotate.d/%{name}
%config %{_sysconfdir}/aliases
%config %{_initrddir}/%{name}

%config %{_Zsysconfdir}/bak
%config %{_Zsysconfdir}/cf/*
%config %{_Zsysconfdir}/db/*
%config %{_Zsysconfdir}/forms/*
%config %dir %{_Zsysconfdir}/fqlists
%attr(2755,root,root) %config %dir %{_Zsysconfdir}/lists
%config %{_Zsysconfdir}/proto/*
%config %{_Zsysconfdir}/vacation.msg
%config %{_Zsysconfdir}/zmailer.conf

%{_bindir}

%{_sbindir}

%{_libdir}/sendmail

%{_Zlibdir}

%{_mandir}/man[158]

%dir %{_Zlogdir}

%attr(2755,root,root) %dir %{_Zpostoffdir}

%doc ChangeLog INSTALL MANIFEST Overview README* TODO contrib/README.debian

# ##################
# doc package files

%files doc
%defattr(-,root,root)
%doc doc/* man-ps man-html

# ##################
# delvel package files

%files devel
%defattr(-,root,root)

%{_libdir}/libzmailer.a
%{_Zincludedir}/zmailer.h
%{_mandir}/man3

# ##################
# changelog

%changelog

* Sun Apr 27 2003 Xose Vazquez <xose@wanadoo.es> 2.99.56-4

- Adaptation for Red Hat Linux 9 and rpm 4.2

* Mon Apr  7 2003 Xose Vazquez <xose@wanadoo.es> 2.99.56-3

- I have stolen some ideas from Conectiva and PLD
  zmailer spec files
- new subpackage zmailer-devel
- doesn't run zmailer again if it was running
- allow --with <feature> at rpm command line build

* Wed Mar 12 2003 Xose Vazquez <xose@wanadoo.es> 2.99.56-2

- major clean up

* Thu May  2 2002 Xose Vazquez <xose@wanadoo.es>

- minor clean up

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

# EOF
