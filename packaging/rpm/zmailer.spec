#
# TODO:
#	- maybe, adaptation for Red Hat alternatives (man 8 alternatives)

# FEATURE:
#	allow several --with <feature> at rpm command line build
#	<feature> = ssl, ldap, sasl2, ipv6, tcpw, whoson or yp
#	e.g. --with ssl --with ldap

%define _Zsysconfdir	%{_sysconfdir}/zmailer
%define _Zincludedir	%{_includedir}/zmailer
%define _Zlibexecdir 	%{_libexecdir}/zmailer
%define _Zlogdir	%{_localstatedir}/log/zmailer
%define _Zmaildir	%{_localstatedir}/spool/mail
%define _Zpostoffdir	%{_localstatedir}/spool/postoffice

%define zmailer_gid	499

Summary: Mailer for extreme performance demands, secure mail delivery agent.
Summary(pt_BR): Servidor de e-mail para demandas extremas de performance e segurança.
Summary(es): Agente de entrega de correo seguro para demandas de rendimiento extremas.
Name: zmailer
Version: 2.99.56
Release: 13
License: Free/Open Source Licenses, see %{_defaultdocdir}/%{name}-%{version}/README
Group: System Environment/Daemons
Provides: MTA smtpd smtpdaemon %{_bindir}/newaliases %{_bindir}/mailq %{_bindir}/rmail %{_bindir}/vacation %{_sbindir}/sendmail
Packager: Xose Vazquez Perez <http://www.zmailer.org/buglog.html>
URL: http://www.zmailer.org
Source0: ftp://ftp.funet.fi/pub/unix/mail/zmailer/src/%{name}-%{version}.tar.gz
Source1: %{name}.init
Source2: %{name}.logrotate
Source3: %{name}.cron
Source4: %{name}.pam
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Prereq: /sbin/chkconfig
Obsoletes: sendmail postfix qmail exim smail vacation masqmail nullmailer courier-mta ssmtp
# NoSource: 0

%description
This is a package that implements an internet message transfer agent
called ZMailer. It is intended for gateways or mail servers or other
large site environments that have extreme demands on the abilities of
the mailer. It was motivated by the problems of the Sendmail design
in such situations.

ZMailer is intended and designed as a multi-protocol mailer. The only
protocol supported in this distribution is RFC822 (and variations).

%description -l pt_BR
This is a package that implements an internet message transfer agent
called ZMailer. It is intended for gateways or mail servers or other
large site environments that have extreme demands on the abilities of
the mailer. It was motivated by the problems of the Sendmail design
in such situations.

ZMailer is intended and designed as a multi-protocol mailer. The only
protocol supported in this distribution is RFC822 (and variations).

%description -l es
Este paquete implementa un agente de tranferencia de mensajes llamado
ZMailer. Es apropiado para pasarelas de correo o servidores de correo
u otros grandes entornos que tienen demandas de correo extremas.
Su desarrollo fue motivado por los problemas de diseño de Sendmail en
tales situaciones.

ZMailer esta pensado y diseñado como un mailer multi-protocolo. El
unico protocolo soportado en esta distribucion es RFC822 (y variaciones).

%package doc
Summary: Documentation about the ZMailer Mail Transport Agent program.
Summary(pt_BR): Documentation about the ZMailer Mail Transport Agent program.
Summary(es): Documentacion sobre el programa ZMailer Mail Transport Agent.
Group: Documentation

%description doc
This package contains documentation about the ZMailer
Mail Transport Agent (MTA) program, including desing notes, 
the ZMailer manual, and a few papers written about ZMailer.
The papers are available in PostScript, tex, html, txt and sgml.

%description doc -l pt_BR
This package contains documentation about the ZMailer
Mail Transport Agent (MTA) program, including desing notes, 
the ZMailer manual, and a few papers written about ZMailer.
The papers are available in PostScript, tex, html, txt and sgml.

%description doc -l es
Esta paquete contiene documentacion sobre el programa
ZMailer Mail Transport Agent (MTA), incluyendo notas de diseño,
el manual de ZMailer, y unos cuantos articulos sobre ZMailer. Los 
articulos estan disponibles en PostScript, tex, html, txt and sgml.

%package devel
Summary: Development files for ZMailer Mail Transport Agent program.
Summary(pt_BR): Development files for ZMailer Mail Transport Agent program.
Summary(es): Ficheros de desarrollo para el programa ZMailer Mail Transport Agent.
Group: Development/Libraries

%description devel
Header file, library and perl module for developing applications
that use the ZMailer Mail Transport Agent.

%description devel -l pt_BR
Header file, library and perl module for developing applications
that use the ZMailer Mail Transport Agent.

%description devel -l es
Fichero de cabezera, bibliotecas y modulo perl para desarrollar
aplicaciones que usen el ZMailer Mail Transport Agent.

%prep
umask 022

# unpack (and patch it).
%setup -q 

# build it
%build
umask 022

%configure \
	--includedir=%{_Zincludedir} \
	--libdir=%{_libdir} \
	--mandir=%{_mandir} \
	--prefix=%{_prefix} \
	--with-perl-installdirs=PREFIX=%{buildroot}/%{_prefix} \
	--with-zconfig=%{_Zsysconfdir}/zmailer.conf \
	--with-logdir=%{_Zlogdir} \
	--with-mailbin=%{_Zlibexecdir} \
	--with-mailbox=%{_Zmaildir} \
	--with-mailvar=%{_Zsysconfdir} \
	--with-mailshare=%{_Zsysconfdir} \
	--with-postoffice=%{_Zpostoffdir} \
	--with-rmailpath=%{_bindir}/rmail \
	--with-sendmailpath=%{_sbindir}/sendmail \
	--with-vacationpath=%{_bindir}/vacation \
	--with-system-malloc \
	%{?_with_ssl:--with-openssl} \
	%{?_with_ldap:--with-ldap} \
	%{?_with_sasl2:--with-sasl2} \
	%{?_with_ipv6:--with-ipv6} \
	%{?_with_tcpw:--with-tcp-wrappers} \
	%{?_with_whoson:--with-whoson} \
	%{?_with_yp:--with-yp}

make

%install
umask 022

rm -rf %{buildroot}
mkdir -p %{buildroot}

make install DESTDIR=%{buildroot}

# install man pages
make MANDIR=%{buildroot}/%{_mandir} -C man install

# install SYSV init stuff
mkdir -p %{buildroot}/%{_initrddir}
install %{_sourcedir}/%{name}.init \
        %{buildroot}/%{_initrddir}/%{name}

# install log rotation stuff
mkdir -p %{buildroot}/%{_sysconfdir}/logrotate.d
install %{_sourcedir}/%{name}.logrotate \
	%{buildroot}/%{_sysconfdir}/logrotate.d/%{name}

# install cron stuff
mkdir -p %{buildroot}/%{_sysconfdir}/cron.d
install %{_sourcedir}/%{name}.cron \
	%{buildroot}/%{_sysconfdir}/cron.d/%{name}

# install pam support
mkdir -p %{buildroot}/%{_sysconfdir}/pam.d
install %{_sourcedir}/%{name}.pam \
	%{buildroot}/%{_sysconfdir}/pam.d/smtpauth-login

# run post-install script:
# create the postoffice spool dirs, move files, and more...
%{buildroot}/%{_Zlibexecdir}/post-install --destdir %{buildroot} 

# put into bin directories links to exec files
mkdir -p %{buildroot}/%{_sbindir} 
mkdir -p %{buildroot}/%{_bindir}

(cd %{buildroot}
ln -sf ../..%{_Zlibexecdir}/zmailer usr/sbin/zmailer
ln -sf ../..%{_Zlibexecdir}/sendmail usr/sbin/sendmail
ln -sf ../..%{_Zlibexecdir}/sendmail usr/lib/sendmail

for i in mailq newaliases rmail vacation; do
	ln -sf ../..%{_Zlibexecdir}/$i usr/bin/$i
done

ln -sf ..%{_Zsysconfdir}/db/aliases etc/aliases
)

# where are ZMailer perl modules installed ?
find %{buildroot} -name perllocal.pod -or -name .packlist | xargs rm -rf

find %{buildroot} -type f -print | \
	sed "s@^%{buildroot}@@g" | \
	grep "mailq.pm" > perl_modules-%{version}-filelist

# create it for rpm packaging
touch %{buildroot}/%{_Zsysconfdir}/mail.conf

# delete not useful files
rm -rf %{buildroot}/%{_Zsysconfdir}/ChangeLog \
	%{buildroot}/%{_Zsysconfdir}/guides \
	%{buildroot}/%{_Zsysconfdir}/config.status

%pre
umask 022
# ####################
# pre-install section

# rpm source function library.
. %{_initrddir}/functions

# stop it if it was running
if ( status scheduler || status router || status smtpserver ) | grep -v stop 2>/dev/null 1>&2 ; then
	if [ -f %{_initrddir}/%{name} ] ; then
		%{_initrddir}/%{name} stop 2>/dev/null 1>&2
	else
		for i in scheduler router smtpserver ; do
			killproc $i 2>/dev/null 1>&2
			rm -rf %{_Zpostoffdir}/.pid.*
		done
	fi
fi

# make zmailer group
if !(grep -q "^zmailer:" %{_sysconfdir}/group) ; then
	# Use 'zmailer_gid' for group id
	groupadd -g %{zmailer_gid} zmailer 2>/dev/null 1>&2
	for i in root daemon uucp; do
		gpasswd -a $i zmailer 2>/dev/null 1>&2
	done
fi

# port to mailer transport queue
if !(grep -q "^mailq" %{_sysconfdir}/services) ; then
	echo  -e "mailq\t\t174/tcp\t\t\t\t# Mailer transport queue" >> %{_sysconfdir}/services
fi

%post
umask 022
# #####################
# post-install section

# SYSV init
chkconfig --add %{name}

# disable automatic start up
chkconfig %{name} off

# mail.conf stuff
if ( [ -s %{_Zsysconfdir}/mail.conf ] ) ; then
	mv -f %{_Zsysconfdir}/mail.conf %{_Zsysconfdir}/mail.conf-$$.old
fi

echo "# Where am I?" > %{_Zsysconfdir}/mail.conf
[ -z "`hostname -d`" ] || echo "orgdomain=`hostname -d`" >> %{_Zsysconfdir}/mail.conf
echo "# Who am I?" >> %{_Zsysconfdir}/mail.conf
[ -z "`hostname -d`" ] || echo "mydomain=`hostname -d`" >> %{_Zsysconfdir}/mail.conf
echo "# Who do I claim to be?" >> %{_Zsysconfdir}/mail.conf
[ -z "`hostname -f`" ] || echo "hostname=`hostname -f`" >> %{_Zsysconfdir}/mail.conf

# localnames stuff
if ( [ -s %{_Zsysconfdir}/db/localnames ] ) ; then
	mv -f %{_Zsysconfdir}/db/localnames %{_Zsysconfdir}/db/localnames-$$.old
fi

cat > %{_Zsysconfdir}/db/localnames << EOF
#a
#b  Remap local names (and recognize them) to their "canonic" forms.
#c  thus having multiple machines on the same mailer..
#d
#z nicname		canonic.name
EOF

echo "localhost" >> %{_Zsysconfdir}/db/localnames
echo "localhost.`hostname -d`" >> %{_Zsysconfdir}/db/localnames
echo "`hostname`" >> %{_Zsysconfdir}/db/localnames
echo "`hostname -s`" >> %{_Zsysconfdir}/db/localnames
echo "`hostname -a`" >> %{_Zsysconfdir}/db/localnames
echo "`hostname -f`" >> %{_Zsysconfdir}/db/localnames
echo "`hostname -d`" >> %{_Zsysconfdir}/db/localnames

# rebuild the zmailer databases
%{_Zlibexecdir}/zmailer newdb 2>/dev/null 1>&2
%{_Zlibexecdir}/policy-builder.sh -n 2>/dev/null 1>&2

%preun
umask 022
# ######################
# pre-uninstall section

# stop it if it was running
if ( %{_initrddir}/%{name} status | grep -v stop 2>/dev/null 1>&2 ); then
	%{_initrddir}/%{name} stop 2>/dev/null 1>&2
fi

# delete SYSV init stuff
chkconfig --del %{name}

%postun
umask 022
# ######################
# post-uninstall section

# delete zmailer group
groupdel zmailer 2>/dev/null 1>&2

%clean
umask 022
rm -rf %{buildroot}
rm -rf %{_builddir}/%{name}-%{version}

# ##################
# package files

%files
%defattr(0644,root,root,0755)

%attr(0755,root,root) %config %{_initrddir}/%{name}
%config %{_sysconfdir}/pam.d/smtpauth-login
%config %{_sysconfdir}/cron.d/%{name}
%config %{_sysconfdir}/logrotate.d/%{name}
%{_sysconfdir}/aliases

%config %dir %{_Zsysconfdir}/bak
%config(noreplace) %{_Zsysconfdir}/cf
%config(noreplace) %{_Zsysconfdir}/db
%config(noreplace) %{_Zsysconfdir}/forms
%config(noreplace) %{_Zsysconfdir}/proto
%config %dir %{_Zsysconfdir}/fqlists
%attr(2755,root,root) %dir %{_Zsysconfdir}/lists
%config(noreplace) %{_Zsysconfdir}/mail.conf
%config(noreplace) %{_Zsysconfdir}/router.cf
%attr(0600,root,root) %config(noreplace) %{_Zsysconfdir}/scheduler.auth
%config(noreplace) %{_Zsysconfdir}/scheduler.conf
%config(noreplace) %{_Zsysconfdir}/sm.conf
%config(noreplace) %{_Zsysconfdir}/smtp-tls.conf
%config(noreplace) %{_Zsysconfdir}/smtpserver.conf
%config(noreplace) %{_Zsysconfdir}/vacation.msg
%config(noreplace) %{_Zsysconfdir}/zmailer.conf

%{_bindir}
%{_sbindir}
%{_libdir}/sendmail
%attr(0755,root,root) %{_Zlibexecdir}
%{_mandir}/man[158]
%attr(0700,root,root) %dir %{_Zlogdir}

%attr(2755,root,root) %dir %{_Zpostoffdir}
%attr(2750,root,root) %{_Zpostoffdir}/deferred
%attr(2750,root,root) %{_Zpostoffdir}/freezer
%attr(2750,root,root) %{_Zpostoffdir}/postman
%attr(3777,root,root) %{_Zpostoffdir}/public
%attr(2750,root,root) %{_Zpostoffdir}/queue
%attr(3777,root,root) %{_Zpostoffdir}/router
%attr(2750,root,root) %{_Zpostoffdir}/transport
%attr(2700,root,root) %{_Zpostoffdir}/TLSclntcache
%attr(2700,root,root) %{_Zpostoffdir}/TLSsrvrcache

%doc LICENSES LICENSES/README

# ##################
# doc package files

%files doc
%defattr(-,root,root,0755)
%doc ChangeLog INSTALL MANIFEST Overview README* TODO doc/* LICENSES

# ##################
# devel package files

%files devel -f perl_modules-%{version}-filelist
%defattr(0644,root,root,0755)

%{_libdir}/libzmailer.a
%{_Zincludedir}/zmailer.h
%{_mandir}/man3

%doc LICENSES LICENSES/README

# ##################
# changelog

%changelog
* Thu Jan 29 2004 Xose Vazquez <xose@wanadoo.es> 2.99.56-13

- README.LICENSES does not exist out of CVS releases.

* Fri Nov  7 2003 Xose Vazquez <xose@wanadoo.es> 2.99.56-12

- Make it simpler
- Minor bugs fixed
- Packaging of perl module
- Doesn't run post-install at %post. Do it at rpm packaging time
- Disable automatic start up, run it manually: # chkconfig zmailer on

* Sun Apr 27 2003 Xose Vazquez <xose@wanadoo.es> 2.99.56-4

- Adaptation for Red Hat Linux 9 and rpm 4.2

* Mon Apr  7 2003 Xose Vazquez <xose@wanadoo.es> 2.99.56-3

- I have stolen some ideas from Conectiva and PLD zmailer spec files
- new subpackage zmailer-devel
- doesn't run zmailer again if it was running
- allow --with <feature> at rpm command line build

* Wed Mar 12 2003 Xose Vazquez <xose@wanadoo.es> 2.99.56-2

- major clean up

* Thu May  2 2002 Xose Vazquez <xose@wanadoo.es>

- minor clean up

* Sat Sep 22 2001 Xose Vazquez <xose@wanadoo.es>

- update the rpm with macros for rpm-4 and a lot of changes
- I think that this is a new spec from top to botton

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

- new version for Zmailer-2.99.53pre1, too many changes

* Wed Oct 13 1999 Xose Vazquez <xose@ctv.es>

- Zmailer-2.99.52 install strip bin files, wonderful
- delete the strip section

* Fri Aug 6  1999 Xose Vazquez <xose@ctv.es>

- split zmailer, the doc is an independent rpm

* Thu Jul 29 1999 Xose Vazquez <xose@ctv.es>

- based on zmailer-%{version}/contrib/zmailer49.spec
- this is the first version, is all ok ?

# EOF
