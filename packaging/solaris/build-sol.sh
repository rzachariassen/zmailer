#!/bin/sh


echo "PREREQUISITES:"
echo "  Execute this in a subdirectory you have made under the ZMailer"
echo "  source directory root, e.g. 'solaris8'"

if [ ! -f ../configure ]; then
   echo "  Proper command is e.g.:  sh ../packages/solaris/build-sol.sh"
   exit 1
fi

echo "  "
echo "  SUGGESTED feature is  www.OpenSSL.org version 0.9.3a at default location"
echo " "
echo "(sleep for 5 seconds, then the business starts..)"
sleep 5

rm -f config.cache config.status
set -x

export CC CFLAGS
CC=gcc
CFLAGS="-g -O"
MAKE=${MAKE:=make}

../configure					\
  --prefix=/opt/mail				\
  --mandir=/usr/local/man			\
  --libdir=/usr/local/lib			\
  --includedir=/usr/local/include		\
  --with-mailbox=/var/mail			\
  --with-postoffice=/var/spool/postoffice	\
  --with-openssl				\
  --without-rfc822-tabs
#  --with-tcp-wrappers=/usr/local/lib
#  --with-generic-include="-I/aa/include -I/usr/local/include"	\
#  --with-generic-library="-L/usr/local/lib"	\
#  --with-getpwnam-library="/aa/lib/libauth.a /aa/lib/libmd5crypt.a /aa/lib/libaa0.a " \
#  --with-logdir=/logs/mail


ZVERSION=`awk -F "\t ="  '
/^MAJORVERSION/{major=$2}
/^MINORVERSION/{minor=$2}
/^PATCHLEVEL/{patch=$2}
END{printf "%s.%s.%s\n",major,minor,patch;}'`

echo "ZVERSION=$ZVERSION"

$MAKE || exit $?

PREFIX="prefix=/tmp/zm-inst"

# --------- build Solaris package out of the stuff -------------
# ------- THIS WILL NOT CONTAIN CUSTOMIZED CFG FILES -----------

rm -rf /tmp/zm-inst
$MAKE install $PREFIX  || exit $?
cd man
 $MAKE install $PREFIX  || exit $?
cd ..

cd packaging/solaris
$MAKE pkgs prefix=/tmp/zm-inst SUFF=mbox VERSION="$ZVERSION"
