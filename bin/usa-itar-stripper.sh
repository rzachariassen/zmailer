#!/bin/sh

#
#  This script hunts for following pairs of egrep lines, and DELETES
#  those lines, plus all text in between them.
#
#	"^#ifdef HAVE_OPENSSL"
#	"^#endif /* - HAVE_OPENSSL */"
#
#  For following patterns this just strips the lines away leaving
#  the text in..
#
#	"^#ifndef HAVE_OPENSSL"
#	"^#endif /* --HAVE_OPENSSL */"
#

if [ "$1" = "reverse" ]; then
    files=`find * -name '*.crypto'`
    > crypto.diff
    for f in $files
    do
	y=`echo $f | sed -e 's!\.crypto$!!'`
	diff -u $y $f >> crypto.diff
	mv $f $y
    done
    exit
fi

files=`find * -type f -name '*.[ch]'`
cryptofiles=`egrep -l HAVE_OPENSSL $files`

echo "Crypto-containing files:" $cryptofiles

for f in $cryptofiles
do
    cat $f | sed -e \
'\!^#ifdef HAVE_OPENSSL!,\!^#endif /\* - HAVE_OPENSSL \*/! s!^.*$!/* SSL RELATED CODE STRIPPED */!' \
-e 's"^#ifndef HAVE_OPENSSL""' -e 's"^#endif /\* --HAVE_OPENSSL \*/""' \
	> $f.cryptocleaned
    mv $f $f.crypto
    mv $f.cryptocleaned $f
done
