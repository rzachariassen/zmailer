#!/bin/sh
#
#

. /etc/zmailer.conf

cd $LOGDIR

for x in router scheduler smtpserver smtp
do
	for y in oooo ooo oo o
	do
		/bin/mv $x.$y $x.${y}o
	done
	/bin/mv	$x $x.o
done

/etc/zmailer  # restart them all
