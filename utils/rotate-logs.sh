#!/bin/sh
#
#  Log-rotation utility for ZMailer
#
#  Your mileage may vary as you tune your loggings
#  At nic.funet.fi we use this DAILY, elsewere it
#  can be used weekly to monthly...
#

# ZCONFIG=@ZMAILERCFGFILE@
# . $ZCONFIG

. /etc/zmailer.conf

cd $LOGDIR

FILES="router scheduler smtpserver smtp"

for x in $FILES
do
	# cut, and compress
	for y in 8 7 6 5 4 3 2 1 0
	do
		z=`expr $y + 1`
		if [ -f $x.$y.gz ]; then
		    /bin/mv $x.$y.gz $x.$z.gz
		fi
	done
	if [ -f $x ]; then
		/bin/mv	$x $x.0
		/bin/touch $x
	fi
done

$MAILBIN/zmailer logsync

# Sleep here to let the logsync to take effect
#  -- what ? half an hour ?
sleep 1800

# Compress the newly separated log files
gzip *.0

