#!/bin/sh
#
#  Expirer -- a crude script to alter "r     XXXXX YYYYYY..." into
#                                     "r+    XXXXX YYYYYY..."
#  Stop the scheduler, have system to quinche, then:
#
#	cd $POSTOFFICE/transport
#	...../expirer.sh "smtp xyz.fii.foo.faa"
#
files=`egrep -l -e "^r      $1 " [1-9]*`
for x in $files
do
	cat $x | \
	awk "/^r     $1 /{printf(\"r+     %s %s %s\\n\",\$2,\$3,\$4);
			  next; }
	     {print;}" > $x.oo
done
