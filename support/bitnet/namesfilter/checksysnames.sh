#!/bin/sh
PATH=/local/bin:/etc:/usr/etc:/bin:/usr/ucb:/usr/bin:
export PATH

cat /local/lib/urep/SYSNAMES | \
awk '
BEGIN	{ FS = " " }
	{ if (substr($0,1,1) != "*" )
		print $1 }
' |  tr A-Z a-z | sort | uniq -d
