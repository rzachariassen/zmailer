#!/bin/sh
PATH=/local/bin:/etc:/usr/etc:/bin:/usr/ucb:/usr/bin:
export PATH
TRANSPORT=/tmp/transport$$
SYSNAMES=/tmp/sysnames$$

cat bitnet.transport | \
awk '
BEGIN	{ FS = "!" }
	{ print $NF }	# print the last name which should be the node
' |  tr A-Z a-z | sort -u > $TRANSPORT

cat /local/lib/urep/SYSNAMES | \
awk '
BEGIN	{ FS = " " }
	{ if (substr($0,1,1) != "*" )
		print $1 }
' |  tr A-Z a-z | sort -u > $SYSNAMES

( echo '#sysnames#'; cat $SYSNAMES; echo '#transport#'; cat $TRANSPORT) |
awk '
BEGIN			{ readthis = 0 }
$1 == "#sysnames#"	{ readthis = 1 ; next }
$1 == "#transport#"	{ readthis = 2 ; next }
readthis == 1		{
				sysnames[$1] = $1
				next
			}
readthis == 2 		{ 
				if (sysnames[$1] == "") {
		printf "Node %s defined in bitnet.transport but ", $1
		printf "not in SYSNAMES\n"
					next
				}
			}
'
rm -f $TRANSPORT $SYSNAMES
