#!/bin/sh
PATH=/local/bin:/etc:/usr/etc:/bin:/usr/ucb:/usr/bin:
export PATH
#
TMPFILE=/tmp/bitnet.transport$$;
echo '***'
echo "### NOW FOR SOME CHECKS"
echo "1) Check that there are not more than one of the same node/name defined"
time cat bitnet.transport | \
	sed -e '/^#/d' -e 's/	.*$//' | uniq -d > $TMPFILE
#
if test -s "$TMPFILE"
then
	echo "***** PROBLEM PROBLEM PROBLEM *****"
	echo "* the following names are defined more than once"
	cat $TMPFILE
	echo "* end of multiple name list"
else
	echo "okay no problem with multiple names/nodes"
fi
echo '***'
rm -f $TMPFILE
echo "2) Check that there are no #OTR in the bitnet.transport (see munge.sh)"
echo "   basically if defined then there is interconnect tag that we do not"
echo "   know about"
time grep '#OTR' bitnet.transport > $TMPFILE
#
if test -s "$TMPFILE"
then
	echo "***** PROBLEM PROBLEM PROBLEM *****"
	echo "* the following lines have OTR defined"
	cat $TMPFILE
	echo "* end of OTR list"
else
	echo "okay no OTR encountered"
fi
echo '***'
rm -f $TMPFILE
echo "3) Check that SYSNAMES do not have multiple entries for one node"
time ./checksysnames.sh > $TMPFILE
#
if test -s "$TMPFILE"
then
	echo "***** PROBLEM PROBLEM PROBLEM *****"
	echo "* the following nodes are defined more than once in SYSNAMES"
	cat $TMPFILE
	echo "* end of SYSNAMES list"
else
	echo "okay no multiple node defined in SYSNAMES"
fi
echo '***'
rm -f $TMPFILE
echo "4) Check that each bitnet.transport entry has corresponding SYSNAMES entry"
time ./comparetransportvssysnames.sh > $TMPFILE
#
if test -s "$TMPFILE"
then
	echo "***** PROBLEM PROBLEM PROBLEM *****"
	cat $TMPFILE
	echo "* end of bitnet.transport vs SYSNAMES list"
else
	echo "okay all bitnet.transport nodes defined in SYSNAMES"
fi
echo '***'
rm -f $TMPFILE
#
