#!/bin/sh
#
#  This script builds a ZMailer SH-script with incore data-entries from
#  a source of  key/data pairs
#
#  ARGS: dbasename infilename outfilename
#

DBASE=$1
INFILE=$2
OUTFILE=$3

PATH=$PATH:/usr/bin:/bin

if [ ! -f "$INFILE" ]; then exit 1; fi

(
	echo "# generated script from '$INFILE' into '$OUTFILE' at `date`"
	echo "relation -lt incore -d pathalias -s 0 $DBASE"
	awk '/^[^#]/{
		printf "db add '$DBASE' '\''%s'\'' '\''%s'\''\n",$1,$2;
	    }' 
) < $INFILE > $OUTFILE
