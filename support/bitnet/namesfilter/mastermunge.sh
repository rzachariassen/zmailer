#!/bin/sh
PATH=/local/bin:/etc:/usr/etc:/bin:/usr/ucb:/usr/bin:
export PATH
# Updated August 89 Johnny Chee Wah for zmailer bitnet.transport file
# 
# This is an attempt to create bitnet.transport. Since this is an attempt,
# please try to understand this script. One may need to update CA manually
# or update the shell script.
#
# Make sure that you have XMAILER.NAMES. You may want to compare with old copy
# which you had copied into the OLD directory.
echo '***'
echo "### doing XMAILER.NAMES to xmailer.names.out."
time munge.sh < XMAILER.NAMES | mastermunge.exception.sh | \
		sort > xmailer.names.out
echo "*** DONE xmailer.names.out ***"
echo '***'
#
# Make sure you have CADOMAIN.NAMES. You may want to compare with old copy
# which you had copied into the OLD directory.
#	You may want to compare things to the CA registery file.
#
# Should check make sure that #OTR does not exist
echo '***'
echo "### doing CADOMAIN.NAMES to cadomain.names.out."
echo "***      CADOMAIN.NAMES should already contains DOMAIN.NAMES as standard"
echo "***      with .ca default removed and .uucp override to UTORGPU added"
time munge.sh < CADOMAIN.NAMES | 
	mastermunge.exception.sh | format.sh | sort > cadomain.names.out
echo "*** DONE cadomain.names.out ***"
echo '***'
#
#
echo '***'
echo "### Merging xmailer.names.out, cadomain.names.out and toronto.names"
echo "*** to bitnet.transport."
echo '***     toronto.names contains the local entries bitnet entry '
echo '***     should keep it up to date and include it in hosts.transport.'
echo '***     This should be good to include this in bitnet.transport'
echo '***     and keep hosts.transport smaller?'
time cat xmailer.names.out cadomain.names.out toronto.names | \
		format.sh | sort -u > bitnet.transport
echo "*** DONE bitnet.transport ***"
echo '***'
