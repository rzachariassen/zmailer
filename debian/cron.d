##
## ZMailer default crontab:
##


# Resubmit deferred messages
28 0,8,16 * * *	root	/etc/init.d/zmailer resubmit >/dev/null

# Cleanout public and postman directories
7 4 * * *	root	/etc/init.d/zmailer cleanup >/dev/null

# Check if services still work
#11 6,12,18,0	root	zmailcheck
