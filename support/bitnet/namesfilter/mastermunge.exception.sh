#!/bin/sh
# Put the exception list here
# Be careful what you do here
# 1) awk - for any dot names that are not in .ca, override (#LOR)
# 2) sed - names that have interconnect.no (#IC.NO), make it valid
# 3) sed - override anything - most likely addition/deletion are done here
# 4) sed - absolute override
#	 - on UTORVM. all mailer utorant files are routed to mailer utorugw
awk '
{
	if (index($0, ".") > 0) {
		if (index($0, ".ca ") > 0)
			print $0
		else 
			printf("#LOR:%s\n", $0)
	} else {
		print $0
	}
}' |
sed -e '/#IC.NO:/s/^.*://' |
sed -e '/:.nl /s/^#.*://' \
    -e '/:.uk /s/^#.*://' \
    -e '/:.it /s/^#.*://' \
    -e '/^\.cdn /s/^/#LOR:/' \
    -e '/^\.fr /s/^/#LOR:/' \
    -e '/^\.ubc.ca /s/^/#LOR:/' \
    -e '/^ubc.ca /s/^/#LOR:/' \
    -e '/^.telly.on.ca /s/^/#LOR:/' \
    -e '/^telly.on.ca /s/^/#LOR:/' |
sed -e '/!utorgpu$/s/^/#LOR:/' \
    -e '/!utoross$/s/^/#LOR:/' \
    -e '/!utorugw$/s/^/#LOR:/' \
    -e '/!utorcsri$/s/^/#LOR:/' \
    -e '/!utorant$/s/bsmtp/smtp!neat.cs.utoronto.ca	#&/' \
    -e '/!utorme$/s/^/#LOR:/' \
    -e '/!interbit$/s/^/#LOR:/' \
    -e '/^.uucp	/s/^/#LOR:/'
