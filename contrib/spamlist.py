#!/usr/bin/python
# Emacs: use -*-Python-*- mode.
#
# Z-mailer spam list maker
#
# Roy Bixler
# rcb@press-gopher.uchicago.edu
# 1 Dec. 1997, 6 Jun 1998
#

import ftplib, httplib, re, string, sys
from urlparse import *

# returns the contents at the given URL (must be either of type "http" or
# "ftp") as a list
def get_url_contents(url):
    global lns
    lns = []
    url_comps = urlparse(url)
    if (url_comps[0] == "file"):
	f = open(url_comps[2])
	ln = f.readline()
	while ln:
	    lns.append(string.rstrip(ln))
	    ln = f.readline()
	f.close()
    elif (url_comps[0] == "ftp"):
	def ftp_line(ln):
	    lns.append(ln)
	h = ftplib.FTP(url_comps[1])
	h.login()
	i = string.rfind(url_comps[2], '/')
	if (i >= 0):
	    h.cwd(url_comps[2][:i])
	    h.retrlines("RETR "+url_comps[2][i+1:], ftp_line)
	else:
	    h.retrlines("RETR "+url_comps[2], ftp_line)
	h.close()
    elif (url_comps[0] == "http"):
	h = httplib.HTTP(url_comps[1])
	h.putrequest('GET', url_comps[2])
	h.putheader('Accept', 'text/html')
	h.putheader('Accept', 'text/plain')
	h.endheaders()
	errcode, errmsg, headers = h.getreply()
	# HTTP/1.1 replies seem to generate an errorcode of -1, so try
	# to handle this case.  This may simply be a manifestation of
	# a broken Python 1.4 httplib module.  This bug has been fixed
	# with Python version 1.5.
	version = sys.version[0:3]
	if ((version < "1.5") and (errcode == -1)):
	    try:
		real_errcode = string.atoi(string.split(errmsg)[1])
	    except ValueError:
		real_errcode = -1 # yes, it really is bogus :-/
	    sys.stderr.write("%d" % (real_errcode)) # Should be 200
	else:
	    sys.stderr.write("%d" % (errcode)) # Should be 200
            if (errcode == 200):
                f = h.getfile()
                ln = f.readline()
                # once again, try to compensate for broken behavior on HTTP/1.1
                # by eating the header lines which would otherwise show up in
                # the data.  This bug has been fixed with Python version 1.5.
                if ((version < "1.5") and (errcode == -1) and (real_errcode <> -1)):
                    while ((ln) and
                           ((len(ln) > 2) or
                            (ln[0] <> "\r") or (ln[-1] <> "\n"))):
                        ln = f.readline()
                while ln:
                    lns.append(string.rstrip(ln)) # Get the raw HTML
                    ln = f.readline()
                f.close()
    return lns

# if there is not @-sign found, insert at beginning of string
def atify(dom):
    if (string.find(dom, '@') == -1):
	return '@'+dom
    else:
	return dom

# add the information found at 'svc_url' to a list of junk e-mailers.
# The list consists of the dictionary 'jdict'.  'svc_name' is merely used
# for the cosmetic purpose of progress reporting.  'start_after' specifies
# a string which marks the beginning of the list and 'end_before' similarly
# specifies a marker which tells when to stop reading the list.  These are
# both optional parameters.
def add_to_junkers_dict(jdict, svc_name, svc_url, start_after='',
			end_before=''):
    sys.stderr.write("%s: (status = " % (svc_name))
    tdict = get_url_contents(svc_url)
    sys.stderr.write(") - done\n")
    i = 0
    if (start_after):
	while ((i < len(tdict)) and
	       (tdict[i][0:len(start_after)] <> start_after)):
	    i = i+1
        i = i+1
    while (i < len(tdict)):
	if ((end_before) and (tdict[i][0:len(end_before)] == end_before)):
	    break
	if ((tdict[i]) and (tdict[i][0] <> "#")):
	    jdict[atify(tdict[i])] = svc_name
        i = i+1

# and now for the main program

# start with an empty junk list
sl = {}

#add_to_junkers_dict(sl, "Local",
#		    "file:/home/rcb/spamlist1",
#		    "", "")

add_to_junkers_dict(sl, "Hilotek",
		    "http://www.hilotek.com/Mail/SpamDomains.html",
		    "<h3", "<P")
add_to_junkers_dict(sl, "Taz 1",
		    "http://www.taz.net.au/Mail/SpamDomains",
		    "", "")
add_to_junkers_dict(sl, "Taz 2",
		    "http://www.taz.net.au/Mail/Spammers",
		    "", "")
add_to_junkers_dict(sl, "Webeasy",
		    "http://www.webeasy.com:8080/spam/spam_download_table",
		    "", "")
add_to_junkers_dict(sl, "Znet",
		    "http://www.znet.com/spammers.txt",
		    "", "")

# we only really care about the dictionary keys
ksl = sl.keys()

# output the sorted dictionary keys
ksl.sort()
ipv4_net = re.compile("^@[0-9]{1,3}(\.[0-9]{0,3}){0,3}$")
for i in ksl:
    if (ipv4_net.match(i)):
        num_dots = string.count(i, ".")
        if (i[-1] == "."):
            num_dots = num_dots-1
            i = i[1:-1]
        else:
            i = i[1:]
        if ((num_dots >= 0) and (num_dots < 4)):
            for n in range(3, num_dots, -1):
                i = i+".0"
            print "[%s]/%d" % (i, (num_dots+1)*8)
        else:
            print "what's wrong with this? i = %s, num_dots = %d" % (i, num_dots)
    else:
        print i
