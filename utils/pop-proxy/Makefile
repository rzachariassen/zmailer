#
#  pop(3)-proxy for Sonera Corporation (Finland) internet services
#
#  THIS IS NOT FULLY INTEGRATED WITH ZMAILER AUTOCONFIG SYSTEM!
#

LIBSOL = -lresolv -lnsl -lsocket
CC     = gcc
LIBS   = -L../aa0 -laa0 $(LIBSOL)
CDEFS  =  -I../aa0 -DUSE_AA0 -DLOGFAC=LOG_LOCAL7
CFLAGS = -g -O -Wall $(CDEFS)

all: pop-proxy

pop-proxy: pop-proxy.o
	$(CC) $(CFLAGS) -o pop-proxy pop-proxy.o $(LIBS)

pop-proxy.o: pop-proxy.c

clean:
	rm -f *~ *.o pop-proxy
