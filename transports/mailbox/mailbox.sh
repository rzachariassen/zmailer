#!/bin/sh
DIR=/home/mea/zmailer-2.99.16/transports/mailbox
LD_LIBRARY_PATH=$DIR
export LD_LIBRARY_PATH
exec $DIR/mailbox.third $*
