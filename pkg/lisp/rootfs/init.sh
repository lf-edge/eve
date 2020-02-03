#!/bin/sh

cd /lisp

# some initial setup
rm -rf logs lisp.config
ln -s /run/lisp.config lisp.config
mkdir logs
mkfifo logs/lisp-traceback.log logs/lisp-flow.log

# waiting for configs to show up
while [ ! -e /run/lisp.config ] || [ ! -e /run/lisp.config.sh ]; do
  sleep 10
done

# start upstream lisp
. /run/lisp.config.sh
/lisp/RUN-LISP 8080 "$LISP_PORT_IFNAME"

# start EVE's own dataplane
/lisp/lisp-ztr -c `cat /run/eve.id` -lisp /lisp &

# get the logs out
tail -f logs/lisp-traceback.log &
tail -f logs/lisp-flow.log &

sh -c 'kill -STOP $$' | cat >>logs/lisp-traceback.log 2>>logs/lisp-flow.log
