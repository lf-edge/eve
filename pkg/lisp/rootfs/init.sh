#!/bin/sh

EVE_ID="$(cat /run/eve.id 2>/dev/null)"

cd /lisp || exit 1

# some initial setup
mkdir -p /run/watchdog/pid 2>/dev/null || :
rm -rf logs lisp.config
mkdir logs
mkfifo logs/lisp-traceback.log logs/lisp-flow.log

# get the logs out
tail -f logs/lisp-traceback.log &
tail -f logs/lisp-flow.log &

# make sure that FIFOs remain alway open for writing (so readers
# don't get EOF, but rather block)
sh -c 'kill -STOP $$' 3>>logs/lisp-traceback.log 4>>logs/lisp-flow.log &

# Need to wait for /persist/config to be decrypted by tpmmgr in the pillar container
# XXX Remove this when we have move to subscribing to GlobalStatus and not GlobalConfig
while [ ! -d /persist/config/GlobalConfig ]; do
    echo "Waiting for /persist/config/GlobalConfig"
    sleep 10
done

# run lisp main loop
while true; do
  if [ -e /run/lisp.config ] && [ -e /run/lisp.config.sh ]; then
     # kill lisp
     killall -9 python lisp-ztr 2>/dev/null
     sleep 5

     # update config
     mv -f /run/lisp.config /run/lisp.config.sh .

     # start upstream lisp
     # shellcheck disable=SC1091
     (. lisp.config.sh ; /lisp/RUN-LISP 8080 "$LISP_PORT_IFNAME")

     # start EVE's own dataplane
     /lisp/lisp-ztr -c "${EVE_ID:-IMGX}" -lisp /lisp &
     touch /run/watchdog/pid/lisp-ztr.pid
  fi

  sleep 30
done
