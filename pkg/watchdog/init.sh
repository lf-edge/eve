#!/bin/sh

USE_HW_WATCHDOG=1
WATCHDOG_CTL=/run/watchdog.ctl

register_watchdog() {
  set $@
  [ -p "$WATCHDOG_CTL" ] || (rm -rf "$WATCHDOG_CTL" ; mkfifo "$WATCHDOG_CTL")
  for i in "$@"; do
    echo "$i" >> "$WATCHDOG_CTL"
  done
}

reload_watchdog() {
    if [ -f /var/run/watchdog.pid ]; then
        wp=$(cat /var/run/watchdog.pid)
        log "Killing watchdog $wp"
        kill "$wp"
        # Wait for it to exit so it can be restarted
        while kill -0 "$wp"; do
            log "Waiting for watchdog to exit"
            if [ $USE_HW_WATCHDOG = 1 ]; then
                wdctl
            fi
            sleep 1
        done
        log "Killed watchdog"
        sync
    fi
    /usr/sbin/watchdog -F -s &
}

log() {
   echo "$(date -Is) $*"
}


# Lets get this party started

if [ -c /dev/watchdog ]; then
    if [ $USE_HW_WATCHDOG = 0 ]; then
        log "Disabling use of /dev/watchdog"
        wdctl /dev/watchdog
    fi
else
    log "Platform has no /dev/watchdog"
    USE_HW_WATCHDOG=0
fi

# Create the watchdog(8) config files we will use
# XXX should we enable realtime in the kernel?
if [ $USE_HW_WATCHDOG = 1 ]; then
   echo 'watchdog-device = /dev/watchdog' >> /etc/watchdog.conf.seed
fi

# Create a control channel if it doesn't exist yet
[ -p "$WATCHDOG_CTL" ] || (rm -rf "$WATCHDOG_CTL" ; mkfifo "$WATCHDOG_CTL")

LAST_RELOAD="$(date -u +%s)"
while true; do
   read cmd < "$WATCHDOG_CTL"
   log "Received the following watchdog request $cmd"
   rm -f /etc/watchdog.conf
   (cat /etc/watchdog.conf.seed
   case "$cmd" in
      /*) echo "file = $cmd"
          echo "change = 300"
          ;;
      @*) echo "pidfile = ${cmd//@/}"
          ;;
   esac) >> /etc/watchdog.conf
   # do the reload every 30 seconds only to not oscilate too much
   if [ $((LAST_RELOAD + 30)) -lt "$(date -u +%s)" ]; then
      reload_watchdog
      LAST_RELOAD="$(date -u +%s)"
   else
      [ "$cmd" ] && (sleep 30 ; echo "" >> "$WATCHDOG_CTL") &
   fi
done
