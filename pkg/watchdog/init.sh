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
    # Firs thinsg first: kill it!
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

    # Now lets rebuild the configuration file
    rm -f /etc/watchdog.conf
    cp /etc/watchdog.conf.seed /etc/watchdog.conf
    find /cache -type f | sed -e 's#/cache/pid#pidfile = #' \
      -e '/\/cache\/file/a change = 300' -e 's#/cache/file#file = #' >> /etc/watchdog.conf

    # And finally re-start
    /usr/sbin/watchdog -F -s &
}

log() {
   echo "$(date -Is) $*"
}

run_watchdog() {
   local LAST_RELOAD
   LAST_RELOAD="$(date -u +%s)"
   while true; do
      read cmd
      log "Received the following watchdog request $cmd"
      case "$cmd" in
         .*) rm "/cache/$cmd"
             ;;
         ?*) mkdir -p "/cache/$(dirname "$cmd")"
             touch "/cache/$cmd"
             ;;
      esac
      # do the reload every 30 seconds only to not oscillate too much
      if [ $((LAST_RELOAD + 30)) -lt "$(date -u +%s)" ]; then
         reload_watchdog
         LAST_RELOAD="$(date -u +%s)"
      else
         [ "$cmd" ] && (sleep 33 ; echo "" >> "$WATCHDOG_CTL") &
      fi
   done
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

run_watchdog < "$WATCHDOG_CTL" 123>>"$WATCHDOG_CTL"
