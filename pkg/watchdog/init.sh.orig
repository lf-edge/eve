#!/bin/sh

USE_HW_WATCHDOG=1
DEFAULT_WATCHDOG_CHANGE_TIME=300
WATCHDOG_CHANGE_TIME=$(</proc/cmdline grep -o '\bchange=[^ ]*' | cut -d = -f 2)

adjust_parent_oom_score() {
  OOM_SCORE_ADJ=$(cat /proc/$$/oom_score_adj)
  if [ -n "$OOM_SCORE_ADJ" ]; then
    log "Set oom_score_adj of $PPID to $OOM_SCORE_ADJ"
    echo "$OOM_SCORE_ADJ">/proc/$PPID/oom_score_adj
  fi
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
            sleep 1
        done
        log "Killed watchdog"
        sync
    fi

    # Now lets replace the configuration file
    cp -f "$1" /etc/watchdog.conf

    # And finally re-start
    /usr/sbin/watchdog -F &
}

log() {
   echo "$(date -Is) $*"
}

run_watchdog() {
   while true; do
      # Now lets see if we need to rebuild the configuration file
      (cat /etc/watchdog.conf.seed
       find /run/watchdog -type f | sed -e 's#/run/watchdog/pid#pidfile = /run#' \
          -e "/\/run\/watchdog\/file/a change = $WATCHDOG_CHANGE_TIME"                             \
          -e 's#/run/watchdog/file#file = /run#') > /etc/watchdog.conf.latest

      # If the configuration changed: reload watchdog
      cmp -s /etc/watchdog.conf.latest /etc/watchdog.conf || reload_watchdog /etc/watchdog.conf.latest

      sleep 30
   done
}

# Lets get this party started

if [ -z "${WATCHDOG_CHANGE_TIME}" ]; then
    log "Setting value of $DEFAULT_WATCHDOG_CHANGE_TIME for WATCHDOG_CHANGE_TIME"
    WATCHDOG_CHANGE_TIME=$DEFAULT_WATCHDOG_CHANGE_TIME
fi

if [ -c /dev/watchdog ]; then
    if [ $USE_HW_WATCHDOG = 0 ]; then
        log "Disabling use of /dev/watchdog"
        wdctl /dev/watchdog
    fi
else
    log "Platform has no /dev/watchdog"
    USE_HW_WATCHDOG=0
fi

# set oom_score_adj for watchdog`s parent process, i.e. containerd-shim
adjust_parent_oom_score

# Create the watchdog(8) config files we will use
# XXX should we enable realtime in the kernel?
if [ $USE_HW_WATCHDOG = 1 ]; then
   echo 'watchdog-device = /dev/watchdog' >> /etc/watchdog.conf.seed
fi

# Create configuration end-points
mkdir -p /run/watchdog/pid /run/watchdog/file 2> /dev/null || :

mkdir -p /persist/log
run_watchdog | tee -a /persist/log/watchdog.log
