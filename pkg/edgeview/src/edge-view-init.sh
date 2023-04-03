#!/bin/sh

if [ -z "$EDGEVIEW_CLIENT" ]; then
  sleep 60 # allow system to settle, no need to come up too fast
  while true;
  do
    sleep 10
    PID=$(pgrep /usr/bin/edge-view)
    if [ -n "$PID" ]; then
      PID=$(echo "$PID" | tr '\n' ' ')
    fi
    if [ ! -f /run/edgeview/edge-view-config ]; then
      timediff=-1
    else
      now=$(date -u '+%s')
      notafter=$(grep "EvJWTExp:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
      timediff=$(( notafter - now ))
    fi
    if [ -z "$PID" ]; then
      if [ -f /run/edgeview/edge-view-config ] && [ $timediff -gt 0 ]; then
        CONFIGSUM=$(md5sum /run/edgeview/edge-view-config)
        TOKEN=$(grep "EvJWToken:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
        INSTNUM=$(grep "EdgeViewMultiInst:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
        if [ -z "${INSTNUM}" ]; then
          /usr/bin/edge-view -server -token "$TOKEN" &
        else
          a=0
          while [ $a -lt "$INSTNUM" ]
          do
            a=$((a+1))
            /usr/bin/edge-view -server -inst "$a" -token "$TOKEN" &
          done
        fi
        sleep 2 && PID=$(pgrep /usr/bin/edge-view)
        PID=$(echo "$PID" | tr '\n' ' ')
        echo "started edge-view with pid $PID"
      else
        if [ -f /run/edgeview/run-techsupport ]; then
          TechSupport="techsupport"
          /usr/bin/edge-view -server "$TechSupport" &
          sleep 30
        fi
      fi
    else
      if [ -f /run/edgeview/run-techsupport ]; then
        sleep 10
      elif [ $timediff -lt 0 ]; then
        kill -9 "$PID"
        echo "edge-view killed"
      else
        if [ -f /run/edgeview/edge-view-config ]; then
          NOWSUM=$(md5sum /run/edgeview/edge-view-config)
          if [ "$NOWSUM" != "$CONFIGSUM" ]; then # for restart, generate stack-trace for current one
            kill -ABRT "$PID"
            echo "edge-view killed due to restart, with stacks"
          fi
        fi
      fi
    fi
  done
else # 'edge-view' client usage
  /usr/bin/edge-view "$@"
fi
