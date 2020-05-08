#!/bin/sh
#
# For now this script only allows us to talk to Adam running
# together with EVE
LOCAL_MODE=${LOCAL_MODE:-1}

adama() {
   adam admin --insecure --server-ca /dev/null device "$@"
}

setdefaults() {
   if [ "$LOCAL_MODE" = 1 ]; then
      ADAM_SERVER="https://localhost:6000"
      export ADAM_SERVER
      UUID="$(adama list)"
      export UUID
   else
      echo "ERROR: only local mode supported for now. Make sure to set LOCAL_MODE=1"
      exit 1
   fi
}

setdefaults
case "$1" in
   getconf)
      adama config get --uuid "$UUID"
      ;;
   setconf)
      adama config set --uuid "$UUID" --config-path "$2"
      ;;
   logs)
      adama logs --uuid "$UUID"
      ;;
   info)
      adama info --uuid "$UUID"
      ;;
   *)
      echo "Usage: $0 getconf|setconf|logs|info"
esac
