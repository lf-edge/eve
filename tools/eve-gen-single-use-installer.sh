#!/bin/sh
# shellcheck disable=SC2086
# shellcheck disable=SC2181

USAGE="Usage: $0 [options]
Options:
  -c <controller's fully-qualified domain name>
     Default is \"zedcloud.zededa.net\"
  -t <EVE image tag>
     Production EVE images built by lf-edge use tags with the format:
       <major>.<minor>.<bugfix>-<hypervisor>-<architecture>
     Where <hypervisor> is one of: kvm | xen
     And <architecture> is one of: amd64 | arm64 | riscv64
     Mandatory argument.
  -s <soft serial string>
     By default, device is started without pre-installed soft serial number.
     In that case, device will randomly generate soft serial and it will also deposit
     the number in the INVENTORY partition as a newly created folder, where the folder
     name is in fact that soft serial number. The user is then expected to import
     the number into the controller.
  -e <path to onboarding certificate>
     The certificate should be in the PEM format.
     By default, the certificate stored in the EVE repo under conf/onboard.cert.pem is installed.
  -k <path to onboarding key>
     The key should be in the PEM format.
     By default, the key stored in the EVE repo under conf/onboard.key.pem is installed.
  -b <path to bootstrap config>
     The file should contain BootstrapConfig (see EVE API) serialized with protobuf binary encoding.
     By default (i.e. bootstrap config not defined), device will start with an empty configuration
     and will try to establish controller connectivity either using a so-called \"lastresort\" network
     config (ethernet + DHCP client) or by receiving a JSON-formatted network config via a dedicated
     USB stick (aka usb.json, see tools/makeusbconf.sh|.bat)
  -o <path where to store output EVE installer>
     Mandatory argument.
  -f <output image format>
     Should be one of: raw | iso
     Default is raw.
Examples:
  $0 -c zedcloud.mycluster.zededa.net -t 8.5.1-kvm-amd64 -s 123456789 -b ./config.pb -o installer.raw
"

bail() {
  [ -n "$1" ] && echo "$1" >&2
  echo "$USAGE" >&2
  exit 1
}

cleanup() {
  [ -n "$CONTAINER" ] && docker rm "$CONTAINER" >/dev/null 2>&1
  [ -n "$VOLUME" ] && docker volume rm "$VOLUME" >/dev/null 2>&1
  [ -n "$TMPDIR" ] && rm -rf "$TMPDIR"
}

while getopts c:t:s:e:k:b:o:f: OPT
do case "$OPT" in
  c)   CONTROLLER="$OPTARG";;
  t)   TAG="$OPTARG";;
  s)   SERIAL="$OPTARG";;
  e)   CERT="$OPTARG";;
  k)   KEY="$OPTARG";;
  b)   BOOTSTRAP="$OPTARG";;
  o)   OUTPUT="$OPTARG";;
  f)   FORMAT="$OPTARG";;
  [?]) bail;;
  esac
done

if [ -z "$TAG" ]; then
  bail "Missing EVE tag argument (-t)"
fi

if [ -z "$OUTPUT" ]; then
  bail "Missing output argument (-o)"
fi

case "$FORMAT" in
  "") FORMAT="raw";; # default value
  "raw");;
  "iso");;
  *) bail "Unrecognized output format ($FORMAT)";;
esac

if [ -n "$CERT" ] && [ ! -f "$CERT" ]; then
  bail "Onboarding certificate file ($CERT) does not exist"
fi

if [ -n "$CERT" ] && [ -z "$KEY" ]; then
  bail "Onboarding certificate defined but not the key"
fi

if [ -n "$KEY" ] && [ ! -f "$KEY" ]; then
  bail "Onboarding key file ($KEY) does not exist"
fi

if [ -n "$BOOTSTRAP" ] && [ ! -f "$BOOTSTRAP" ]; then
  bail "Bootstrap config file ($BOOTSTRAP) does not exist"
fi

TMPDIR="$(mktemp -d -t config-override-XXXXXXXXXX)"
if [ -n "$CONTROLLER" ]; then
  echo "$CONTROLLER" > "$TMPDIR/server"
  FILES="$FILES server"
fi
if [ -n "$SERIAL" ]; then
  echo "$SERIAL" > "$TMPDIR/soft_serial"
  FILES="$FILES soft_serial"
fi
if [ -n "$CERT" ]; then
  cp "$CERT" "$TMPDIR/onboard.cert.pem"
  cp "$KEY" "$TMPDIR/onboard.key.pem"
  FILES="$FILES onboard.cert.pem onboard.key.pem"
fi
if [ -n "$BOOTSTRAP" ]; then
  cp "$BOOTSTRAP" "$TMPDIR/bootstrap-config.pb"
  FILES="$FILES bootstrap-config.pb"
fi

# Prepare lfedge/eve docker container with config files to override/add before
# starting the image builder.
CMD="installer_$FORMAT"
if [ -n "$FILES" ]; then
  # Note that lfedge/eve entrypoint expects /in directory to be mountpoint.
  VOLUME="$(docker volume create)"
  [ $? -ne 0 ] && bail
  CONTAINER="$(docker create --mount "source=${VOLUME},destination=/in" "lfedge/eve:$TAG" "$CMD")"
  [ $? -ne 0 ] && bail
  tar -cf - -C "$TMPDIR" $FILES | docker cp - "${CONTAINER}:/in"
  [ $? -ne 0 ] && bail
else
  # No config files to override/add.
  CONTAINER="$(docker create "lfedge/eve:$TAG" "$CMD")"
fi

# Start lfedge/eve entrypoint to build the installer image.
docker start -a "$CONTAINER" > "$OUTPUT"
[ $? -eq 0 ] && echo "Single-use EVE installer image was written to $OUTPUT"
cleanup
