#!/bin/sh
#
# This script is used to collect all info from the machine which
# helps to debug and resolve EVE issues.
#

# Script version, don't forget to bump up once something is changed

VERSION=40
# Add required packages here, it will be passed to "apk add".
# Once something added here don't forget to add the same package
# to the Dockerfile ('ENV PKGS' line) of the debug container,
# because we don't want to fail in case of network problems, on
# the other hand we want to support old versions of EVE, so we
# still attempt to install those packages.
PKG_DEPS="procps tar dmidecode iptables dhcpcd"

DATE=$(date "+%Y-%m-%d-%H-%M-%S")
# Function to get device identifier (UUID if onboarding, serial otherwise)
get_device_identifier() {
    local device_id=""
    # Check if device is onboarded by looking for device UUID
    # During onboarding, the device UUID is typically stored in /persist/status/uuid
    if [ -f "/persist/status/uuid" ]; then
        device_id=$(tr -d '\n' < /persist/status/uuid 2>/dev/null)
    fi
    # If no UUID found or device is not onboarded, attempt to retrieve the device serial
    if [ -z "$device_id" ] ; then
        #Get device serial number from DMI/SMBIOS
        device_id=$(dmidecode -s system-serial-number 2>/dev/null | head -1)
    fi
    # Clean up the identifier (remove spaces, special chars, limit length)
    device_id=$(echo "$device_id" | tr -d ' \t\n\r' | tr -cd '[:alnum:]-' | cut -c1-32)
    # If still empty return "unknown"
    if [ -z "$device_id" ]; then
        logger -s "Could not get either device UUID or device serial"
        device_id="unknown"
    fi
    echo "$device_id"
}

# Get device identifier
DEVICE_ID=$(get_device_identifier)

# Generate filename with device identifier
INFO_DIR_SUFFIX="eve-info-v$VERSION-$DEVICE_ID-$DATE"

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

COLLECT_LOGS_DAYS=
READ_LOGS_DEV=
READ_LOGS_APP=
TAR_WHOLE_SYS=
OUT_LOGS_IN_JSON=

usage()
{
    echo "Usage: collect-info.sh [-v] [-h] [-a APPLICATION-UUID] [-d]"
    echo "       -h   show this help"
    echo "       -v   show the script version"
    echo ""
    echo "The script works in two modes depending on the location where it"
    echo "is invoked:"
    echo " 1. Script, being called from EVE, collects all the logs, states"
    echo "    and makes a tarball. This mode is referenced as 'collect-logs mode',"
    echo "    see some options described below."
    echo " 2. Script, being called from untared tarball (collect-info.sh is"
    echo "    included into the resulting tarball), outputs all the"
    echo "    logs to the stdout. This mode is referenced as 'read-logs mode',"
    echo "    see some options described below."
    echo ""
    echo "Collect-logs mode:"
    echo "       -s tar whole /sysfs"
    echo "       -t NUMBER-OF-DAYS    - collect logs from the last NUMBER-OF-DAYS [0-30]. Set to 0 to not include /persist/newlog logs."
    echo "       -u server            - upload logs via http to server with credentials in AUTHORIZATION environment variable"
    echo "                              AUTHORIZATION is the value for the http header called 'Authorization'"
    echo "                              To use basic auth with user-id 'Aladdin' and password 'open sesame', it would be the following:"
    echo "                              'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='"
    echo "                              To create the base64-encoded value, the following can be used:"
    echo "                              echo -n 'Aladdin:open sesame' | base64"
    echo "                              After uploading the tarball will be deleted."
    echo ""
    echo "Read-logs mode:"
    echo "       -d                   - read device logs only"
    echo "       -a APPLICATION-UUID  - read specified application logs only"
    echo "       -e                   - additional edgeview string in filename"
    echo "       -j                   - output logs in json"
    echo ""
    echo "WARNING: $0 does not have a stable CLI interface. Use with caution in scripts."
    exit 1
}

while getopts "vu:sha:djet:" o; do
    case "$o" in
        h)
            usage
            ;;
        v)
            echo "v$VERSION"
            exit 0
            ;;
        a)
            READ_LOGS_APP="$OPTARG"
            ;;
        t)
            COLLECT_LOGS_DAYS="$OPTARG"
            if [ "$COLLECT_LOGS_DAYS" -lt 0 ] || [ "$COLLECT_LOGS_DAYS" -gt 30 ]; then
                echo "Error: COLLECT_LOGS_DAYS must be between 0 and 30."
                exit 1
            fi
            ;;
        d)
            READ_LOGS_DEV=1
            ;;
        e)
            INFO_DIR_SUFFIX="eve-info-edgeview-v$VERSION-$DEVICE_ID-$DATE"
            ;;
        s)
            TAR_WHOLE_SYS=1
            ;;
        j)
            OUT_LOGS_IN_JSON=1
            ;;
        u)
            UPLOAD="$OPTARG"
            ;;
        :)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

TARBALL_FILE="/persist/eve-info/$INFO_DIR_SUFFIX.tar.gz"

is_in_debug_service() {
    grep -q '/eve/services/debug' < /proc/self/cgroup
}

sort_cat_jq()
{
    # Sort and extract a filename
    sort -n | awk '{print $2}' | \
    # Decompress if needed and output
    xargs --no-run-if-empty zcat -f | \
    # Add a new JSON entry "timestamp.str" which represents timestamp
    # in a human readable `strftime` format: "%Y-%m-%d %I:%M:%S.%f".
    # The whole complexity lies in the JQ `strftime` implementation
    # which does not support milli/nano seconds ("%f" part), and for
    # me that means converting nanos# to a fraction of a float number.
    # If nanos field does not have exactly 9 digits it should be
    # prepended with 0. E.g. nanos == 99, so the fraction should be
    # ".000000099" and not ".99", that's why the complex conversion:
    # "nanos  + 1e9 | tostring | .[1:]".
    # Also:
    # "-R (. as $line | try fromjson)" means ignore a line if is not a JSON,
    # "(nanos // 0)" means return 0 if nanos is null
    if [ -n "$OUT_LOGS_IN_JSON" ]; then
        jq -R '(. as $line | try fromjson) | .timestamp.str.nanos = ((.timestamp.nanos // 0) + 1e9 | tostring | .[1:]) | .timestamp.str.human = (.timestamp.seconds | strftime("%Y-%m-%d %I:%M:%S")) | .timestamp.str = "\(.timestamp.str.human).\(.timestamp.str.nanos)"'
    else
        # "(.content as $cont | $cont | try (fromjson.msg) catch $cont)"
        #     - we handle nested JSON, which is not always the case
        # | awk /./
        #     - remove blank lines, kernel log has additional \n at the end
        jq -r -R '(. as $line | try fromjson) | .timestamp.str.nanos = ((.timestamp.nanos // 0) + 1e9 | tostring | .[1:4]) | .timestamp.str.human = (.timestamp.seconds | strftime("%Y-%m-%d %I:%M:%S")) | "\(.timestamp.str.human).\(.timestamp.str.nanos)|\(.severity)|\(.source)|\(.filename // "")| \(  (.content as $cont | $cont | try (fromjson.msg) catch $cont) )"' | awk /./
    fi
}

# We are not on EVE? Switch to read-logs mode
if [ -d "$SCRIPT_DIR/persist-newlog" ]; then
    FIND=".log"

    if [ -n "$READ_LOGS_DEV" ]; then
        FIND="dev.log"
    elif [ -n "$READ_LOGS_APP" ]; then
        FIND="app.$READ_LOGS_APP.log"
    fi

    # Find compressed logs (device or application or both)
    find . -name "*$FIND*gz" 2>/dev/null | \
        # Extract timestamp and make it a first column
        perl -ne 'if (/\.(\d+).gz$/){ printf "$1 $_";  }' | \
        # Process the rest
        sort_cat_jq

    # Find not yet compressed logs (device or application or both)
    # which follow the compressed logs.
    #
    # For each file read a first valid line with a timestamp and output
    # in the following format: "$TIMESTAMP $FILEPATH". Also:
    # "-R (. as $line | try fromjson)" means ignore a line if is not a JSON,
    # "(nanos // 0)" means return 0 if nanos is null
    # shellcheck disable=SC2156
    find . -regex ".*$FIND.?[0-9]+" -exec \
        sh -c "jq -R '(. as \$line | try fromjson) | select(has(\"timestamp\")) | (.timestamp.seconds + (.timestamp.nanos // 0) / 1e9)' {} | head -n 1 | sed 's:$: {}:' " \; 2>/dev/null | \
        # Process the rest
        sort_cat_jq

    exit
fi

# We are on EVE? Switch to collect-info mode
# but only if we are in debug container
if ! is_in_debug_service; then
    echo "$0 has to be started from debug container; use 'eve enter debug' to enter debug container"
    exit 1
fi

# Create temporary dir
echo "- basic setup"
TMP_DIR=$(mktemp -d -t -p /persist/tmp/)
LOG_TMP_DIR="$TMP_DIR/dayslogs"
DIR="$TMP_DIR/$INFO_DIR_SUFFIX"
mkdir -p "/persist/eve-info"
mkdir -p "$DIR"
mkdir -p "$DIR/network"

# Check for internet access, timeouts at 30 seconds,
# If there is internet access, install required GNU utilities and networking tools.
if nc -z -w 30 dl-cdn.alpinelinux.org 443 2>/dev/null; then
  echo "- install GNU utilities and networking tools"
  # shellcheck disable=SC2086
  apk add $PKG_DEPS >/dev/null 2>&1
fi

check_tar_flags() {
  tar --version | grep -q "GNU tar"
}

collect_sysfs()
{
    echo "- sysfs"
    local tarball_file="$DIR/sysfs.tar"
    if check_tar_flags; then
        tar --ignore-failed-read --warning=none -czf "$tarball_file" "/sys" > /dev/null 2>&1 || true
    else
        tar -czf "$tarball_file" "/sys" > /dev/null 2>&1 || true
    fi
}

collect_network_info()
{
    echo "- network info"
    echo "   - ifconfig, ip, arp, netstat, iptables, conntrack"
    ifconfig       > "$DIR/network/ifconfig"
    ip -s link     > "$DIR/network/ip-s-link"
    ip rule list   > "$DIR/network/ip-rule-list"
    arp -n         > "$DIR/network/arp-n"
    netstat -tuapn > "$DIR/network/netstat-tuapn"

    ip route show table all \
                   > "$DIR/network/ip-route-show-table-all"
    iptables -L -v -n --line-numbers -t raw \
                   > "$DIR/network/iptables-raw"
    iptables -L -v -n --line-numbers -t filter \
                   > "$DIR/network/iptables-filter"
    iptables -L -v -n --line-numbers -t mangle \
                   > "$DIR/network/iptables-mangle"
    iptables -L -v -n --line-numbers -t nat \
                   > "$DIR/network/iptables-nat"
    eve exec pillar /opt/zededa/bin/conntrack > "$DIR/network/conntrack"

    echo "   - dhcpcd for all ifaces"
    for iface in /sys/class/net/*; do
        iface="${iface##*/}"
        echo "------ $iface -------"
        dhcpcd -U -4 "$iface"
    done > "$DIR/network/dhcpcd-all-ifaces" 2>&1

    echo "   - cellular modems"
    MODEMS="$(eve exec --fork wwan mmcli -L |\
              sed -n 's/.*\/ModemManager1\/Modem\/\([0-9]\+\).*/\1/p' | uniq)"
    for MODEM in $MODEMS; do
        INFO="$(eve exec --fork wwan mmcli -m "$MODEM")"
        echo
        echo "Modem $MODEM:"
        echo "$INFO"
        SIMS="$(echo "$INFO" |\
                sed -n 's/.*\/ModemManager1\/SIM\/\([0-9]\+\).*/\1/p' | uniq)"
        for SIM in $SIMS; do
            echo
            echo "SIM $SIM used by modem $MODEM:"
            eve exec --fork wwan mmcli -i "$SIM"
        done
        BEARERS="$(echo "$INFO" |\
                   sed -n 's/.*\/ModemManager1\/Bearer\/\([0-9]\+\).*/\1/p' | uniq)"
        for BEARER in $BEARERS; do
            echo
            echo "Bearer $BEARER used by modem $MODEM:"
            eve exec --fork wwan mmcli -b "$BEARER"
        done
        echo
        echo "Modem $MODEM location status:"
        eve exec --fork wwan mmcli -m "$MODEM" --location-status
        echo
        echo "Modem $MODEM location:"
        eve exec --fork wwan mmcli -m "$MODEM" --location-get
    done > "$DIR/network/wwan" 2>&1

    echo "- done network info"
}

collect_pillar_backtraces()
{
    echo "- pillar memory backtraces"

    eve http-debug > /dev/null 2>&1
    curl --retry-all-errors --retry 3 --retry-delay 3 -m 5 -s "http://127.1:6543/debug/pprof/heap?debug=1" | gzip > "$DIR/pillar-memory-backtraces.gz"
    curl --retry-all-errors --retry 3 --retry-delay 3 -m 5 -s "http://127.1:6543/debug/pprof/goroutine?debug=2" | gzip > "$DIR/pillar-backtraces.gz"
    eve http-debug stop > /dev/null 2>&1

    echo "- done pillar memory backtraces"
}

collect_zfs_info()
{
    type=$(cat /run/eve.persist_type)
    if [ "$type" = "zfs" ]; then
       echo "- Collecting ZFS specific info"
       {
           echo "zpool status"
           echo "============"
           eve exec pillar zpool status
           echo "============"
           echo "zpool list -v"
           echo "============"
           eve exec pillar zpool list -v
           echo "============"
           echo "zfs get all properties"
           echo "============"
           eve exec pillar zfs get all
           echo "============"
           echo "zfs list -o all"
           echo "============"
           eve exec pillar zfs list -o all
           echo "============"
           echo "ZFS DMU TX "
           echo "============"
           eve exec pillar cat /proc/spl/kstat/zfs/dmu_tx
           echo "============"
           echo "ZFS ARC stats "
           echo "============"
           eve exec pillar cat /proc/spl/kstat/zfs/arcstats
           echo "============"
        } > "$DIR/zfs-info"
    fi
}
collect_kube_info()
{
    type=$(cat /run/eve-hv-type)
    if [ "$type" = "kubevirt" ]; then
       echo "- Collecting Kube specific info"
       {
           echo "kubectl get nodes"
           echo "============"
           eve exec kube kubectl get nodes -o wide
           echo "============"
           echo "kubectl describe nodes"
           echo "============"
           eve exec kube kubectl describe nodes
           echo "============"
           echo "kubectl get pods -A"
           echo "============"
           eve exec kube kubectl get pods -A
           echo "============"
           echo "kubectl describe pods -A"
           echo "============"
           eve exec kube kubectl describe pods -A
           echo "============"
           echo "kubectl get rs -A"
           echo "============"
           eve exec kube kubectl get rs -A
           echo "============"
           echo "kubectl describe rs -A"
           echo "============"
           eve exec kube kubectl describe rs -A
           echo "============"
           echo "kubectl get pvc -A"
           echo "============"
           eve exec kube kubectl get pvc -A
           echo "============"
           echo "kubectl describe pvc -A"
           echo "============"
           eve exec kube kubectl describe pvc -A
           echo "============"
           echo "kubectl get vmi -A"
           echo "============"
           eve exec kube kubectl get vmi -A
           echo "============"
           echo "kubectl describe vmi -A"
           echo "============"
           eve exec kube kubectl describe vmi -A
           echo "============"
           echo "kubectl get vmirs -A"
           echo "============"
           eve exec kube kubectl get vmirs -A
           echo "============"
           echo "kubectl describe vmirs -A"
           echo "============"
           eve exec kube kubectl describe vmirs -A
           echo "============"
           echo "kubectl get kubevirt -n kubevirt -o yaml"
           echo "============"
           eve exec kube kubectl get kubevirt -n kubevirt -o yaml
           echo "============"
           echo "kubectl top node"
           echo "============"
           eve exec kube kubectl top node
           echo "============"
           echo "kubectl top pod -A --sum"
           echo "============"
           eve exec kube kubectl top pod -A --sum
           echo "============"
        } > "$DIR/kube-info"
    fi
}

collect_longhorn_info()
{
    type=$(cat /run/eve-hv-type)
    if [ "$type" != "kubevirt" ]; then
        return
    fi
    echo "- Collecting Longhorn specific info"
    {
        echo "  - longhorn support bundle: please wait up to 300 seconds."
        # This step involves multiple network operations
        # including an image pull and requests to other
        # cluster nodes which can all see delays and timeouts
        # when nodes are down.
        # Give up after 5min, and allow remaining system data to be collected.
        timeout 300s eve exec kube /usr/bin/longhorn-generate-support-bundle.sh
    } > "$DIR/longhorn-info" 2>&1
}

# Copy itself
cp "${0}" "$DIR"

# Have to chroot, lsusb does not work from this container
echo "- lsusb, dmesg, ps, lspci, lsblk, lshw, lsof, lsmod, logread, dmidecode, ls -lRa /dev, free"
chroot /hostfs lsusb -vvv    > "$DIR/lsusb-vvv"
chroot /hostfs lsusb -vvv -t > "$DIR/lsusb-vvv-t"

{
    find /sys/devices/ -path '*/usb[0-9]/*' -name "uevent" -exec awk '{print FILENAME ":" $0}' {} \;
    find /sys/devices/ -path '*/usb[0-9]/*' -name "product" -exec awk '{print FILENAME ":" $0}' {} \;
    echo "ls -l /sys/class/net/"
    ls -l /sys/class/net/
} > "$DIR/sys-fs-usb"

dmesg -T         > "$DIR/dmesg-T"
ps -xao uid,pid,ppid,vsz,rss,c,pcpu,pmem,stime,tname,stat,time,cmd \
                 > "$DIR/ps-xao"
lspci -vvv       > "$DIR/lspci-vvv"
lspci -vvv -t    > "$DIR/lspci-vvv-t"
lsblk -a         > "$DIR/lsblk-a"
lshw             > "$DIR/lshw"
lsof             > "$DIR/lsof"
lsmod            > "$DIR/lsmod"
logread          > "$DIR/logread"
dmidecode        > "$DIR/dmidecode"
ls -lRa /dev     > "$DIR/ls-lRa-dev"
ls -lRa /persist > "$DIR/ls-lRa-persist"
free             > "$DIR/free"
df -h            > "$DIR/df-h"

echo "- vmallocinfo, slabinfo, meminfo, zoneinfo, mounts, vmstat, cpuinfo, iomem"
cat /proc/vmallocinfo > "$DIR/vmallocinfo"
cat /proc/slabinfo    > "$DIR/slabinfo"
cat /proc/meminfo     > "$DIR/meminfo"
cat /proc/zoneinfo    > "$DIR/zoneinfo"
cat /proc/mounts      > "$DIR/mounts"
cat /proc/vmstat      > "$DIR/vmstat"
cat /proc/cpuinfo     > "$DIR/cpuinfo"
cat /proc/iomem       > "$DIR/iomem"

echo "- qemu affinities"
qemu-affinities.sh    > "$DIR/qemu-affinities"

echo "- iommu groups"
iommu-groups.sh       > "$DIR/iommu-groups"

echo "- TPM event log"
find /sys/kernel/security -name "tpm*" | while read -r TPM; do
    if [ -f "$TPM/binary_bios_measurements" ]; then
        TPM_LOG_BIN="$(basename "$TPM").evtlog_bin"
        TPM_LOG_INFO="$(basename "$TPM").evtlog_info"
        TPM_EVT_LOG_SIZE=$(wc -c "$TPM/binary_bios_measurements" | cut -d ' ' -f1)
        # read max size is 1mb
        if [ "$TPM_EVT_LOG_SIZE" -gt 1048576 ]; then
            TPM_EVT_LOG_SIZE=1048576
            echo "tpm log is truncated" > "$DIR/$TPM_LOG_INFO"
        else
            echo "tpm log is NOT truncated" > "$DIR/$TPM_LOG_INFO"
        fi
        dd if="$TPM/binary_bios_measurements" of="$DIR/$TPM_LOG_BIN" bs=1 count="$TPM_EVT_LOG_SIZE"
    fi
done

echo "- vTPM (SWTPM) logs"
for dir in /persist/swtpm/tpm-state-*; do
    if [ -d "$dir" ]; then
        uuid="${dir##*/tpm-state-}"
        log_file="$dir/swtpm.log"
        if [ -f "$log_file" ]; then
            cp "$log_file" "$DIR/$uuid.swtpm.log"
        fi
    fi
done

if [ -c /dev/tpm0 ]; then
    echo "- TPM persistent handles"
    eve exec vtpm tpm2 getcap handles-persistent > "$DIR/handles-persistent.txt"
    echo "- TPM PCRs capabilitie"
    eve exec vtpm tpm2 getcap pcrs > "$DIR/selected-pcrs.txt"
fi

if [ -n "$COLLECT_LOGS_DAYS" ]; then
    mkdir -p "$LOG_TMP_DIR"
    # Find and copy log files from /persist/newlog to $LOG_TMP_DIR in previous days
    find /persist/newlog -type f -mtime -"$COLLECT_LOGS_DAYS" -exec ln -s {} "$LOG_TMP_DIR" \;
    ln -s "$LOG_TMP_DIR" "$DIR/persist-newlog"
else
    ln -s /persist/newlog "$DIR/persist-newlog"
fi

ln -s /persist/certs        "$DIR/persist-certs"
ln -s /persist/status       "$DIR/persist-status"
ln -s /persist/log          "$DIR/persist-log"
[ -d /persist/kubelog ] && ln -s /persist/kubelog "$DIR/persist-kubelog"
ln -s /persist/netdump      "$DIR/persist-netdump"
ln -s /persist/kcrashes     "$DIR/persist-kcrashes"
[ -d /persist/memory-monitor/output ] && ln -s /persist/memory-monitor/output "$DIR/persist-memory-monitor-output"
[ -f /persist/agentdebug/watcher/sigusr1 ] && cp /persist/agentdebug/watcher/sigusr1 "$DIR/goroutin-leak-detector-stacks-dump"
ln -s /run                  "$DIR/root-run"
cp -r /sys/fs/cgroup/memory "$DIR/sys-fs-cgroup-memory" >/dev/null 2>&1
[ -f /persist/SMART_details.json ] && ln -s /persist/SMART_details* "$DIR/"
cp    /config/grub.cfg      "$DIR/config-grub.cfg"
cp    /config/server        "$DIR/config-server"
[ -d /persist/monitor ] && ln -s /persist/monitor "$DIR/persist-monitor"

# Network part
collect_network_info

# Pillar part
collect_pillar_backtraces

# ZFS part
collect_zfs_info

# Kube part
collect_kube_info
collect_longhorn_info

if [ -n "$TAR_WHOLE_SYS" ]; then
  collect_sysfs
fi

# Make a tarball
# --exlude='root-run/run'              /run/run/run/.. exclude symbolic link loop
# --exclude='root-run/containerd-user'  the k8s.io/*/rootfs paths go deep
# --ignore-failed-read --warning=none  ignore all errors, even if read fails
# --dereference                        follow symlinks
echo "- tar/gzip"
if check_tar_flags; then
  tar -C "$TMP_DIR" --exclude='root-run/run' --exclude='root-run/containerd-user' --ignore-failed-read --warning=none --dereference -czf "$TARBALL_FILE" "$INFO_DIR_SUFFIX"
else
  tar -C "$TMP_DIR" --exclude='root-run/run' --exclude='root-run/containerd-user' --dereference -czf "$TARBALL_FILE" "$INFO_DIR_SUFFIX"
fi
rm -rf "$TMP_DIR"
sync

echo "- done"
echo
echo "EVE info is collected into '$TARBALL_FILE'"

if [ -n "$UPLOAD" ];
then
    echo "Uploading tarball to $UPLOAD"
    curl --retry-all-errors --retry 10 --retry-delay 3 -s -d @"$TARBALL_FILE" -H "Authorization: $AUTHORIZATION" "$UPLOAD/$INFO_DIR_SUFFIX.tar.gz" && \
        rm -f "$TARBALL_FILE"
    echo "Uploading tarball to $UPLOAD done"
fi
