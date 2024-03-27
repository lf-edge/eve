#!/bin/sh
#
# This script is used to collect all info from the machine which
# helps to debug and resolve EVE issues.
#

# Script version, don't forget to bump up once something is changed

VERSION=18
# Add required packages here, it will be passed to "apk add".
# Once something added here don't forget to add the same package
# to the Dockerfile ('ENV PKGS' line) of the debug container,
# because we don't want to fail in case of network problems, on
# the other hand we want to support old versions of EVE, so we
# still attempt to install those packages.
PKG_DEPS="procps tar dmidecode iptables dhcpcd"

DATE=$(date "+%Y-%m-%d-%H-%M-%S")
INFO_DIR="eve-info-v$VERSION-$DATE"
TARBALL_FILE="/persist/$INFO_DIR.tar.gz"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

READ_LOGS_DEV=
READ_LOGS_APP=

usage()
{
    echo "Usage: collect-info.sh [-v] [-h] [-a APPLICATION-UUID] [-d]"
    echo "       -h   show this help"
    echo "       -v   show the script version"
    echo ""
    echo "Read-logs mode:"
    echo "       -d                   - read device logs only"
    echo "       -a APPLICATION-UUID  - read specified application logs only"
    exit 1
}

while getopts "vha:d" o; do
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
        d)
            READ_LOGS_DEV=1
            ;;
        :)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

sort_cat_jq()
{
    # Sort and extract a filename
    sort -n | awk '{print $2}' | \
    # Decompress if needed and output
    xargs --no-run-if-empty zcat -f | \
    # Add a new JSON entry "timestamp.str" which represents timestamp
    # in a human readable `strftime` format: "%B %d %Y %I:%M:%S.%f".
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
    jq -R '(. as $line | try fromjson) | .timestamp.str.nanos = ((.timestamp.nanos // 0) + 1e9 | tostring | .[1:]) | .timestamp.str.human = (.timestamp.seconds | strftime("%B %d %Y %I:%M:%S")) | .timestamp.str = "\(.timestamp.str.human).\(.timestamp.str.nanos)"'
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

# Create temporary dir
echo "- basic setup"
TMP_DIR=$(mktemp -d)
DIR="$TMP_DIR/$INFO_DIR"
mkdir -p "$DIR"
mkdir -p "$DIR/network"

# Check for internet access, timeouts at 30 seconds,
# If there is internet access, install required GNU utilities and networking tools.
if nc -z -w 30 dl-cdn.alpinelinux.org 443 2>/dev/null; then
  echo "- install GNU utilities and networking tools"
  # shellcheck disable=SC2086
  apk add $PKG_DEPS >/dev/null 2>&1
fi

collect_network_info()
{
    echo "- network info"
    echo "   - ifconfig, ip, arp, netstat, iptables"
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
    echo "- pillar backtraces"
    logread -f > "$DIR/pillar-backtraces" &
    pid=$!

    echo "  - pkill -USR1 /opt/zededa/bin/zedbox"
    eve exec pillar pkill -USR1 /opt/zededa/bin/zedbox

    iters=15
    echo "  - wait for pillar backtraces"
    until grep -q "sigusr" "$DIR/pillar-backtraces"; do
        sleep 1s
        if [ $iters -eq 0 ]; then
            echo "      ERR: timeout! exit wait"
            break
        fi
        iters=$((iters - 1))
    done

    # To be sure all backtraces are written
    sleep 1s

    kill $pid

    echo "- done pillar backtraces"
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

ln -s /persist/status       "$DIR/persist-status"
ln -s /persist/log          "$DIR/persist-log"
ln -s /persist/newlog       "$DIR/persist-newlog"
ln -s /persist/netdump      "$DIR/persist-netdump"
ln -s /persist/kcrashes     "$DIR/persist-kcrashes"
ln -s /run                  "$DIR/root-run"
cp -r /sys/fs/cgroup/memory "$DIR/sys-fs-cgroup-memory" >/dev/null 2>&1
[ -f /persist/SMART_details.json ] && ln -s /persist/SMART_details* "$DIR/"

# Network part
collect_network_info

# Pillar part
collect_pillar_backtraces

# ZFS part
collect_zfs_info

# Kube part
collect_kube_info

check_tar_flags() {
  tar --version | grep -q "GNU tar"
}


# Make a tarball
# --exlude='root-run/run'              /run/run/run/.. exclude symbolic link loop
# --exclude='root-run/containerd-user'  the k8s.io/*/rootfs paths go deep
# --ignore-failed-read --warning=none  ignore all errors, even if read fails
# --dereference                        follow symlinks
echo "- tar/gzip"
if check_tar_flags; then
  tar -C "$TMP_DIR" --exclude='root-run/run' --exclude='root-run/containerd-user' --ignore-failed-read --warning=none --dereference -czf "$TARBALL_FILE" "$INFO_DIR"
else
  tar -C "$TMP_DIR" --exclude='root-run/run' --exclude='root-run/containerd-user' --dereference -czf "$TARBALL_FILE" "$INFO_DIR"
fi
rm -rf "$TMP_DIR"
sync

echo "- done"
echo
echo "EVE info is collected '$TARBALL_FILE'"
