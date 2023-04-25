#!/bin/sh
#
# This script is used to collect all info from the machine which
# helps to debug and resolve EVE issues.
#

# Script version, don't forget to bump up once something is changed
VERSION=4

DATE=$(date -Is)
INFO_DIR="eve-info-v$VERSION-$DATE"
TARBALL_FILE="/persist/$INFO_DIR.tar.gz"

usage()
{
    echo "Usage: collect-info.sh [-v] [-h]"
    echo "       -h   show this help"
    echo "       -v   show the script version"
    exit 1
}

while getopts "vh" o; do
    case "$o" in
        h)
            usage
            ;;
        v)
            echo "v$VERSION"
            exit 0
            ;;
        :)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

# Create temporary dir
echo "- basic setup"
TMP_DIR=$(mktemp -d)
DIR="$TMP_DIR/$INFO_DIR"
mkdir -p "$DIR"
mkdir -p "$DIR/network"

# Install GNU version of the 'ps', 'tar' and other tools
echo "- install GNU tools"
apk add procps tar dmidecode >/dev/null 2>&1

collect_network_info()
{
    echo "- network info"

    # Install missing tools
    echo "   - install networking GNU tools"
    apk add iptables dhcpcd >/dev/null 2>&1

    echo "   - ifconfig, ip, arp, netstat, iptables"
    ifconfig       > "$DIR/network/ifconfig"
    ip -s link     > "$DIR/network/ip-s-link"
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

# Copy itself
cp "${0}" "$DIR"

# Have to chroot, lsusb does not work from this container
echo "- lsusb, dmesg, ps, lspci, lsblk, lshw, lsof, lsmod, logread, dmidecode"
chroot /hostfs lsusb -vvv    > "$DIR/lsusb-vvv"
chroot /hostfs lsusb -vvv -t > "$DIR/lsusb-vvv-t"

dmesg         > "$DIR/dmesg"
ps -ef        > "$DIR/ps-ef"
lspci -vvv    > "$DIR/lspci-vvv"
lspci -vvv -t > "$DIR/lspci-vvv-t"
lsblk -a      > "$DIR/lsblk-a"
lshw          > "$DIR/lshw"
lsof          > "$DIR/lsof"
lsmod         > "$DIR/lsmod"
logread       > "$DIR/logread"
dmidecode     > "$DIR/dmidecode"

echo "- vmallocinfo, slabinfo, zoneinfo, mounts, vmstat, cpuinfo"
cat /proc/vmallocinfo > "$DIR/vmallocinfo"
cat /proc/slabinfo    > "$DIR/slabinfo"
cat /proc/zoneinfo    > "$DIR/zoneinfo"
cat /proc/mounts      > "$DIR/mounts"
cat /proc/vmstat      > "$DIR/vmstat"
cat /proc/cpuinfo     > "$DIR/cpuinfo"

echo "- qemu affinities"
qemu-affinities.sh    > "$DIR/qemu-affinities"

echo "- iommu groups"
iommu-groups.sh       > "$DIR/iommu-groups"

echo "- TPM event log"
find /sys/kernel/security -name "tpm*" | while read -r TPM; do
    if [ -f "$TPM/binary_bios_measurements" ]; then
        TPM_LOG="$(basename "$TPM").event_log"
        ln -s "$TPM/binary_bios_measurements" "$DIR/$TPM_LOG"
    fi
done

ln -s /persist/status   "$DIR/persist-status"
ln -s /persist/log      "$DIR/persist-log"
ln -s /persist/newlog   "$DIR/persist-newlog"
ln -s /persist/netdump  "$DIR/persist-netdump"
ln -s /persist/kcrashes "$DIR/persist-kcrashes"
ln -s /run              "$DIR/root-run"

# Network part
collect_network_info

# Pillar part
collect_pillar_backtraces

# Make a tarball
# --exlude='root-run/run'              /run/run/run/.. exclude symbolic link loop
# --ignore-failed-read --warning=none  ignore all errors, even if read fails
# --dereference                        follow symlinks
echo "- tar/gzip"
tar -C "$TMP_DIR" --exclude='root-run/run' --ignore-failed-read --warning=none --dereference -czf "$TARBALL_FILE" "$INFO_DIR"
rm -rf "$TMP_DIR"
sync

echo "- done"
echo
echo "EVE info is collected '$TARBALL_FILE'"
