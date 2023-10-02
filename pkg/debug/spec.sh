#!/bin/sh
#shellcheck disable=SC2039
# This script creates an initial hardware model file.
# It should be run on KVM and without having already made some adapters be
# app direct
# The KVM requirement is due to looking at iommu_group and that might be
# bogus under Xen
# Note that the generated USB configuration does not include each USB port
# aka receptacle, since that is not known to software; only the controllers
# can be seen. Those can be manually added after determining which USB controller
# handles the different USB ports.
# Also, the user needs to fill in the jpg links with the photos of the front
# and back of the box.
#
# The script checks for conflicting iommu groups with unknown devices in
# the lspci output; such devices could be memory controllers or anything else
# which would prevent assignment of other devices in that iommu group.
#
# If the -v (verbose) flag is set, then it adds unknown devices in lspci
# as "other" with additional class, vendor, device, and description.
# Note that such output is informative since the resulting json might not be
# accepted by the controller.
#
# Note that handling of wlan and other network interfaces sitting on USB buses
# does not set the correct assignment group.

verbose=
while getopts v o
do      case "$o" in
        v)      verbose=1;;
        [?])    echo "Usage: $0 [-v]"
                exit 1;;
        esac
done
shift $((OPTIND-1))

if [ "$(uname -m)" = x86_64 ]; then
   ARCH=2
else
   ARCH=4
fi

# pci_iommu_group returns the iommu_group, or "" if there is none
# $1 is the PciLong value
# If running on Xen we can't tell the safe groups
pci_iommu_group() {
    local pcilong=$1
    if [ -e /dev/xen ]; then
        echo "warning:no_group_determined_using_xen"
    else
        readlink "/sys/bus/pci/devices/$pcilong/iommu_group" 2>/dev/null | sed 's,.*kernel/iommu_groups/,,'
    fi
}

# get_assignmentgroup returns a guess at the assignment group
# Note that if multiple devices are functions on the same controller
# they are made unassignable, since it is hard to gather the group and
# verify that there are no other functions on that controller
# $1 is the name; $2 is the PciLong value
get_assignmentgroup() {
    local pcilong=$2
    local grp
    grp=$(pci_iommu_group "$pcilong")
    if [ -z "$grp" ]; then
        # Maybe no VT-d support hence not assignable
        echo ""
    elif pci_iommugroup_includes_unknown "${pcilong}" "${grp}"; then
        echo ""
    else
        echo "group${grp}"
    fi
}

# pci_iommugroup_includes_unknown($PCIID, $IOMMUGRPNUM)
# returns whether or not there is some unknown to EVE-OS type of
# device in the group
pci_iommugroup_includes_unknown() {
    local pcilong=$1
    local iommugrpnum=$2
    local grp
    local pci
    local ztype
#shellcheck disable=SC2044
    for a in $(find /sys/kernel/iommu_groups/ -type l); do
        grp=$(echo "${a}" | awk -F/ '{print $5}')
        pci=$(echo "${a}" | awk -F/ '{print $7}')
        [ "${grp}" = "${iommugrpnum}" ] || continue
        [ "${pci}" != "${pcilong}" ] || continue

        # Check if $pci is of unknown type
        ztype=$(pci_to_ztype "$pci")
        if [ "$ztype" = 255 ]; then
            return 0
        fi
    done
    return 1
}

# pci_to_ztype($PCI_ID) returns a numeric ztype
pci_to_ztype() {
    local pci=$1
    if [ -d "/sys/bus/pci/devices/${pci}/net" ]; then
        local ifname
        local ztype
        ifname=$(ls "/sys/bus/pci/devices/${pci}/net")
        ztype=1
        if [ "${ifname:0:4}" = "wlan" ]; then
            ztype=5
        elif [ "${ifname:0:4}" = "wwan" ]; then
            ztype=6
        fi
    elif lspci -D -s "${pci}" | grep -q USB; then
        ztype=2
    elif lspci -D -s "${pci}" | grep -q Audio; then
        ztype=4
    elif lspci -D -s "${pci}" | grep -q VGA; then
        ztype=7
    elif lspci -D -s "${pci}" | grep -q "Non-Volatile memory"; then
        ztype=8
    else
        ztype=255
    fi
    echo "$ztype"
}

# add_pci_info($pci) adds information in the verbose case
add_pci_info() {
    local pci="$1"
    info=$(lspci -Dnmm -s "$pci")
    class=$(echo "$info" | cut -f2 -d\ )
    vendor=$(echo "$info" | cut -f3 -d\ )
    device=$(echo "$info" | cut -f4 -d\ )
    desc=$(lspci -D -s "$pci" | sed "s/$pci //")
    iommu_group=$(pci_iommu_group "$pci")
    cat <<__EOT__
      ,
      "class": ${class},
      "vendor": ${vendor},
      "device": ${device},
      "description": "${desc}",
      "iommu_group": ${iommu_group}
__EOT__
}

get_modem_protocol() {
    local sys_dev="$1"
    local module
    module="$(basename "$(readlink "${sys_dev}/device/driver/module")")" || return 1
    case "$module" in
        "cdc_mbim") echo "mbim"
        ;;
        "qmi_wwan") echo "qmi"
        ;;
        *) return 1
        ;;
    esac
}

get_modem_ifname() {
    local sys_dev="$1"
    ls "${sys_dev}/device/net"
}

get_modem_usbaddr() {
    local sys_dev="$1"
    local dev_path
    dev_path="$(readlink -f "${sys_dev}/device")" || return 1
    while [ -e "$dev_path/subsystem" ]; do
        if [ "$(basename "$(readlink "$dev_path/subsystem")")" != "usb" ]; then
            dev_path="$(dirname "$dev_path")"
            continue
        fi
        basename "$dev_path" | cut -d ":" -f 1 | tr '-' ':'
        return
    done
}

get_modem_pciaddr() {
    local sys_dev="$1"
    local dev_path
    dev_path="$(readlink -f "${sys_dev}/device")" || return 1
    while [ -e "$dev_path/subsystem" ]; do
        if [ "$(basename "$(readlink "$dev_path/subsystem")")" != "pci" ]; then
            dev_path="$(dirname "$dev_path")"
            continue
        fi
        basename "$dev_path"
        return
    done
}

# https://en.wikipedia.org/wiki/Hayes_command_set
# Args: <command> <tty device>
send_at_command() {
    printf "%s\r\n" "$1" | picocom -qrx 2000 -b 9600 "$2"
}

get_modem_ttys() {
    # Convert USB address to <bus>-<port> as used in the /sys filesystem.
    local USB_ADDR
    USB_ADDR="$(echo "$1" | tr ':' '-')"
    find /sys/bus/usb/devices -maxdepth 1 -name "${USB_ADDR}*" |\
        while read -r USB_INTF; do
            find "$(realpath "$USB_INTF")" -maxdepth 1 -name "tty*" -exec basename {} \;
        done
}

get_modem_atport() {
    for TTY in $(get_modem_ttys "$1"); do
        if send_at_command "AT" "/dev/$TTY" 2>/dev/null | grep -q "OK"; then
            echo "/dev/$TTY"
            return
        fi
    done
    return 1
}

if [ -e /dev/xen ]; then
   CPUS=$(eve exec xen-tools xl info | grep nr_cpus | cut -f2 -d:)
   MEM=$(( $(eve exec xen-tools xl info | grep total_memory | cut -f2 -d:) / 1024 ))
else
   CPUS=$(grep -c '^processor.*' < /proc/cpuinfo)
   MEM=$(awk '/MemTotal:/ { print int($2 / 1048576); }' < /proc/meminfo)
fi

DISK=$(lsblk -b  | grep disk | awk '{ total += $4; } END { print int(total/(1024*1024*1024)); }')
WDT=$([ -e /dev/watchdog ] && echo true || echo false)
HSM=$([ -e /dev/tpmrm0 ] && echo 1 || echo 0)

cat <<__EOT__
{
  "arch": $ARCH,
  "productURL": "$(cat /persist/status/hardwaremodel || cat /config/hardwaremodel)",
  "productStatus": "production",
  "attr": {
    "memory": "${MEM}G",
    "storage": "${DISK}G",
    "Cpus": "${CPUS}",
    "watchdog": "${WDT}",
    "hsm": "${HSM}",
    "leds": "0"
  },
  "logo": {
    "logo_back":"/workspace/spec/logo_back_.jpg",
    "logo_front":"/workspace/spec/logo_front_.jpg"
  },
  "ioMemberList": [
__EOT__

#enumerate GPUs
ID=""
for VGA in $(lspci -D  | grep VGA | cut -f1 -d\ ); do
    grp=$(get_assignmentgroup "VGA${ID}" "$VGA")
    cat <<__EOT__
    {
      "ztype": 7,
      "phylabel": "VGA${ID}",
      "assigngrp": "${grp}",
      "phyaddrs": {
        "PciLong": "${VGA}"
      },
      "logicallabel": "VGA${ID}",
      "usagePolicy": {}
__EOT__
    if [ -n "$verbose" ]; then
        add_pci_info "${VGA}"
    fi
    cat <<__EOT__
    },
__EOT__
    ID=$(( ${ID:-0} + 1 ))
done

#enumerate USB
ID=""
for USB in $(lspci -D  | grep USB | cut -f1 -d\ ); do
    grp=$(get_assignmentgroup "USB${ID}" "$USB")
    cat <<__EOT__
    {
      "ztype": 2,
      "phylabel": "USB${ID}",
      "assigngrp": "${grp}",
      "phyaddrs": {
        "PciLong": "${USB}"
      },
      "logicallabel": "USB${ID}",
      "usagePolicy": {}
__EOT__
    if [ -n "$verbose" ]; then
        add_pci_info "${USB}"
    fi
    cat <<__EOT__
    },
__EOT__
    ID=$(( ${ID:-0} + 1 ))
done
if [ -z "$ID" ] && [ "$(lsusb -t | wc -l)" -gt 0 ]; then
cat <<__EOT__
    {
      "ztype": 2,
      "phylabel": "USB",
      "assigngrp": "USB",
      "logicallabel": "USB",
      "usagePolicy": {}
    },
__EOT__
fi

#enumerate NVME
ID=""
for NVME in $(lspci -D  | grep "Non-Volatile memory" | cut -f1 -d\ ); do
    grp=$(get_assignmentgroup "NVME${ID}" "$NVME")
    cat <<__EOT__
    {
      "ztype": 255,
      "phylabel": "NVME${ID}",
      "assigngrp": "${grp}",
      "phyaddrs": {
        "PciLong": "${NVME}"
      },
      "logicallabel": "NVME${ID}",
      "usagePolicy": {}
__EOT__
    if [ -n "$verbose" ]; then
        add_pci_info "${NVME}"
    fi
    cat <<__EOT__
    },
__EOT__
    ID=$(( ${ID:-0} + 1 ))
done

#enumerate serial ports
ID="1"
for TTY in /sys/class/tty/*; do
   if [ -f "$TTY/device/resources" ]; then
      IO=$(grep '^io ' "$TTY/device/resources" | sed -e 's#io 0x##' -e 's#0x##')
      IRQ=$(awk '/^irq /{print $2;}' < "$TTY/device/resources")
   elif [ "$(uname -m)" = aarch64 ] && [ -f "$TTY/irq" ]; then
      IRQ=$(cat "$TTY/irq")
      [ "${IRQ:-0}" -gt 0 ] || IRQ=""
      IO=""
   else
      IO=""
      IRQ=""
   fi
   TTY=$(echo "$TTY" | cut -f5 -d/)
   if [ -n "$IO" ] || [ -n "$IRQ" ]; then
cat <<__EOT__
    {
      "ztype": 3,
      "phylabel": "COM${ID}",
      "assigngrp": "COM${ID}",
      "phyaddrs": {
__EOT__
      if [ -n "$IO" ] && [ -n "$IRQ" ]; then
cat <<__EOT__
        "Ioports": "${IO}",
        "Irq": "${IRQ}",
__EOT__
      fi
cat <<__EOT__
        "Serial": "/dev/${TTY}"
      },
      "logicallabel": "COM${ID}",
      "usagePolicy": {}
    },
__EOT__
     ID=$(( ${ID:-0} + 1 ))
   fi
done

#enumerate cellular modems
ID="0"
for USBDEV in /sys/class/usbmisc/*; do
    get_modem_protocol "$USBDEV" >/dev/null || continue
    IFNAME="$(get_modem_ifname "$USBDEV")"
    MODEMS="${MODEMS}${IFNAME}\n" # skip during NIC enumeration
    USB_ADDR="$(get_modem_usbaddr "$USBDEV")"
    PCI_ADDR="$(get_modem_pciaddr "$USBDEV")"
    GROUP=$(get_assignmentgroup "${IFNAME}" "${PCI_ADDR}")
    cat <<__EOT__
    ${COMMA}
    {
      "ztype": 6,
      "logicallabel": "modem${ID}",
      "phylabel": "modem${ID}",
      "assigngrp": "${GROUP}",
      "phyaddrs": {
        "PciLong": "${PCI_ADDR}",
        "UsbAddr": "${USB_ADDR}"
      },
      "cost": 10,
__EOT__
    if [ -n "$verbose" ] && [ -x "$(command -v picocom)" ]; then
        AT_PORT="$(get_modem_atport "$USB_ADDR")"
        if [ -n "$AT_PORT" ]; then
            # Close any previous communication at this AT port.
            send_at_command "+++" "${AT_PORT}"
            # Return modem identification.
            # Use sed to remove lines containing only whitespace.
            OUTPUT="$(send_at_command "ATI" "${AT_PORT}" | sed '/^\s*$/d')"
            if echo "$OUTPUT" | grep -qv "ERROR"; then
                # Remove control commands.
                OUTPUT="$(echo "$OUTPUT" | sed '/^\s*ATI\s*$/d; /^\s*OK\s*$/d' | tr -d '\r')"
                # Keep at most two lines and join them by semi-colon.
                OUTPUT="$(echo "$OUTPUT" | head -n 2 | sed ':a;N;$!ba;s/\n/; /g')"
                cat <<__EOT__
      "description": "$OUTPUT",
__EOT__
            fi
        fi
    fi
    cat <<__EOT__
      "usagePolicy": {}
__EOT__
    COMMA="},"
    ID=$(( ${ID:-0} + 1 ))
done

#enumerate NICs (except for cellular modems)
for ETH in /sys/class/net/*; do
   LABEL=$(echo "$ETH" | sed -e 's#/sys/class/net/##' -e 's#^k##')
   COST=0
   ZTYPE=1
   if printf "%b" "$MODEMS" | grep -q "^$LABEL$"; then
     # Cellular modems are enumerated separately (see above).
     continue
   fi
   if [ -d "$ETH/wireless" ]; then
       # WiFi
       ZTYPE=5
   fi
   ETH=$(readlink "$ETH")
   if echo "$ETH" | grep -vq '/virtual/'; then
     cat <<__EOT__
    ${COMMA}
    {
      "ztype": ${ZTYPE},
      "usage": 1,
      "phylabel": "${LABEL}",
      "logicallabel": "${LABEL}",
      "usagePolicy": {},
      "cost": ${COST},
__EOT__
     # XXX shouldn't we check if on USB and use the group for the USB controller?
     BUS_ID=$(echo "$ETH" | sed -e 's#/net/.*'"${LABEL}"'##' -e 's#^.*/##')
     if echo "$BUS_ID" | grep -q '[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f].[0-9a-f]'; then
         grp=$(get_assignmentgroup "$LABEL" "$BUS_ID")
         cat <<__EOT__
      "assigngrp": "${grp}",
      "phyaddrs": {
        "Ifname": "${LABEL}",
        "PciLong": "${BUS_ID}"
      }
__EOT__
         if [ -n "$verbose" ]; then
             add_pci_info "${BUS_ID}"
         fi
     else
cat <<__EOT__
      "phyaddrs": {
        "Ifname": "${LABEL}"
      }
__EOT__
     fi
     COMMA="},"
  fi
done

#enumerate Audio
ID=""
for audio in $(lspci -D  | grep Audio | cut -f1 -d\ ); do
    grp=$(get_assignmentgroup "Audio${ID}" "$audio")
    cat <<__EOT__
    ${COMMA}
    {
      "ztype": 4,
      "phylabel": "Audio${ID}",
      "assigngrp": "${grp}",
      "phyaddrs": {
        "PciLong": "${audio}"
      },
      "logicallabel": "Audio${ID}",
      "usagePolicy": {}
__EOT__
    if [ -n "$verbose" ]; then
        add_pci_info "${audio}"
    fi
    ID=$(( ${ID:-0} + 1 ))
    COMMA="},"
done

if [ -n "$verbose" ]; then
    # look for type 255
    ID=0
    for pci in $(lspci -Dn  | cut -f1 -d\ ); do
        ztype=$(pci_to_ztype "$pci")
        [ "$ztype" = 255 ] || continue
        cat <<__EOT__
    ${COMMA}
    {
      "ztype": $ztype,
      "phylabel": "Other${ID}",
      "assigngrp": "",
      "phyaddrs": {
        "PciLong": "${pci}"
      },
      "logicallabel": "Other${ID}",
      "usagePolicy": {}
__EOT__
        add_pci_info "${pci}"
        ID=$(( ${ID:-0} + 1 ))
        COMMA="},"
    done
fi

cat <<__EOT__
    }
  ]
}
__EOT__
