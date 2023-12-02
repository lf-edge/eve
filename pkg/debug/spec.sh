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
usb_devices=
while getopts uv o
do      case "$o" in
        v)      verbose=1;;
        u)      usb_devices=1;;
        [?])    echo "Usage: $0 [-uv]"
                echo "    -u - include USB devices"
                echo "    -v - verbose"
                exit 1;;
        esac
done
shift $((OPTIND-1))

UNAME_M=$(uname -m)

if [ "$UNAME_M" = x86_64 ]; then
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
FIND_IOMMU_GROUPS=$(find /sys/kernel/iommu_groups/ -type l)

pci_iommugroup_includes_unknown() {
    local pcilong=$1
    local iommugrpnum=$2
    local grp
    local pci
    local ztype
#shellcheck disable=SC2044
    for a in $FIND_IOMMU_GROUPS; do
        oldIFS=$IFS
        IFS="/";# read -a arr <<<"$a"
        set -- "$a"
        grp=$5
        pci=$7
        IFS=$oldIFS
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
    lspci_ds=$(lspci -D -s "$pci")

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
    elif echo "$lspci_ds" | grep -q USB; then
        ztype=2
    elif echo "$lspci_ds" | grep -q Audio; then
        ztype=4
    elif echo "$lspci_ds" | grep -q VGA; then
        ztype=7
    elif echo "$lspci_ds" | grep -q "Non-Volatile memory"; then
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

if [ -e /dev/xen ]; then
   CPUS=$(eve exec xen-tools xl info | grep nr_cpus | cut -f2 -d:)
   MEM=$(( $(eve exec xen-tools xl info | grep total_memory | cut -f2 -d:) ))
else
   CPUS=$(grep -c '^processor.*' < /proc/cpuinfo)
   MEM=$(awk '/MemTotal:/ { print int($2 / 1024); }' < /proc/meminfo)
fi

DISK=$(lsblk -b -o NAME,TYPE,TRAN,SIZE | grep disk | grep -v usb | awk '{ total += $4; } END { print int(total/(1024*1024*1024)); }')
WDT=$([ -e /dev/watchdog ] && echo true || echo false)
HSM=$([ -e /dev/tpmrm0 ] && echo 1 || echo 0)

add_description() {
    DEVICE_TYPE="$1"
    if [ -n "$verbose" ]; then
        desc=$(lspci -Ds "${DEVICE_TYPE}")
        desc="${desc#*: }"
            cat <<__EOT__
      "description": ${desc},
__EOT__
    fi
}

LSPCI_D=$(lspci -D)
cat <<__EOT__
{
  "arch": $ARCH,
  "productURL": "$(cat /persist/status/hardwaremodel || cat /config/hardwaremodel)",
  "productStatus": "production",
  "attr": {
    "memory": "${MEM}M",
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
for VGA in $(echo "$LSPCI_D" | grep VGA | cut -f1 -d\ ); do
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
__EOT__
    add_description "${VGA}"
    cat <<__EOT__
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

#enumerate USB controller
print_usb_controllers() {
    ID=""
    for USB in $(echo "$LSPCI_D" | grep USB | cut -f1 -d\ ); do
        grp="group$(pci_iommu_group "$USB")"
        cat <<__EOT__
    {
      "ztype": 2,
      "phylabel": "USB${ID}",
      "assigngrp": "${grp}",
      "phyaddrs": {
        "PciLong": "${USB}"
      },
      "logicallabel": "USB${ID}",
__EOT__
    add_description "${USB}"
    cat <<__EOT__
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
__EOT__
    add_description "${USB}"
    cat <<__EOT__
      "usagePolicy": {}
    },
__EOT__
    fi
}

#enumerate USB devices
#if $1 is "1" then only nics/modems will be printed
print_usb_devices() {
    netdevpaths=""
    local only_nics="$1"

    # some usb network cards might not have their module included into the eve kernel
    # this results into not detecting the network card and therefore allowing
    # passthrough of the device into an edge application
    # fortunately this is not a problem as we currently disallow the passthrough of
    # usb networking devices in order to not confuse pillar daemon
    # no kernel module -> pillar does not get confused -> passthrough of the device is okay
    for i in /sys/class/net/*
    do
        i=$(basename "$i")
        local devicepath
        devicepath=$(realpath "/sys/class/net/$i/../../")
        local isUSB
        isUSB=$(echo "$devicepath" | grep -Eo '/usb[0-9]/' || true)

        if [ "$isUSB" = "" ];
        then
            continue
        fi
        local netdevpaths="$netdevpaths $devicepath"
    done

    for i in $(find /sys/devices/ -name uevent | grep -E '/usb[0-9]/' | grep -E '/[0-9]-[0-9](\.[0-9]+)?/uevent')
    do
        local ztype="IO_TYPE_UNSPECIFIED"
        local ignore_dev=0
        local devicepath
        devicepath=$(dirname "$i")
        local busAndPort
        busAndPort=$(echo "$i" | grep -Eo '/[0-9]-[0-9](\.[0-9]+)?/uevent' | grep -Eo '[0-9]-[0-9](\.[0-9]+)?')
        local assigngrp
        assigngrp="USB${busAndPort}"

        local bus
        bus=$(echo "${busAndPort}" | cut -d - -f1)
        local port
        port=$(echo "${busAndPort}" | cut -d - -f2)
        local usbaddr="$bus:$port"

        local ifname
        ifname="$(ls -1 "${devicepath}/*/net" 2>/dev/null || true)"
        local cost=0
        local is_nic
        is_nic=$(grep -Eo 'cdc_mbim|qmi_wwan' "${devicepath}"/*/uevent 2>/dev/null)
        if [ "${is_nic}" != "" ]
        then
            cost=10
            assigngrp="modem${busAndPort}"
            assigngrp=$(get_assignmentgroup "${ifname}" "${pciaddr}")
            ztype="IO_TYPE_WWAN"
        fi

        local pciaddr
        pciaddr=$(echo "$i" | grep -Eo '/pci[^/]+/[^/]+/usb' | cut -d / -f3)
        local parentassigngrp
        parentassigngrp="group$(pci_iommu_group "${pciaddr}")"
        if [ "$parentassigngrp" = "group" ]
        then
            parentassigngrp=""
        fi
        local label
        idVendor=$(cat "${devicepath}/idVendor")
        idProduct=$(cat "${devicepath}/idProduct")
        label="USB-${idVendor}:${idProduct}-${busAndPort}"

        type=$(grep -Eo '^TYPE=[0-9]+/' "$i"| grep -Eo '[0-9]+')
        # ignore USB hubs
        if [ "$type" = "9" ];
        then
            ignore_dev=1
        fi

        if [ "${is_nic}" = "" ]
        then
            for netdevpath in $netdevpaths
            do
                # check if devicepath starts with netdevpath
                case $netdevpath in "$devicepath"*)
                    netdevname=$(find "${netdevpath}"/net/* -prune -exec basename "{}" \; | head -n1)
                    if [ "$netdevname" != "" ]
                    then
                        label=$netdevname
                    fi
                    is_nic=1
                    ztype="IO_TYPE_ETH"
                esac
            done
        fi

        if [ "$only_nics" = 1 ] && [ "${is_nic}" = "" ]
        then
            ignore_dev=1
        fi

        if [ "$ignore_dev" = "1" ]
        then
            continue
        fi

        cat <<__EOT__
    {
      "ztype": "${ztype}",
      "phylabel": "${label}",
      "assigngrp": "${assigngrp}",
      "cost": ${cost},
      "phyaddrs": {
        "usbaddr": "$usbaddr"
      },
      "logicallabel": "$label",
      "usagePolicy": {}
    },
__EOT__
    done
}

if [ "$usb_devices" = "1" ]
then
    print_usb_devices
else
    print_usb_controllers
    print_usb_devices 1
fi

#enumerate NVME
ID=""
for NVME in $(echo "$LSPCI_D" | grep "Non-Volatile memory" | cut -f1 -d\ ); do
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
__EOT__
    add_description "${NVME}"
    cat <<__EOT__
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
   elif [ "$UNAME_M" = aarch64 ] && [ -f "$TTY/irq" ]; then
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

#enumerate NICs (ignoring USB devices)
for ETH in /sys/class/net/*; do
   LABEL=$(echo "$ETH" | sed -e 's#/sys/class/net/##' -e 's#^k##')
   # Does $LABEL start with wlan or wwan? Change ztype and cost
   COST=0
   ZTYPE=1
   isUSB=$(readlink "$ETH" | grep -Eo '/usb[0-9]/' || true)
   if [ "$isUSB" != "" ]
   then
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
__EOT__
    BUS_ID=$(echo "$ETH" | sed -e 's#/net/.*'"${LABEL}"'##' -e 's#^.*/##')
    if echo "${BUS_ID}" | grep -q "virtio"; then
        PCI_ADDR=$(echo "$ETH" | sed -e 's#/'"${BUS_ID}"'/.*##' -e 's#^.*/##')
        add_description "${PCI_ADDR}"
    else
        add_description "${BUS_ID}"
    fi
    cat <<__EOT__
      "usagePolicy": {},
      "cost": ${COST},
__EOT__
     # XXX shouldn't we check if on USB and use the group for the USB controller?
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
for audio in $(echo "$LSPCI_D" | grep Audio | cut -f1 -d\ ); do
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
__EOT__
    add_description "${audio}"
    cat <<__EOT__
      "usagePolicy": {}
__EOT__
    if [ -n "$verbose" ]; then
        add_pci_info "${audio}"
    fi
    ID=$(( ${ID:-0} + 1 ))
    COMMA="},"
done

LSPCI_DN=$(lspci -Dn)
if [ -n "$verbose" ]; then
    # look for type 255
    ID=0
    for pci in $(echo "$LSPCI_DN"  | cut -f1 -d\ ); do
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
__EOT__
    add_description "${pci}"
    cat <<__EOT__
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
