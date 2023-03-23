#!/bin/sh
#
# Output the PCI devices grouped by the IOMMU
#

for d in /sys/kernel/iommu_groups/*/devices/*; do
    if [ ! -e "$d" ]; then
        continue
    fi
    n="${d#*/iommu_groups/*}"
    n="${n%%/*}"
    printf 'IOMMU Group %s \n--------------\n' "$n"
    lspci -vmms "${d##*/}" | grep -E "^Slot|^Class|^Vendor|^Device"
    printf 'IDs:    '
    lspci -ns "${d##*/}" | awk {print\ \$3}
    lspci -vmms "${d##*/}" | grep -E "^Rev"
    printf '\n'
done
