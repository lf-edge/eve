#!/bin/sh

# Generate a parallels compatible disk with XML format.
# https://github.com/qemu/qemu/blob/595123df1d54ed8fbab9e1a73d5a58c5bb71058f/docs/interop/prl-xml.txt

LIVE=$1
SNAPSHOT_UUID=$2
DISK_VIRTUAL_SIZE_BYTES=$3

cat > "${LIVE}".parallels/DiskDescriptor.xml <<EOF
<?xml version='1.0' encoding='UTF-8'?>
<Parallels_disk_image Version="1.0">
    <Disk_Parameters>
        <Disk_size>$((DISK_VIRTUAL_SIZE_BYTES / 16 / 32))</Disk_size>
        <Cylinders>$((DISK_VIRTUAL_SIZE_BYTES / 16 / 32 / 512))</Cylinders>
        <PhysicalSectorSize>512</PhysicalSectorSize>
        <Heads>16</Heads>
        <Sectors>32</Sectors>
        <Padding>0</Padding>
        <Encryption>
            <Engine>{00000000-0000-0000-0000-000000000000}</Engine>
            <Data></Data>
        </Encryption>
        <UID>{$(uuidgen)}</UID>
        <Name>eve</Name>
        <Miscellaneous>
            <CompatLevel>level2</CompatLevel>
            <Bootable>1</Bootable>
            <SuspendState>0</SuspendState>
        </Miscellaneous>
    </Disk_Parameters>
    <StorageData>
        <Storage>
            <Start>0</Start>
            <End>$((DISK_VIRTUAL_SIZE_BYTES / 16 / 32))</End>
            <Blocksize>2048</Blocksize>
            <Image>
                <GUID>${SNAPSHOT_UUID}</GUID>
                <Type>Compressed</Type>
                <File>live.0.${SNAPSHOT_UUID}.hds</File>
            </Image>
        </Storage>
    </StorageData>
    <Snapshots>
        <Shot>
            <GUID>${SNAPSHOT_UUID}</GUID>
            <ParentGUID>{00000000-0000-0000-0000-000000000000}</ParentGUID>
        </Shot>
    </Snapshots>
</Parallels_disk_image>
EOF