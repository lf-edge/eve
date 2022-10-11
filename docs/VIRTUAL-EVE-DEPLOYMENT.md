# Deploying EVE-OS in virtual environments

The main target for EVE-OS deployment is on bare metal at the distributed edge rather as a virtual machine on top of another virtualization platform. However, virtualization platforms are good alternatives for testing purposes especially when bare metal hardware is not available.

As per the [deployment](DEPLOYMENT.md) document, EVE-OS is known to run under:

* [qemu](https://www.qemu.org/)
* [VirtualBox](https://www.virtualbox.org/)
* [Parallels](https://www.parallels.com/)
* [VMware Fusion](https://www.vmware.com/products/fusion.html)
* [VMware Workstation Player](https://www.vmware.com/products/workstation-player.html)
* [VMware Workstation Pro](https://www.vmware.com/products/workstation-pro.html)
* [Google Cloud Platform (GCP) Compute Engine](https://cloud.google.com/compute)

> **_NOTE:_** In order to deploy applications into the EVE-OS VM, the virtualization platform will need to have nested virtualization enabled

This document will cover some important notes and instructions for running EVE-OS on x86 architectures for the following virtualization platforms:
1. [VirtualBox and VMware](#deploying-in-virtualbox-and-vmware)
2. [GCP Compute Engine](#deploying-in-gcp)

## Deploying in VirtualBox and VMware

Prerequisites for deploying EVE-OS in a virtual machine are as follows:
1. Host systems that run AMD and Intel CPUs with nested virtualization support
2. EFI-compatible virtualization platform
3. A machine with [docker](https://docs.docker.com/engine/install/) installed to generate EVE-OS installer ISO image

Follow these steps to create EVE-OS as a virtual machine:
1. Create an EVE-OS installer ISO image: ```docker run lfedge/eve:<eve-os-version>-kvm-amd64 installer_iso > installer.iso``` 
2. Create a Linux VM (Other Linux 64-bit) for EVE-OS VM the with desired CPU, memory and disk
3. Set firmware of the VM to **EFI**
4. Attach EVE-OS **installer.iso** ISO image to virtual optical/DVD drive
5. Change boot order and set DVD drive to boot first
6. Power on EVE-OS VM and let the installer runs. At the end of its run, the installer process will shut down the EVE-OS VM
7. Detach installer.iso ISO image from the virtual optical/DVD drive
8. Power on EVE-OS VM, perform VM console and retrieve serial number from /config/soft_serial to onboard EVE-OS VM to controller: ```cat /config/soft_serial```


#### Notes on EFI Firmware

The VM for EVE-OS must have the firmware set to **EFI** in order to boot the ISO installer image. In VirtualBox, firmware settings can be changed from the User Interface or the VBoxManage command line: ```VBoxManage modifyvm [vm-name] --firmware efi```. In VMware (e.g., Fusion, Workstation), you can edit the .vmx file and add the line: ```firmware = "efi"``` or in some version the firmware setting is available under the *Advanced Option*.

References:
* [Alternative Firmware (EFI) in VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/6.0/user/efi.html)
* [Configure a Firmware Type in VMware Workstation Pro](https://docs.vmware.com/en/VMware-Workstation-Pro/16.0/com.vmware.ws.using.doc/GUID-064517C9-14D6-4C87-8D2C-2856EFAE88EB.html)

####Sample VBoxManage script to create an EVE-OS VM
```sh
VBoxManage createvm --name [vm-name] --ostype Linux_64 --register
VBoxManage modifyvm [vm-name] --cpus [cpucount] --memory [memorysize] --nic1 nat --nic1 nat --hwvirtex on --vtxvpid on --vtxux on --firmware efi --nested-hw-virt on
VBoxManage createhd --filename "[path]\[disk-name].vdi" --size [size in MiB units] --format VDI
VBoxManage storagectl [vm-name] --name "SATA Controller" --add sata --controller IntelAhci
VBoxManage storageattach [vm-name] --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "[path]\[disk-name].vdi"
VBoxManage storageattach [vm-name] --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "[path]\installer.iso"
VBoxManage modifyvm [vm-name] --boot1 dvd --boot2 disk --boot3 none --boot4 none
VBoxManage startvm [vm-name]
```

**Sample VBoxManage script to detach installer.iso and then power the EVE-OS VM back on**
* Detach installer iso: ```VBoxManage storageattach [vm-name] --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium none```
* Start EVE-OS VM: ```VBoxManage startvm [vm-name]```

#### Sample VirtualBox .xml file
```xml
<?xml version="1.0"?>
<VirtualBox xmlns="http://www.virtualbox.org/" version="1.16-windows">
  <Machine uuid="{9c681c2a-6f9a-48b6-abe9-2db70dc91d3a}" name="eve-vm1" OSType="Linux_64" snapshotFolder="Snapshots" lastStateChange="2022-10-08T22:24:05Z">
    <MediaRegistry>
      <HardDisks>
        <HardDisk uuid="{740633ea-8c64-40ca-b02c-30d3df15ea27}" location="eve-vm1_DISK.vdi" format="VDI" type="Normal"/>
      </HardDisks>
      <DVDImages>
        <Image uuid="{4ac79c7d-feea-4f98-aafb-393676e7ddc4}" location="installer.iso"/>
      </DVDImages>
    </MediaRegistry>
    <ExtraData>
      <ExtraDataItem name="GUI/LastCloseAction" value="PowerOff"/>
      <ExtraDataItem name="GUI/LastNormalWindowPosition" value="826,94,1024,819"/>
    </ExtraData>
    <Hardware>
      <CPU count="2">
        <PAE enabled="true"/>
        <LongMode enabled="true"/>
        <X2APIC enabled="true"/>
        <HardwareVirtExLargePages enabled="true"/>
      </CPU>
      <Memory RAMSize="1024"/>
      <Firmware type="EFI"/>
      <Boot>
        <Order position="1" device="DVD"/>
        <Order position="2" device="HardDisk"/>
        <Order position="3" device="None"/>
        <Order position="4" device="None"/>
      </Boot>
      <BIOS>
        <IOAPIC enabled="true"/>
        <SmbiosUuidLittleEndian enabled="true"/>
      </BIOS>
      <Network>
        <Adapter slot="0" enabled="true" MACAddress="080027C08E7C" type="82540EM">
          <NAT/>
        </Adapter>
      </Network>
      <AudioAdapter driver="DirectSound" enabled="true" enabledIn="false" enabledOut="false"/>
      <Clipboard/>
      <GuestProperties>
        <GuestProperty name="/VirtualBox/HostInfo/GUI/LanguageID" value="en_US" timestamp="1665267845949658700" flags="RDONLYGUEST"/>
      </GuestProperties>
    </Hardware>
    <StorageControllers>
      <StorageController name="IDE Controller" type="PIIX4" PortCount="2" useHostIOCache="true" Bootable="true">
        <AttachedDevice type="HardDisk" hotpluggable="false" port="0" device="0">
          <Image uuid="{740633ea-8c64-40ca-b02c-30d3df15ea27}"/>
        </AttachedDevice>
        <AttachedDevice passthrough="false" type="DVD" hotpluggable="false" port="1" device="0">
          <Image uuid="{4ac79c7d-feea-4f98-aafb-393676e7ddc4}"/>
        </AttachedDevice>
      </StorageController>
    </StorageControllers>
  </Machine>
</VirtualBox>
```

#### Sample VMware .vmx file
```sh
.encoding = "windows-1252"
firmware = "efi"
config.version = "8"
virtualHW.version = "19"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
nvram = "eve-1.nvram"
virtualHW.productCompatibility = "hosted"
gui.exitOnCLIHLT = "FALSE"
powerType.powerOff = "soft"
powerType.powerOn = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"
displayName = "eve-1"
usb.vbluetooth.startConnected = "TRUE"
vvtd.enable = "TRUE"
guestOS = "other26xlinux-64"
vhv.enable = "TRUE"
vpmc.enable = "TRUE"
tools.syncTime = "FALSE"
sound.autoDetect = "TRUE"
sound.fileName = "-1"
sound.present = "TRUE"
vcpu.hotadd = "TRUE"
memsize = "6144"
mem.hotadd = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0.present = "TRUE"
scsi0:0.fileName = "eve-1.vmdk"
scsi0:0.present = "TRUE"
ide1:0.deviceType = "cdrom-raw"
ide1:0.fileName = "auto detect"
ide1:0.present = "TRUE"
usb.present = "TRUE"
ehci.present = "TRUE"
ethernet1.connectionType = "hostonly"
ethernet1.addressType = "generated"
ethernet1.virtualDev = "e1000"
ethernet2.connectionType = "hostonly"
ethernet2.addressType = "generated"
ethernet2.virtualDev = "e1000"
ethernet0.addressType = "generated"
ethernet0.virtualDev = "e1000"
serial0.fileType = "thinprint"
serial0.fileName = "thinprint"
ethernet1.present = "TRUE"
ethernet2.present = "TRUE"
ethernet0.present = "TRUE"
serial0.present = "TRUE"
extendedConfigFile = "eve-1.vmxf"
floppy0.present = "FALSE"
uuid.bios = "56 4d 89 e6 b3 6d 8f 4b-ec 83 0e e1 92 7c bf 81"
uuid.location = "56 4d 89 e6 b3 6d 8f 4b-ec 83 0e e1 92 7c bf 81"
scsi0:0.redo = ""
pciBridge0.pciSlotNumber = "17"
pciBridge4.pciSlotNumber = "21"
pciBridge5.pciSlotNumber = "22"
pciBridge6.pciSlotNumber = "23"
pciBridge7.pciSlotNumber = "24"
scsi0.pciSlotNumber = "16"
usb.pciSlotNumber = "32"
ethernet0.pciSlotNumber = "33"
ethernet1.pciSlotNumber = "34"
ethernet2.pciSlotNumber = "35"
sound.pciSlotNumber = "36"
ehci.pciSlotNumber = "37"
svga.vramSize = "268435456"
vmotion.checkpointFBSize = "134217728"
vmotion.checkpointSVGAPrimarySize = "268435456"
vmotion.svga.mobMaxSize = "268435456"
vmotion.svga.graphicsMemoryKB = "262144"
ethernet0.generatedAddress = "00:0c:29:7c:bf:81"
ethernet0.generatedAddressOffset = "0"
ethernet1.generatedAddress = "00:0c:29:7c:bf:8b"
ethernet1.generatedAddressOffset = "10"
ethernet2.generatedAddress = "00:0c:29:7c:bf:95"
ethernet2.generatedAddressOffset = "20"
vmci0.id = "-1837318271"
monitor.phys_bits_used = "45"
cleanShutdown = "TRUE"
softPowerOff = "FALSE"
usb:1.speed = "2"
usb:1.present = "TRUE"
usb:1.deviceType = "hub"
usb:1.port = "1"
usb:1.parent = "-1"
ide1:0.autodetect = "TRUE"
usb:0.present = "TRUE"
usb:0.deviceType = "hid"
usb:0.port = "0"
usb:0.parent = "-1"
ide1:0.startConnected = "FALSE"
tools.remindInstall = "TRUE"
```

## Deploying in GCP

Prerequisites for deploying EVE-OS in GCP Compute Engine VM instance are as follows:
1. A [Google Account](https://www.google.com/accounts/NewAccount) 
2. Access to [GCP Compute Engine](https://cloud.google.com/compute)
3. Access to [GCP Cloud Storage](https://cloud.google.com/storage)
4. A machine with [docker](https://docs.docker.com/engine/install/) installed (alternatively, you can also run a virtual machine with docker installed in GCP Compute Engine).
5. A machine with [Google Cloud CLI](https://cloud.google.com/sdk/docs/install-sdk) [Optional]

Follow these steps to create EVE-OS in GCP:
1. Create EVE-OS gcp live image using docker and pipe out to a ```.tar.gz``` file: ```docker run lfedge/eve:<eve-os-version>-kvm-amd64 -f gcp live > <image-filename>.tar.gz```
2. [Create a GCP Cloud Storage Bucket](https://cloud.google.com/storage/docs/creating-buckets) (Optional if there is no existing one)
3. Upload the ```<image-filename>.tar.gz``` to a GCP Cloud Storage Bucket
4. Create a custom image in GCP Compute Engine with **Cloud Storage file** as the **Source** using the uploaded image file.
5. Once the custom image is ready, [create a GCP VM instance](https://cloud.google.com/compute/docs/instances/create-start-instance) with [nested-virtualization enabled](https://cloud.google.com/compute/docs/instances/nested-virtualization/enabling) using the image. *Note: Enabling nested-virtualization can only be done via API / gcloud cli*
6. Serial console to the VM to get the soft serial and onboard EVE-OS to controller using the soft serial: ```cat /config/soft_serial```


#### Sample script for GCP

The following is a sample script leveraging docker and Google Cloud CLI to generate gcp image, upload image to storage bucket, and create a VM for EVE-OS with the uploaded image

```sh
docker run lfedge/eve:8.11.0-kvm-amd64 -f gcp live > <image-filename>.tar.gz
gsutil cp <image-filename>.tar.gz gs://<gcp-storage-bucket-name>/<image-filename>.tar.gz
gcloud compute images create <gcp-image-name> --source-uri gs://<gcp-storage-bucket-name>/<image-filename>.tar.gz --guest-os-features=UEFI_COMPATIBLE
gcloud compute project-info add-metadata --metadata serial-port-enable=TRUE
gcloud compute instances create <eve-vm-name> --project=<projectid> --zone=<zone> --machine-type=n2-standard-4 --network-interface=network-tier=STANDARD,subnet=<subnet-name> --can-ip-forward --provisioning-model=STANDARD --image eve-os-image --enable-nested-virtualization --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```

#### Deploying EVE-OS in GCP using Terraform

Following are some sample Terraform modules to facilitate deploying EVE-OS in GCP

Sample terraform module to generate gcp image and upload to gcp storage bucket:
https://registry.terraform.io/modules/bayupw/eve-gcp-image/google/latest?tab=readme

Sample module to run eve as GCP VM, can call the gcp-image module or use existing image:
https://registry.terraform.io/modules/bayupw/eve-vm/google/latest?tab=readme
