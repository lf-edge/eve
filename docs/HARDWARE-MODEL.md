# Hardware model description and testing

The initial steps of bringing up EVE-OS on a new hardware model are described in [HARDWARE-BRINGUP](./HARDWARE-BRINGUP.md), and the necessary BIOS support and setup in [BIOS-FIRMWARE](./BIOS-FIRMWARE.md).

In order for the controller and EVE-OS to assign resources like memory and I/O devices each hardware device it needs a model file, hence such a file needs to be created and validated/tested that it corresponds to the hardware.

Finally there is a need to test other hardware aspects such as the hardware watchdog timer and LED/LCD with EVE-OS.

## Model description files

The model files are kept in [eden/models](https://github.com/lf-edge/eden/tree/master/models) and are composed of several parts:

- General description including a product URL
- Attributes for CPU cores, memory, storage, TPM, etc
- Front and back images
- I/O adapters

### Product URL

This is supposed to be a URL which identifies the model in sufficient detail that someone else can order it and EVE will run the same.

### Front and back images

The purposes of these images is to create a binding between the physical ports on the device and the names used in the model file. In some cases the device enclosure has unique names printed next to each port, and in other cases it is useful to annotate the image with unique names. And example of the former is [logo_nacl_MOXA-1200](https://github.com/lf-edge/eden/blob/master/models/logo_back_MOXA-1200.jpg) and an example of the latter is [logo_back_MBI-6418A-T7H](https://github.com/lf-edge/eden/blob/master/models/logo_back_MBI-6418A-T7H.jpg).

### I/O Adapters

The purpose of the I/O adapters section is to describe the networking ports which can be used by EVE-OS to reach the controller, and also to describe networking, other I/O ports, and GPUs which can potentially be assigned to application instances.

Serial ports can be assigned to app instances without much restrictions, but the details depend on the hypervisor being used. The model file supports both KVM and Xen and different virtualization modes like PV and HVM by specifying the different phyaddr; both a Serial field in the form of /dev/ttyS* and an IRQ and IOPort address. In some cases an IRQ might be shared between different COM ports which might require them to be in the same assignment group. Note that this requires manual validation.

For security and stability reasons the Xen and KVM hypervisors restrict the assignment of PCI devices and controllers based on the capabilities of the IOMMU. This is to prevent one application instance to be able to program a DMA engine in an I/O device to use DMA to read and/or write from other parts of the physical memory in the device. (This is captured using a concept called IOMMU groups.)

The model file describes these assignment constraints using the assigngrp field. If the assigngrp field is empty it means that the adapter can not be assigned to application instances (but if it is a networking adapter it can still be used by EVE-OS). Otherwise all of the adapters with the same assignment group can be assigned as a unit to the same application instance. An example of this is a GPU device which might have a graphics and a separate audio device, which are in the same group.

USB controllers vs USB ports vs cellular modems requires some additional work and might place some more constraints as specified below.

Last but not least, there are reports in industry that for some devices (in particular GPUs) the IOMMU group specification might be incorrect. Thus it is critical that the model description is tested by doing actual assignment to application instances.

## Generating initial model file

If and only if you have a debug version of EVE-OS booted with the KVM hypervisor and no actual model being provided by the controller, then you can can run a script to get a partial and initial model file. That script is invoked as:

```shell
# eve exec debug spec.sh
```

Note that the script does not take photos of the front and back, nor find the product URL, hence the output must be edited. The less obvious but more critical manual work includes:

- The script looks for controllers on the PCI bus but has no visibility to which controllers are connected to which external physical ports. This is an issue in particular for USB ports where one controller can be connected to multiple physical ports, but there can also be multiple USB controllers perhaps with some of them having no external physical ports. On a device with multiple USB controllers manual testing is needed to determine which controller is connected to which external USB ports.
- A cellular modem (if available) is typically connected via a USB controller, but it might not be visible (not plugged in or software not yet initializing it) when you run the script. ```lsusb``` and ```lspci``` can help finding those.
- If there are unknown controllers/functions on the PCI bus which share an IOMMU group with a known controller/function, the script is conservative and will mark the known as not assignable by setting assigngrp to empty. More about that below.

### Completing the model file

Starting from the generated model file and add or adjust:

- Add the product URL
- Add photos of the front and back with sufficient detail to show any printed labels next to the physical ports. If there are no such unique labels, add annotations on the photo with unique labels.
- Edit the phylabel fields in the model file to match the above labels.
- Optionally, if the intended application pre-determined and e.g., eth1 will be connected to the shopfloor network, you can set the logicallabel field to "shopfloor". That makes it more clear in the UI the intended use of that port.
- If the model file shows multiple USB controllers, then plug in e.g., a USB stick in each physical USB port and use ```lsusb``` and ```lspci``` to tell which controller to which port is connected.
- If the device has multiple physical USB ports, please add a entry for each one of them in the json file (on the correct USB controller if there are multiple)
- If you device has a cellular modem verify that there is one or two wwan interfaces in the generated file, and if not add one. If it is connected via a USB controller (```lsusb``` will tell you that) it needs to be in the same assignment group as the USB controller.
- If some controllers have an empty assignment group there might be an issue with an unknown controller/function. The ```-v``` option to the script can be used to get more information about such unknown controllers/functions.

#### Check for unknown controllers/functions

This example shows a device with two VGA controllers, where only one
appears to be assignable. The script outputs

```json
    {
      "ztype": 7,
      "phylabel": "VGA",
      "assigngrp": "group2",
      "phyaddrs": {
        "PciLong": "0000:00:13.0"
      },
      "logicallabel": "VGA",
      "usagePolicy": {}
    },
    {
      "ztype": 7,
      "phylabel": "VGA1",
      "assigngrp": "",
      "phyaddrs": {
        "PciLong": "0000:04:00.0"
      },
      "logicallabel": "VGA1",
      "usagePolicy": {}
    }
```

In this case one can invoke ```spec.sh -v``` which includes additional fields and information for all items in lspci. NOTE that this output is not a valid model file hence should not be submitted as a PR to lf-edge/eden; it is merely useful to determine whether the script was too conservative in disabling assignment.
In the above example we got:

```json
    {
      "ztype": 7,
      "phylabel": "VGA",
      "assigngrp": "group2",
      "phyaddrs": {
        "PciLong": "0000:00:13.0"
      },
      "logicallabel": "VGA",
      "usagePolicy": {}
      ,
      "class": "0000",
      "vendor": "8086",
      "device": "a135",
      "description": "Non-VGA unclassified device: Intel Corporation 100 Series/
C230 Series Chipset Family Integrated Sensor Hub (rev 31)",
      "iommu_group": 2
    },
    {
      "ztype": 7,
      "phylabel": "VGA1",
      "assigngrp": "",
      "phyaddrs": {
        "PciLong": "0000:04:00.0"
      },
      "logicallabel": "VGA1",
      "usagePolicy": {}
      ,
      "class": "0300",
      "vendor": "1a03",
      "device": "2000",
      "description": "VGA compatible controller: ASPEED Technology, Inc. ASPEED Graphics Family (rev 30)",
      "iommu_group": 11
    },
    {
      "ztype": 255,
      "phylabel": "Other11",
      "assigngrp": "",
      "phyaddrs": {
        "PciLong": "0000:03:00.0"
      },
      "logicallabel": "Other11",
      "usagePolicy": {}
      ,
      "class": "0604",
      "vendor": "1a03",
      "device": "1150",
      "description": "PCI bridge: ASPEED Technology, Inc. AST1150 PCI-to-PCI Bri
dge (rev 03)",
      "iommu_group": 11
    }
```

That second device, which is a PCI bridge in the VGA controller it seems, is in the same iommu_group as the VGA1 device hence the reason for disabling assignment of VGA1 by default. However, in this case that might be normal and they should be assigned as a unit. But in all such case it REQUIRES manual testing and verification that the controllers still work as expected when assigned to an app insgance.

In this case it would make sense to try with:

```json
    {
      "ztype": 7,
      "phylabel": "VGA",
      "assigngrp": "group2",
      "phyaddrs": {
        "PciLong": "0000:00:13.0"
      },
      "logicallabel": "VGA",
      "usagePolicy": {}
    },
    {
      "ztype": 7,
      "phylabel": "VGA1",
      "assigngrp": "group11",
      "phyaddrs": {
        "PciLong": "0000:04:00.0"
      },
      "logicallabel": "VGA1",
      "usagePolicy": {}
    },
    {
      "ztype": 255,
      "phylabel": "Other11",
      "assigngrp": "group11",
      "phyaddrs": {
        "PciLong": "0000:03:00.0"
      },
      "logicallabel": "Other11",
      "usagePolicy": {}
    }
```

## Testing

The model file as well as other hardware functions used by EVE-OS should be tested before submitting a pull request to add the model file.

### Testing the model file

The testing includes to assign each assignable adapter to an app instance and verifying that it works when used by that app instance. That testing is different if this is a USB controller, audio device, serial port, GPU, or network port.
While testing this it is also critical to test that other PCI functions on the same controller remain usable by EVE-OS (or that they can be assigned to other application instances and work there). For instance, if eth4, eth5, eth6, and eth7 are separate functions on the same PCI controller. For example,

```shell
# lspci | grep 0b:00
0b:00.0 Ethernet controller: Intel Corporation I350 Gigabit Network Connection (rev 01)
0b:00.1 Ethernet controller: Intel Corporation I350 Gigabit Network Connection (rev 01)
0b:00.2 Ethernet controller: Intel Corporation I350 Gigabit Network Connection (rev 01)
0b:00.3 Ethernet controller: Intel Corporation I350 Gigabit Network Connection (rev 01)
# find /sys/kernel/iommu_groups/ -type l | grep 0b:00
/sys/kernel/iommu_groups/41/devices/0000:0b:00.3
/sys/kernel/iommu_groups/38/devices/0000:0b:00.0
/sys/kernel/iommu_groups/40/devices/0000:0b:00.2
/sys/kernel/iommu_groups/39/devices/0000:0b:00.1
```

In such a case it would make sense to assign eth4, eth5, eth6, and eth7 to different application instances and verify that they are able to send and receive packets.

### Testing hardware watchdog

On a test system, ideally connected to a monitor and keyboard, suspend the software watchdog process and wait for some time (based on the hardware watchdog timer, which might be configurable in the BIOS) and the hardware watchdog should reset the box. One way to do this is:

```shell
# pkill -SUSP watchdog
```

Alternatively one can use [/opt/zededa/bin/faultinjection -W](./FAULT-INJECTION.md) to cause the hardware watchdog to fire.

### Verifying the TPM support

The existence of the TPM is determined by the spec.sh script and it puts this in the hsm attribute. Since EVE only supports TPM 2.0 this does not detect TPM 1.2 devices.

However, even a TPM 2.0 device might not support all of the functionality needed for ECC certificates, ECDH generation, sealing a vault key under the TPM measurements, measured boot and remote attestation.

Once EVE-OS is installed on a device and the device is onboarded to the controller one can check that this functionality is seen by the controller.

Prior to that one can verify that:

- There is a /config/device.cert.pem and no /config/device.key.pem, indicating that the device certificate was generated by the TPM (and the private key is kept in the TPM chip)
- There is a set of certificate files in /persist/certs/: ek.cert.pem, attest.cert.pem, and ecdh.cert.pem

### Verifying the VT-x and VT-d

This is reported in the EVE API and can be seen in the controller.

If and only if you have a debug version of EVE-OS booted using the KVM hypervisor you can also verify that VT-d is enabled by checking that /sys/kernel/iommu_groups exists and is not empty.

### Verifying LED progress indication

As EVE-OS boots the LED (by default the disk LED) will repeatedly blink once until the device has an IP address, then repeatedly blink twice while trying to connect to the controller, then repeatedly blink three or four times when connected to the controller. If your hardware model has some other LED to use for this, please review [ledmanager](../pkg/pillar/cmd/ledmanager) and submit a pull request for your hardware model.

### Hardware model in verification image

Among other logs, the verification process generates and collects the hardware model of the edge device as described in [HARDWARE-VERIFICATION](./HARDWARE-VERIFICATION.md).
