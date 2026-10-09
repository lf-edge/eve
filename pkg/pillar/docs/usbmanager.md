# USB Manager

The USB Manager manages pillar in regards to USB devices and edge applications.

## USB Controller

The USB Controller is the core that is connected to all other components to perform
the operations.
It receives information:

- USB devices"
- Edge Application status
- Model Manifest

One example of of the USB controller is used, can be found in FuzzUSBManagerController test in
[usbcontroller_test.go](./usbcontoller_test.go).

### Flow when a new USB device is recognized

1. Apply all passthrough rules on this device
2. If a rule applies, attach the device to the vm that is returned by the rule with the highest priority

### Flow when a USB device is removed

1. Remove the device from the vm

### Flow when an Edge Application (vm) is added

1. Update all passthrough rules with this adapter and the ones in the same assigngrp
2. Iterate over all USB devices and connect them to the vm if applicable this could even mean that the
    USB device gets disconnected first from another vm, because now the passthrough rules priority is
    higher

### Flow when an Edge Application (vm) is removed

1. Remove all adapters of this vm from all passthrough rules
2. Iterate over all USB devices and check if other rules now apply and do a passthrough of those devices
    accordingly

### Flow when a new IOBundle is added

1. Create a passthrough rule of the new IOBundle
2. Update all depending rules of this new IOBundle (meaning all rules that have the according parentassigngrp)
3. Iterate over all USB devices and update USB passthroughs accordingly, meaning
    that a different rule may apply now for some USB device and it may be connected to another vm

### Flow when an IOBundle changes

1. If the fields a passthrough rule is built from changed (usbaddr, usbproduct, pcilong, assigngrp,
    parentassigngrp), remove the old IOBundle and add the new one as described above; a change of
    runtime fields such as the assigned application does not touch the rules

### Flow when a new IOBundle is removed

1. Remove the IOBundle
2. Update all depending rules of this new IOBundle (meaning all rules that have the according parentassigngrp)
3. Iterate over all USB devices and update USB passthroughs accordingly, meaning
    that a different rule may apply now for some USB device and it may be connected to another vm

## Passthrough Rules

### Passthrough Rule Actions

A passthrough rule is a rule that decides if a USB device gets connected to a vm. A passthrough rule can
evaluate to three possible actions:

- passthroughDo -> passthrough of the USB device to the vm should be done, if there is no other rule with
    a higher priority
- passthroughNo -> this rule does not apply to the USB device and therefore don't passthrough the device
    to this vm
- passthroughForbid -> do not passthrough the device and overrule all other rules

### Passthrough Rule Priorities

Every passthrough Rule does not only provide the passthrough action but also a priority, because some
ways of passthrough have a higher priority than others.
F.e. Given a USB device and two passthrough rules to two different vms. One rule is addressing the device
via USB address, the other rule is addressing the device via product and vendor id. For the user it would
be unexpected if the device would be passed through to the vm with the rule for passing through by vendor
and product id.

A priority has two dimensions, one for the USB address and one for the vendor/product id. Priorities are
compared by the USB address dimension first; the vendor/product dimension only decides between rules
with an equal USB address dimension. Combined passthrough rules ([see](#list-of-passthrough-rules)) get
their priorities added per dimension. If several passthrough rules within a combined passthrough rule
match, the highest priority is returned.

The priorities are chosen so that the more specific claim wins:

| Rule | USB address | Vendor/product |
|------|-------------|----------------|
| usbPortPassthroughRule with an exact port (`1:2.3`) | 10 | 0 |
| usbPortPassthroughRule with a wildcard (`1:*`, `1:2.*`, `1:2.3.*`, ...) | 1 + number of fixed port components (1 to 6) | 0 |
| usbDevicePassthroughRule | 0 | 1 |
| pciPassthroughRule | 0 | 0 |

Therefore an exact port claim beats a wildcard covering that port, a longer wildcard beats a shorter one
and any location claim beats a vendor/product claim, even one combined with a less specific location:
`1:2.3` wins over `1:*` plus a vendor/product id, while `1:2.*` plus a vendor/product id wins over a
plain `1:2.*`.

### List of Passthrough Rules

- pciPassthroughForbidRule - this rule returns passthroughForbid if the PCI address matches; it is used
    to forbid passthrough of USB devices that are connected to a PCI controller that might be passed through
- neverPassthroughRule - this rule always returns passthroughNo; it is used for assigngroups that have no
    ioBundles
- pciPassthroughRule - this rule is used to match PCI addresses; it is used so far only in composition rules
- usbDevicePassthroughRule - this rule matches USB devices via product and vendor id
- usbPortPassthroughRule - this rule matches by USB bus number and port number; a trailing wildcard
    (`1:2.*`) matches every device below that port, e.g. all devices behind a hub plugged into the port,
    and `1:*` matches every device on the bus; the device in the port itself does not match a wildcard;
    a wildcard accepts at most five fixed components as USB port paths have at most six
- usbHubForbidPassthroughRule - this rule prevents passing through of USB hubs as it is not supported;
    the devices behind a hub can still be passed through individually, e.g. via a wildcard port rule
- usbNetworkAdapterForbidPassthroughRule - forbids passing through of network adapters as this could
    take away the only working network adapter from EVE

Composition rules are used to put several passthrough rules together:

- compositionANDPassthroughRule - this rule matches if all containing rules match
- compositionORPassthroughRule - this rule matches if at least one rule matches

compositionORPassthroughRule is used to put all IOBundles together that have the same assigngrp.
compositionANDPassthroughRule is used to put IOBundles together that are linked via the
parentassigngrp feature.
