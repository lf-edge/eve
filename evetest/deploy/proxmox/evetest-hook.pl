#!/usr/bin/perl
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# evetest-hook.pl - Proxmox VE hookscript installed on the PVE host by the
# evetest broker installer (see evetest/deploy/proxmox). The evetest Proxmox
# device provider attaches it to every VM it creates via the "hookscript" config
# option (local:snippets/evetest-hook.pl).
#
# On guest post-start it enables forwarding of link-local L2 protocols (LACP,
# EAPOL/802.1X, LLDP) and sets arp_ignore on the evetest "xconnect" VNet bridges
# the guest is attached to, so EVE can exercise those protocols across the
# simulated point-to-point links to the SDN VM. These are host-namespace
# operations that the broker (running inside a VM) cannot perform itself.
#
# On guest post-stop it removes any dnsmasq DHCP lease belonging to the VM from
# the evetest SDN zone's lease file and restarts dnsmasq so the cleanup takes
# effect. dnsmasq's static IPv6 (and IPv4) address reservations are keyed by
# MAC in PVE's own generated config, but the *lease* database is keyed by
# address and never released by PVE itself, so a destroyed VM's stale,
# unreleased lease (dnsmasq's static leases use an infinite lease time) would
# otherwise permanently block the same address from being reassigned to
# whatever VM claims that address next.
#
# It is intentionally best-effort: it logs and continues on any error and always
# exits 0, so it can never prevent a guest from starting or stopping.
#
# Every invocation, action, and outcome is logged via log_info()/log_error()
# below -- to syslog/journald (tag "evetest-hook", so `journalctl -t
# evetest-hook` shows a persistent record across every VM start) and to STDERR
# (so it also shows up in that specific qm start's own task log).

use strict;
use warnings;

# evetest always uses a single, fixed SDN zone (see sdnZone in
# broker/provider/proxmox.go), so the dnsmasq instance/paths are fixed too.
my $DNSMASQ_ZONE    = 'evetest';
my $LEASES_FILE     = "/var/lib/misc/dnsmasq.$DNSMASQ_ZONE.leases";
my $ETHERS_FILE     = "/etc/dnsmasq.d/$DNSMASQ_ZONE/ethers";
my $DNSMASQ_SERVICE = "dnsmasq\@$DNSMASQ_ZONE";

my $vmid  = shift @ARGV;
my $phase = shift @ARGV;

log_info('?', "invoked: vmid=" . (defined $vmid ? $vmid : '?')
    . " phase=" . (defined $phase ? $phase : '?'));

exit 0 unless defined $vmid && defined $phase;

if ($phase eq 'post-stop') {
    cleanup_stale_leases($vmid);
    exit 0;
}

# Only act once the VM has started: at post-start its tap devices exist and are
# enslaved to the SDN VNet bridges (the documented moment for group_fwd_mask).
exit 0 unless $phase eq 'post-start';

# group_fwd_mask 0x4008 = EAPOL (0x4000) + LLDP (0x0008). LACP (0x4) is rejected
# in the bridge-level mask by the kernel (BR_GROUPFWD_RESTRICTED) and is instead
# set per bridge port below.
my $BRIDGE_FWD_MASK = '0x4008';
my $LACP_PORT_MASK  = '0x4';

# Parse the VM's network interfaces from its config. Read the config file
# directly (robust, no PATH/subprocess dependency) and stop at the first section
# header (e.g. "[snapshot]" / pending) so only the active config is considered.
my $conf = "/etc/pve/qemu-server/$vmid.conf";
open(my $fh, '<', $conf) or do {
    log_error($vmid, "cannot open $conf: $!");
    exit 0;
};
my $configured = 0;
my $args_line = '';
while (my $line = <$fh>) {
    last if $line =~ /^\[/;               # stop at snapshot/pending sections
    $args_line = $1 if $line =~ /^args:\s*(.*)$/;
    next unless $line =~ /^net(\d+):\s*(.*)$/;
    my ($idx, $spec) = ($1, $2);
    my ($bridge) = $spec =~ /bridge=([^,\s]+)/;
    next unless defined $bridge;

    # Only evetest xconnect bridges ("evx" + 5 hex). The uplink bridge
    # (evu) must NOT get these tweaks.
    next unless $bridge =~ /^evx[0-9a-f]{5}$/;

    my $tap = "tap${vmid}i${idx}";
    log_info($vmid, "configuring xconnect bridge $bridge (tap $tap, net$idx)");
    configure_xconnect($vmid, $bridge, $tap);
    $configured++;
}
close($fh);

# XConnect NICs defined through QEMU args rather than netX (see
# buildVMOptions in broker/provider/proxmox.go): the broker places each of
# them behind its own pcie-root-port so that it lands in its own IOMMU
# group inside the guest, which is what makes passing an individual NIC
# through from EVE to an application possible. PVE knows nothing about
# these taps, so enslave them to their VNet bridges here (the netdev id
# encodes the bridge: id=evn_<bridge>_<index>, with the ifname adjacent),
# then apply the same L2 tweaks as for netX-based xconnects.
while ($args_line =~ /id=evn_(evx[0-9a-f]{5})_\d+,ifname=([^,\s]+)/g) {
    my ($bridge, $tap) = ($1, $2);
    log_info($vmid, "enslaving args-defined tap $tap to xconnect bridge $bridge");
    # Raise the tap MTU to the bridge's before enslaving (as PVE's own
    # bridge script does), or the bridge MTU would drop to the tap's 1500.
    if (open(my $mfh, '<', "/sys/class/net/$bridge/mtu")) {
        my $mtu = <$mfh>;
        close($mfh);
        chomp $mtu if defined $mtu;
        run_cmd($vmid, "ip link set dev $tap mtu $mtu") if $mtu;
    }
    run_cmd($vmid, "ip link set dev $tap master $bridge");
    run_cmd($vmid, "ip link set dev $tap up");
    configure_xconnect($vmid, $bridge, $tap);
    $configured++;
}
if ($configured) {
    log_info($vmid, "configured $configured xconnect bridge(s)");
} else {
    log_info($vmid, "no xconnect bridges found, nothing to do");
}
exit 0;

# cleanup_stale_leases removes any dnsmasq lease belonging to vmid's own MAC
# addresses, or to any address reserved for them in the ethers file, then
# restarts dnsmasq so the now-freed address(es) can be reassigned to whatever
# VM claims them next. The VM's own config file is still readable at
# post-stop (it is only removed later, if at all, by qm destroy).
sub cleanup_stale_leases {
    my ($vmid) = @_;

    my $conf = "/etc/pve/qemu-server/$vmid.conf";
    open(my $fh, '<', $conf) or do {
        log_error($vmid, "cannot open $conf for lease cleanup: $!");
        return;
    };
    my %macs;
    while (my $line = <$fh>) {
        last if $line =~ /^\[/;   # stop at snapshot/pending sections
        next unless $line =~ /^net\d+:\s*(.*)$/;
        my ($mac) = $1 =~ /virtio=([0-9A-Fa-f:]+)/;
        $macs{lc $mac} = 1 if $mac;
    }
    close($fh);
    unless (%macs) {
        log_info($vmid, "no interfaces found, nothing to clean up in dnsmasq leases");
        return;
    }

    # Addresses (v4 and/or v6) reserved for this VM's MACs, per the ethers file.
    my %addrs;
    if (open(my $eth, '<', $ETHERS_FILE)) {
        while (my $line = <$eth>) {
            chomp $line;
            my ($mac, @rest) = split(/,/, $line);
            next unless defined $mac && $macs{lc $mac};
            for my $field (@rest) {
                my ($ip6) = $field =~ /^\[(.+)\]$/;
                $addrs{lc($ip6 // $field)} = 1;
            }
        }
        close($eth);
    } else {
        log_info($vmid, "cannot open $ETHERS_FILE: $! (continuing with MAC-only match)");
    }

    open(my $in, '<', $LEASES_FILE) or do {
        log_info($vmid, "no dnsmasq lease file at $LEASES_FILE, nothing to clean up");
        return;
    };
    my (@keep, $removed);
    while (my $line = <$in>) {
        # "duid <server-duid>" is the server's own identity, not a lease.
        if ($line !~ /^duid /) {
            my (undef, $field2, $field3) = split(' ', $line);
            if (defined $field2 && defined $field3
                && ($macs{lc $field2} || $addrs{lc $field3}))
            {
                $removed++;
                next;
            }
        }
        push @keep, $line;
    }
    close($in);

    unless ($removed) {
        log_info($vmid, "no stale dnsmasq leases found for this VM");
        return;
    }

    if (open(my $out, '>', $LEASES_FILE)) {
        print $out @keep;
        close($out);
        log_info($vmid, "removed $removed stale dnsmasq lease(s) for MAC(s) "
            . join(',', keys %macs));
        if (system('systemctl', 'restart', $DNSMASQ_SERVICE) == 0) {
            log_info($vmid, "restarted $DNSMASQ_SERVICE to apply lease cleanup");
        } else {
            log_error($vmid, "failed to restart $DNSMASQ_SERVICE: $!");
        }
    } else {
        log_error($vmid, "failed to write $LEASES_FILE: $!");
    }
}

# configure_xconnect applies the link-local L2 forwarding tweaks to one
# xconnect bridge and the VM's tap port on it.
sub configure_xconnect {
    my ($vmid, $bridge, $tap) = @_;
    # Bridge-level forwarding of EAPOL + LLDP.
    write_sysfs($vmid, "/sys/class/net/$bridge/bridge/group_fwd_mask", $BRIDGE_FWD_MASK);
    # Do not answer ARP for the host's IPs on this bridge (xconnect VNets carry
    # no host IP; set defensively to match the libvirt/qemu providers).
    write_sysfs($vmid, "/proc/sys/net/ipv4/conf/$bridge/arp_ignore", '1');
    # Per-port LACPDU forwarding on the VM's tap port.
    write_sysfs($vmid, "/sys/class/net/$tap/brport/group_fwd_mask", $LACP_PORT_MASK);
}

# run_cmd runs a shell command, logging it and its outcome; best-effort like
# everything else in this script.
sub run_cmd {
    my ($vmid, $cmd) = @_;
    my $rc = system($cmd);
    if ($rc == 0) {
        log_info($vmid, "ran: $cmd");
    } else {
        log_error($vmid, "command failed (rc=$rc): $cmd");
    }
}

sub write_sysfs {
    my ($vmid, $path, $value) = @_;
    if (open(my $out, '>', $path)) {
        print $out $value;
        if (close($out)) {
            log_info($vmid, "wrote '$value' to $path");
        } else {
            log_error($vmid, "error closing $path: $!");
        }
    } else {
        log_error($vmid, "failed to write '$value' to $path: $!");
    }
}

# log_info/log_error send a tagged message to syslog/journald (at "info" or
# "err" priority) and to STDERR. Fire-and-forget: logging itself is never
# allowed to fail the hookscript.
sub log_info {
    my ($vmid, $msg) = @_;
    my $line = "vmid=$vmid: $msg";
    print STDERR "evetest-hook: $line\n";
    system('logger', '-t', 'evetest-hook', '-p', 'user.info', $line);
}

sub log_error {
    my ($vmid, $msg) = @_;
    my $line = "vmid=$vmid: $msg";
    warn "evetest-hook: $line\n";
    system('logger', '-t', 'evetest-hook', '-p', 'user.err', $line);
}
