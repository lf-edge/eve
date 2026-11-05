#!/usr/bin/perl
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# evetest-oom-hook.pl - Proxmox VE hookscript installed on the PVE host by the
# evetest installers (see evetest/deploy/proxmox). On guest post-start it sets
# the QEMU process's OOM-killer priority (oom_score_adj) by role, so that when
# the host runs out of RAM the kernel kills the evetest test VMs first, then
# the GitHub runner VMs, and the broker VM last (the broker is the single point
# of failure for every running test).
#
# The role comes from the VM's Proxmox tags, set by the installers:
#   evetest-broker -> -900 (best protected)
#   evetest-runner -> -500
#   anything else  ->  500 (a test VM created by the broker)
#
# It is attached directly to the broker and runner VMs. A VM has only one
# hookscript, so for the test VMs, which carry evetest-hook.pl, that script
# calls this one.
#
# Best-effort: it logs and always exits 0, so it can never prevent a guest from
# starting. Logged to syslog (tag "evetest-oom-hook") and STDERR.

use strict;
use warnings;

my $vmid  = shift @ARGV;
my $phase = shift @ARGV;
exit 0 unless defined $vmid && defined $phase && $phase eq 'post-start';

my %tags;
if (open(my $fh, '<', "/etc/pve/qemu-server/$vmid.conf")) {
    while (my $line = <$fh>) {
        last if $line =~ /^\[/;    # stop at snapshot/pending sections
        %tags = map { $_ => 1 } split(/[;,\s]+/, $1) if $line =~ /^tags:\s*(.*)$/;
    }
    close($fh);
}
my $score = $tags{'evetest-broker'} ? -900
          : $tags{'evetest-runner'} ? -500
          : 500;

my $pidfile = "/var/run/qemu-server/$vmid.pid";
my $pid;
if (open(my $pf, '<', $pidfile)) {
    $pid = <$pf>;
    close($pf);
}
unless (defined $pid && $pid =~ /^\s*(\d+)\s*$/) {
    log_msg('err', $vmid, "cannot read QEMU pid from $pidfile; oom_score_adj not set");
    exit 0;
}
$pid = $1;
my $ok = 0;
if (open(my $out, '>', "/proc/$pid/oom_score_adj")) {
    $ok = print {$out} $score;
    $ok = close($out) && $ok;
}
if ($ok) {
    log_msg('info', $vmid, "set oom_score_adj=$score on QEMU pid $pid");
} else {
    log_msg('err', $vmid, "failed to set oom_score_adj=$score on pid $pid: $!");
}
exit 0;

sub log_msg {
    my ($prio, $vmid, $msg) = @_;
    my $line = "vmid=$vmid: $msg";
    print STDERR "evetest-oom-hook: $line\n";
    system('logger', '-t', 'evetest-oom-hook', '-p', "user.$prio", $line);
}
