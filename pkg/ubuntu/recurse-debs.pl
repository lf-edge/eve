#!/usr/bin/env perl

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

use 5.12.0;
use strict;

my @pkgs = @ARGV;

# expand the requested packages with their transitive hull
my %seen = map { $_ => 1 } @pkgs;
my $is_added=1;
while ($is_added) {
    $is_added=0;
    # only Depends/Pre-Depends and only the first alternative of an OR group,
    # which is what apt picks when none of them is installed yet
    open(my $dh, "-|", 'apt-cache', 'depends', '--important', '-o', 'APT::Cache::ShowOnlyFirstOr=true', @pkgs)
        or die "could not run apt-cache: $!";
    my $virtual = 0;
    while (<$dh>) {
        my $dep;
        # a virtual target (<name>) is followed by its providers, best one first
        if (m/^\s+(?:Pre)?Depends:\s+<[^>]+>/) { $virtual = 1; next; }
        if (m/^\s+(?:Pre)?Depends:\s+(\S+)/) { $dep = $1; }
        elsif ($virtual and m/^ {4}(\S+)/) { $dep = $1; }
        else { next; }
        $virtual = 0;
        $is_added=1 unless $seen{$dep};
        push @pkgs, $dep unless $seen{$dep}++;
    }
    close($dh) or die "could not finish apt-cache: $!";
}
print("@pkgs\n");

