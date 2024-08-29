#!/usr/bin/env perl

use strict;
use warnings;

print "usage: $0 <docker tag>\n" and exit if not defined $ARGV[0];
system("docker save $ARGV[0] | ../../build-tools/bin/linuxkit cache import /dev/stdin");


my $found = 0;
open my $cmd, "-|", "../../build-tools/bin/linuxkit cache ls 2>&1";
while (<$cmd>) {
    chomp;
    if (m/$ARGV[0]/) {
        print("Found ".$_." in the linuxkit cache\n");
        $found = 1;
    }
}

die "Did not find image in linuxkit cache" if not $found == 1;

if ($ARGV[0] =~ /^docker.io\/(.*)/) {
    print("Please use the following image name:\n$1\n");
}

