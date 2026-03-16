#!/usr/bin/perl

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

use 5.12.0;

-d ".git" or die "Please run from the root directory of the repository";

say "Be aware of the two shortcomings of this tool:";
say "1. pkg/eve/Dockerfile.in is not bumped";
say "2. Some Dockerfiles copy themselves into the container";
say "   therefore this tool has to be re-run after the git commit";

while (1) {
    my $found = 0;

    open my $cmd, "-|", "make check-docker-hashes-consistency 2> /dev/null";

    while (<$cmd>) {
        chomp;

        if (m/(\S*) uses ([^:]+):(\S*) but (\S+) is built/) {
            my $file = $1;
            my $oldhash = $3;
            my $newhash = $4;
            print "file: ".$file." oldhash: ".$oldhash." newhash: ".$newhash."\n";
            $found = 1;

            rename($file, $file . '.bak');
            open(my $IN, '<', $file . '.bak') or die $!;
            open(my $OUT, '>', $file) or die $!;
            while(<$IN>)
            {
                $_ =~ s/$oldhash/$newhash/g;
                print $OUT $_;
            }
            close($IN);
            close($OUT);

            unlink($file. '.bak');
        }
    }

    if ($found == 0) {
        last;
    }
}

