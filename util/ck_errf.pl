#! /usr/bin/env perl
# Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# This is just a quick script to scan for cases where the 'error'
# function name in a XXXerr() macro is wrong.
#
# Run in the top level by going
# perl util/ck_errf.pl */*.c */*/*.c
#

use strict;
use warnings;

my $err_strict = 0;
my $bad        = 0;

# To detect if there is any error generation for a libcrypto/libssl libs
# we don't know, we need to find out what libs we do know.  That list is
# readily available in crypto/err/openssl.ec, in form of lines starting
# with "L ".
my $config     = "crypto/err/openssl.ec";
my %libs       = ( "SYS" => 1 );
open my $cfh, $config or die "Trying to read $config: $!\n";
while (<$cfh>) {
    s|\R$||;                    # Better chomp
    next unless m|^L ([0-9A-Z_]+)\s|;
    next if $1 eq "NONE";
    $libs{$1} = 1;
}

foreach my $file (@ARGV) {
    if ( $file eq "-strict" ) {
        $err_strict = 1;
        next;
    }
    open( IN, "<$file" ) || die "Can't open $file, $!";
    my $func = "";
    while (<IN>) {
        if ( !/;$/ && /^\**([a-zA-Z_].*[\s*])?([A-Za-z_0-9]+)\(.*([),]|$)/ ) {
            /^([^()]*(\([^()]*\)[^()]*)*)\(/;
            $1 =~ /([A-Za-z_0-9]*)$/;
            $func = $1;
            $func =~ tr/A-Z/a-z/;
        }
        if ( /([A-Z0-9_]+[A-Z0-9])err\(([^,]+)/ && !/ckerr_ignore/ ) {
            my $errlib = $1;
            my $n      = $2;

            unless ( $libs{$errlib} ) {
                print "$file:$.:$errlib unknown\n";
                $bad = 1;
            }

            if ( $func eq "" ) {
                print "$file:$.:???:$n\n";
                $bad = 1;
                next;
            }

            if ( $n !~ /^(.+)_F_(.+)$/ ) {
                #print "check -$file:$.:$func:$n\n";
                next;
            }
            my $lib = $1;
            $n   = $2;

            if ( $lib ne $errlib ) {
                print "$file:$.:$func:$n [${errlib}err]\n";
                $bad = 1;
                next;
            }

            $n =~ tr/A-Z/a-z/;
            if ( $n ne $func && $errlib ne "SYS" ) {
                print "$file:$.:$func:$n\n";
                $bad = 1;
                next;
            }

            #		print "$func:$1\n";
        }
    }
    close(IN);
}

if ( $bad && $err_strict ) {
    print STDERR "FATAL: error discrepancy\n";
    exit 1;
}
