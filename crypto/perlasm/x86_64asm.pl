#! /usr/bin/env perl
# Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


package x86_64asm;

# require "x86_64asm.pl";
# $endbr=&endbr64();
# &file_end($flavour);
# close STDOUT;

# Collect all compiler flags.
my $cflags="";
for($i=0;$i<=$#ARGV;$i++) {
    if ($ARGV[$i] eq "386") {
	last;
    }
    $cflags.=" $ARGV[$i]";
}

# Check if Intel CET is enabled at compile time.
my $cet_enabled=(`echo "#ifdef __CET__\n#error CET is enabled\n#endif" | $ENV{CC} $cflags -c -o /dev/null -x c - 2>&1` =~ /CET is enabled/)?1:0;

sub ::file_end
{
    my($flavour)=@_;

    if ($cet_enabled and $flavour =~ /elf/) {
	my $p2align=(`echo "#ifdef __ILP32__\n#error ILP32 is enabled\n#endif" | $ENV{CC} $cflags -c -o /dev/null -x c - 2>&1` =~ /ILP32 is enabled/)?2:3;
	print <<___;
	.section \".note.gnu.property\", \"a\"
	.p2align $p2align
	.long 1f - 0f
	.long 4f - 1f
	.long 5
0:
	.asciz \"GNU\"
1:
	.p2align $p2align
	.long 0xc0000002
	.long 3f - 2f
2:
	.long 3
3:
	.p2align $p2align
4:
___
    }
}

sub ::endbr64
{
    return ($cet_enabled)?"endbr64":"";
}

1;
