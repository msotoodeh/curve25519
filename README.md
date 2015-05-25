# curve25519
Efficient implementation of elliptic curve 25519
================================================

Copyright Mehdi Sotoodeh.  All rights reserved.
<mehdisotoodeh@gmail.com>

This code and accompanying files are put in public domain by the author.
You can freely use, copy, modify and distribute this software as long
as you comply with the license terms. See license file for details.

This library supports DH key exchange using curve25519 as well as sign/verify
operations based on twisted Edwards curve 25519.
Code includes portable C code as well as X86_64 assembly language for 64-bit 
AMD/Intel CPU architectures.

Performance:
------------
The portable C version is nearly twice faster than Google's implementation (http://code.google.com/p/curve25519-donna/) on 64-bit platforms and a factor 
of close to 4 on 32-bit platforms.
The assembly implementation is approximately 3 times faster than C implementation 
on 64-bit platforms. Who calls C language 'portable assembly'!


Timing for ed25519 sign/verify:
```
    windows7-64: VS2010 + MS Assembler
        KeyGen: 192276 cycles = 56.552 usec @3.4GHz
          Sign: 188232 cycles = 55.362 usec @3.4GHz
        Verify: 257272 cycles = 75.668 usec @3.4GHz
        
    windows7-64: VS2010 + MS Assembler (constant-time)
        KeyGen: 202148 cycles = 59.455 usec @3.4GHz
          Sign: 205156 cycles = 60.340 usec @3.4GHz
        Verify: 257756 cycles = 75.811 usec @3.4GHz

    windows7-64:  VS2010
        KeyGen: 553940 cycles = 162.924 usec @3.4GHz
          Sign: 540488 cycles = 158.967 usec @3.4GHz
        Verify: 727140 cycles = 213.865 usec @3.4GHz

    windows7-64:  VS2010, Constant-time
        KeyGen: 579192 cycles = 170.351 usec @3.4GHz
          Sign: 584234 cycles = 171.834 usec @3.4GHz
        Verify: 725878 cycles = 213.494 usec @3.4GHz

    windows7-32:  VS2010
        KeyGen: 2335613 cycles = 686.945 usec @3.4GHz
          Sign: 2259537 cycles = 664.570 usec @3.4GHz
        Verify: 3006601 cycles = 884.294 usec @3.4GHz
    
    cygwin-32: gcc 4.5.3
        KeyGen: 1696521 cycles = 498.977 usec @3.4GHz
          Sign: 1652167 cycles = 485.931 usec @3.4GHz
        Verify: 2211727 cycles = 650.508 usec @3.4GHz
```

Timing for DH point multiplication:
```
    windows7-64: VS2010 + MS Assembler
        Donna: 779116 cycles = 229.152 usec @3.4GHz -- ratio: 4.887
        Mehdi: 159438 cycles = 46.894 usec @3.4GHz -- delta: 79.54%     ** MSASM **

    Mingw-x86_64: gcc 9.9.2, nasm 2.11.08
        Donna: 851840 cycles = 250.541 usec @3.4GHz -- ratio: 5.331
        Mehdi: 159778 cycles = 46.994 usec @3.4GHz -- delta: 81.24%     ** NASM **

    ubuntu-12.04.3-x86_64: nasm 2.09.10
        Donna: 867671 cycles = 255.197 usec @3.4GHz -- ratio: 5.464
        Mehdi: 158787 cycles = 46.702 usec @3.4GHz -- delta: 81.70%     ** NASM **

    windows7-64:  VS2010
        Donna: 780131 cycles = 229.450 usec @3.4GHz -- ratio: 1.682
        Mehdi: 463769 cycles = 136.403 usec @3.4GHz -- delta: 40.55%

    windows7-32:  VS2010
        Donna: 7398408 cycles = 2176.002 usec @3.4GHz -- ratio: 3.832
        Mehdi: 1930862 cycles = 567.901 usec @3.4GHz -- delta: 73.90%

    cygwin-32: gcc 4.5.3
        Donna: 2550650 cycles = 750.191 usec @3.4GHz -- ratio: 1.810
        Mehdi: 1409196 cycles = 414.469 usec @3.4GHz -- delta: 44.75%
                    
    -- Linux debian6-64 2.6.32-5-amd64 #1 SMP Mon Sep 23 22:14:43 UTC 2013 x86_64 GNU/Linux

    debian-64: gcc (Debian 4.4.5-8) 4.4.5
        Donna: 860872 cycles = 253.198 usec @3.4GHz -- ratio: 1.610
        Mehdi: 534584 cycles = 157.231 usec @3.4GHz -- delta: 37.90%      
```

Building:
---------
The design uses a configurable switch that defines the byte order of the
target CPU. In default mode it uses Little-endian byte order. You need to
change this configuration for Big-endian targets by setting ECP_BIG_ENDIAN
switch (see Makefile).

Second configurable switch controls usage of TSC (Time Stamp Counter). It is
only used as a high resolution timer for performance measurements. You need 
to turn ECP_NO_TSC switch on if your target does not support it.

Another configurable switch named ECP_CONSTANT_TIME is added for constant-time
implementation of the library when it operates on private keys.

For building the library using the assembly sources, two assemblers are currently
supported: Microsoft Assembler (Windows) and NASM (Windows/Linux). 
NASM can be downloaded from: http://www.nasm.us/pub/nasm/releasebuilds/2.11.08/

- For Windows platforms, open windows/EC25519.sln using Visual Studio 2010
  and build Asm64Test project for x64 configuration.
  You also have the option of using Mingw and nasm on windows platforms,
- For Linux platforms, Ubuntu has been tested so far. For X86 assembly support 
  you need to install nasm first and then run: 'make asm' from project root.
  Output files will be created in asm64/build/test64.

