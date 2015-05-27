# curve25519
Efficient implementation of elliptic curve 25519
================================================

Copyright Mehdi Sotoodeh.  All rights reserved.
<mehdisotoodeh@gmail.com>

This code and accompanying files are put in public domain by the author.
You can freely use, copy, modify and distribute this software as long
as you comply with the license terms. See license file for details.

This library delivers high performance and high security while having a small
footprint with minimum resource requirements.
This library supports DH key exchange using curve25519 as well as sign/verify
operations based on twisted Edwards curve 25519.


Performance:
------------
Google's implementation (http://code.google.com/p/curve25519-donna/) is used
here for performance comparison only. This library outperforms Google's code 
by a factor of 1.6 to 5.4 depending on the platform and selected language.

For best performance, use the 64-bit assembly version on AMD/Intel CPU 
architectures. The portable C code is provided mainly for 32-bit OS's and
other CPU types.

Note that the assembly implementation is approximately 3 times faster than C 
implementation on 64-bit platforms.
On 32-bit platforms, the biggest hit is due to usage of standard C library for
64-bit arithmetic operations. Numbers below indicate that GCC and glibc does a 
much better job than MSVC.


Timing for ed25519 sign/verify (short message & constant-time):
```
    windows7-64: VS2010 + MS Assembler
        KeyGen: 170258 cycles = 50.076 usec @3.4GHz
          Sign: 173560 cycles = 51.047 usec @3.4GHz
        Verify: 257994 cycles = 75.881 usec @3.4GHz

    windows7-64:  VS2010
        KeyGen: 499052 cycles = 146.780 usec @3.4GHz
          Sign: 502174 cycles = 147.698 usec @3.4GHz
        Verify: 727178 cycles = 213.876 usec @3.4GHz
    
    windows7-32:  VS2010
        KeyGen: 2069688 cycles = 608.732 usec @3.4GHz
          Sign: 2082760 cycles = 612.576 usec @3.4GHz
        Verify: 3007596 cycles = 884.587 usec @3.4GHz
    
    cygwin-32: gcc 4.5.3
        KeyGen: 1529706 cycles = 449.914 usec @3.4GHz
          Sign: 1545370 cycles = 454.521 usec @3.4GHz
        Verify: 2220586 cycles = 653.114 usec @3.4GHz
        
    x86_64-w64-mingw32: gcc 4.9.2 + NASM 2.11.08
        KeyGen: 171528 cycles = 50.449 usec @3.4GHz
          Sign: 176172 cycles = 51.815 usec @3.4GHz
        Verify: 261740 cycles = 76.982 usec @3.4GHz

    x86_64-w64-mingw32: gcc 4.9.2
        KeyGen: 521278 cycles = 153.317 usec @3.4GHz
          Sign: 524676 cycles = 154.316 usec @3.4GHz
        Verify: 757684 cycles = 222.848 usec @3.4GHz
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

For building the library using the assembly sources, two assemblers are currently
supported: Microsoft Assembler (Windows) and NASM (Windows/Linux). 
NASM can be downloaded from: http://www.nasm.us/pub/nasm/releasebuilds/2.11.08/

- For Windows platforms, open windows/EC25519.sln using Visual Studio 2010
  and build Asm64Test project for x64 configuration.
  You also have the option of using Mingw and nasm on windows platforms,
- For Linux platforms, Ubuntu has been tested so far. For X86 assembly support 
  you need to install nasm first and then run: 'make asm' from project root.
  Output files will be created in asm64/build/test64.

