# curve25519
High performance implementation of elliptic curve 25519
=======================================================

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
The new version of this library sets NEW SPEED RECORDS. This is achieved 
without taking advantage of special CPU instructions or multi-CPU parallel 
processing.
The library implements a new technique (I call it FOLDING for now) that 
effectively reduces the number of EC point operations by a factor of 2, 4 
or even more. The trade off is the pre computation and cost of cached memory.

Google's implementation (http://code.google.com/p/curve25519-donna/) is used
here for performance comparison only. This library outperforms Google's code 
by a factor of 1.6 to 11 depending on the platform and selected language.

For best performance, use the 64-bit assembly version on AMD/Intel CPU 
architectures. The portable C code can be used for 32-bit OS's and other CPU 
types.

Note that the assembly implementation is approximately 3 times faster than C 
implementation on 64-bit platforms (C != PortableAssembly).
On 32-bit platforms, the biggest hit is due to usage of standard C library for
64-bit arithmetic operations. Numbers below indicate that GCC and glibc does a 
much better job than MSVC.


Timing for ed25519 sign/verify (short message & constant-time):
```
    windows7-64: VS2010 + MS Assembler
        KeyGen: 76188 cycles = 22.408 usec @3.4GHz
          Sign: 79972 cycles = 23.521 usec @3.4GHz
        Verify: 125396 cycles = 36.881 usec @3.4GHz (Init)
                110596 cycles = 32.528 usec @3.4GHz (Check)

    windows7:  VS2010, Portable-C, 64-bit
        KeyGen: 215870 cycles = 63.491 usec @3.4GHz
          Sign: 219972 cycles = 64.698 usec @3.4GHz
        Verify: 370388 cycles = 108.938 usec @3.4GHz (Init)
                306322 cycles = 90.095 usec @3.4GHz (Check)
    
    windows7:  VS2010, Portable-C, 32-bit
        KeyGen: 914630 cycles = 269.009 usec @3.4GHz
          Sign: 926174 cycles = 272.404 usec @3.4GHz
        Verify: 1550028 cycles = 455.891 usec @3.4GHz (Init)
                1300068 cycles = 382.373 usec @3.4GHz (Check)

    cygwin-32: gcc 4.5.3, Portable-C, 32-bit
        KeyGen: 667780 cycles = 196.406 usec @3.4GHz
          Sign: 683420 cycles = 201.006 usec @3.4GHz
        Verify: 1132878 cycles = 333.199 usec @3.4GHz (Init)
                951252 cycles = 279.780 usec @3.4GHz (Check)

    x86_64-w64-mingw32: gcc 4.9.2 + NASM 2.11.08
        KeyGen: 76758 cycles = 22.576 usec @3.4GHz
          Sign: 80586 cycles = 23.702 usec @3.4GHz
        Verify: 126716 cycles = 37.269 usec @3.4GHz (Init)
                111124 cycles = 32.684 usec @3.4GHz (Check)
    
Timing for DH point multiplication:
```
    windows7-64: VS2010 + MS Assembler
        Donna: 778914 cycles = 229.092 usec @3.4GHz -- ratio: 10.491
        Mehdi: 74248 cycles = 21.838 usec @3.4GHz -- delta: 90.47%      ** MSASM **

    Mingw-x86_64: gcc 9.9.2, nasm 2.11.08
        Donna: 852662 cycles = 250.783 usec @3.4GHz -- ratio: 11.431
        Mehdi: 74594 cycles = 21.939 usec @3.4GHz -- delta: 91.25%

    ubuntu-12.04.3-x86_64: nasm 2.09.10
        Donna: 867671 cycles = 255.197 usec @3.4GHz -- ratio: 5.464
        Mehdi: 158787 cycles = 46.702 usec @3.4GHz -- delta: 81.70%     ** NASM **

    windows7:  VS2010, Portable-C, 64-bit
        Donna: 780008 cycles = 229.414 usec @3.4GHz -- ratio: 3.692
        Mehdi: 211272 cycles = 62.139 usec @3.4GHz -- delta: 72.91%

    windows7:  VS2010, Portable-C, 32-bit
        Donna: 7460048 cycles = 2194.132 usec @3.4GHz -- ratio: 8.208
        Mehdi: 908870 cycles = 267.315 usec @3.4GHz -- delta: 87.82%

    cygwin-32: gcc 4.5.3, Portable-C, 32-bit
        Donna: 2550612 cycles = 750.180 usec @3.4GHz -- ratio: 3.899
        Mehdi: 654232 cycles = 192.421 usec @3.4GHz -- delta: 74.35%
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

