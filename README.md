# curve25519
Efficient implementation of elliptic curve 25519
================================================

Copyright Mehdi Sotoodeh.  All rights reserved.
<mehdisotoodeh@gmail.com>

This code and accompanying files are put in public domain by the author.
You are free to use, copy, modify and distribute this software as long
as you comply with the license terms. See license.txt file for details.


Performance:
------------
The library is not fully optimized yet. Squaring uses regular multiplication
and modular inverse uses exponentiation. Still, it outperforms google's 
implementation by a big margin (http://code.google.com/p/curve25519-donna/).

Timing for point multiplication:
```
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
