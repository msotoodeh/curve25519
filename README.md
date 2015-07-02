# curve25519
High performance implementation of elliptic curve 25519
=======================================================

Copyright (c) 2015 mehdi sotoodeh.
mehdisotoodeh@gmail.com

MIT license.


This library delivers high performance and high security while having a small
footprint with minimum resource requirements.
This library supports DH key exchange using curve25519 as well as sign/verify
operations based on twisted Edwards curve 25519.


Performance:
------------
Current version of this library sets **NEW SPEED RECORDS**. This is achieved 
without taking advantage of special CPU instructions or parallel processing.

The library implements a new technique (I call it FOLDING) that effectively 
reduces the number of EC point operations by a factor of 2, 4 or even more. 
The trade off is the pre-computation and cost of cached memory.
Currently 8-fold is implemented for KeyGen, Sign and DH(base point) operations 
and 4-fold for signature verification.
With 8-fold, it takes only 43K cycles on an Intel(tm) Core(tm) i7 CPU to do a 
base point scalar multiplication.

Google's implementation (http://code.google.com/p/curve25519-donna/) is used
here for performance comparison only. This library outperforms Google's code 
by a factor of 6.2 to 19.5 depending on the platform and selected language.

For best performance, use the 64-bit assembly version on AMD/Intel CPU 
architectures. The portable C code can be used for 32-bit OS's and other CPU 
types.

Note that the assembly implementation is approximately 3 times faster than C 
implementation on 64-bit platforms.
On 32-bit platforms, the biggest hit is due to usage of standard C library for
64-bit arithmetic operations. Numbers below indicate that GCC and glibc does a 
much better job than MSVC.

**V1.1:** 
Cycle count for ed25519 sign/verify (short messages):
```
| Platform       | KeyGen    | Sign     | Verify(init) | Verify(check) |
| -------------- | ---------:| --------:| ------------:| -------------:|
| W7-64/MASM     | 44647     | 48639    | 114325       | 110371        |
| W7-64/MASM (B) | 45227     | 49035    |              |               |
| W7-64/MSC      | 128777    | 133823   | 341097       | 307533        |
| W7-64/MSC (B)  | 130269    | 135011   |              |               |
| W7-32/MSC      | 542914    | 556878   | 1430160      | 1307354       |
| W7-32/MSC (B)  | 550024    | 563302   |              |               |
| W7-32/MSC      | 542914    | 556878   | 1430160      | 1307354       |
| W7-32/MSC (B)  | 550024    | 563302   |              |               |
| M64/GAS        | 44954     | 49008    | 114642       | 111156        |
| M64/GAS (B)    | 45628     | 49510    |              |               |
| C32/GCC        | 393512    | 411468   | 1046166      | 954980        |
| C32/GCC (B)    | 400014    | 414946   |              |               |
(B) = With blinding option.
```

New version with **Constant-Time:** 

Cycle count for ed25519 sign/verify (short messages):
```
| Platform       | KeyGen    | Sign     | Verify(init) | Verify(check) |
| -------------- | ---------:| --------:| ------------:| -------------:|
| W7-64/MASM     | 49881     | 53785    | 126880       | 103392        |
| W7-64/MASM (B) | 52123     | 55741    |              |               |
| W7-64/MSC      | 149033    | 154407   | 394500       | 308194        |
| W7-64/MSC (B)  | 150827    | 156295   |              |               |
| W7-32/MSC      | 552812    | 564216   | 1455728      | 1143550       | 
| W7-32/MSC (B)  | 559108    | 570324   |              |               | 
| M64/GAS        | 49782     | 53370    | 126812       | 103834        |
| M64/GAS (B)    | 50358     | 53920    |              |               |
| C32/GCC        | 440652    | 454156   | 1177857      | 919193        | 
| C32/GCC (B)    | 445872    | 459012   |              |               | 
```

Cycle count for X25519 DH base point multiplication:
```
| Platform   | Ver. | Donna-C  | Mehdi   | Ratio  |
| ---------- |:----:| --------:| -------:| ------:|
| W7-64/MASM | V1.1 | 779653   | 43229   | 18.035 |
| W7-64/MASM | CT   | 780207   | 48435   | 16.108 |
| W7-64/MSC  | V1.1 | 779753   | 125761  |  6.200 |
| W7-64/MSC  | CT   | 779941   | 146343  |  5.330 |
| W7-32/MSC  | V1.1 | 7289134  | 538846  | 13.527 | 
| W7-32/MSC  | CT   | 7387272  | 548398  | 13.471 | 
| M64/GAS    | V1.1 | 851314   | 43456   | 19.590 |
| M64/GAS    | CT   | 851564   | 48268   | 17.642 |
| C32/GCC    | V1.1 | 2551492  | 386498  |  6.602 | 
| C32/GCC    | CT   | 2549964  | 436616  |  5.840 | 
CT = Constant-Time
Fastest time = 43229 cycles = 12.74 micro-seconds @3.4GHz
```

Platforms:
```
| ID         | Configuration
|:----------:| --------------------------------------------------------------------
| W7-64/MASM | windows7-64: VS2010 + MS Assembler, Intel(R) Core(TM) i7-2670QM CPU
| W7-64/MSC  | windows7-64: VS2010, Portable-C, 64-bit, Intel(R) Core(TM) i7-2670QM CPU
| W7-32/MSC  | windows7: VS2010, Portable-C, 32-bit, Intel(R) Core(TM) i7-2670QM CPU
| M64/GAS    | x86_64-w64-mingw32: GNU assembler 2.25, Intel(R) Core(TM) i7-2670QM CPU
| C32/GCC    | Cygwin-32: gcc 4.5.3, Portable-C, 32-bit, Intel(R) Core(TM) i7-2670QM CPU
```

Side Channel Security:
----------------------
This library uses multiple measures with the gaol of eliminating leakage of secret 
keys during cryptographic operations. Constant-time is one of these measures and 
is implemented for all the field operations (no conditional operation based on key values). 
The second and more effective measure that this library uses is blinding. Blinding
hides the private keys by combining them with a random value. 
It calculates (a-b)*P + B where b is random blinding scalar and B = b*P.
The third measure is the randomization of the starting point. Instead of using (X,Y,Z), 
we use (XR,YR,ZR) where R is a randomly generated number.

This is a fact that constant-time implementation does not necessarily translate to
constant-power-consumption, constant-electro-magnetic-radiation and so on. It also
depends on how the underlying hardware manipulates different circuitry for each
operation. For example, a hardware multiplier may use the primitive technique of
shift-and-conditional-add or it may use barrel shifter when multiplying a power of 
2 number.

Blinding is the more effective measure with less performance penalty.
Constant-time alone, pushes attackers to dig deeper for clues.


Building:
---------
The design uses a configurable switch that defines the byte order of the
target CPU. In default mode it uses Little-endian byte order. You need to
change this configuration for Big-endian targets by setting ECP_BIG_ENDIAN
switch (see Rules.mk file on project root).

Define USE_ASM_LIB configuration when building to utilize ASM version of the library.

For building the library using the assembly sources, two assemblers are currently
supported: Microsoft Assembler (Windows) and GNU Assembler (Windows/Linux). 

- For Windows platforms, open windows/EC25519.sln using Visual Studio 2010
  and build Asm64Test project for x64 configuration.
  You also have the option of using Mingw and GNU assembler on windows.
- For Linux platforms, Debian and Ubuntu have been tested so far. For X86_64 
  assembly run: 'make clean asm' from project root. 

A custom tool creates a random blinder on every new build. This blinder is static
and will be part of the library. This blinder is only used for blinding the point 
multiplication when creating blinding context via ed25519_Blinding_Init() API.
Make sure you run the custom tool as part of your regular build.

