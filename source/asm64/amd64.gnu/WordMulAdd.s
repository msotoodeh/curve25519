/* The MIT License (MIT)
 * 
 * Copyright (c) 2015 mehdi sotoodeh
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject to 
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

.include "defines.inc"

/* _______________________________________________________________________
/*
/*   Z(4) = Y(4) + b*X(4)    mod 2**255-19
/*   void ecp_WordMulAddReduce(U64 *Z, const U64* Y, U64 b, const U64* X)
/*   Constant-time
/* _______________________________________________________________________ */
    PUBPROC ecp_WordMulAddReduce

    SaveArg2
    SaveArg3
    SaveArg4

.equ  Z,  ARG1
.equ  Y,  ARG2M
.equ  b,  ARG3M
.equ  X,  ARG4M

    MULADD_W0 A0,(Y),b,(X)
    MULADD_W1 A1,8(Y),b,8(X)
    MULADD_W1 A2,16(Y),b,16(X)
    MULADD_W1 A3,24(Y),b,24(X)

    MULT    $38,ACH
    ADDA    $0,$0,ACH,ACL
    
    sbb     ACL,ACL
    and     $38,ACL
    ADDA    $0,$0,$0,ACL

    /* return result */
    STOREA  Z

    RestoreArg4
    RestoreArg3
    RestoreArg2
    ret
    
/* _______________________________________________________________________
/*
/*   C:Z(5) = Y(5) + b*X(4)
/*   U64 ecp_WordMulAdd(U64 *Z, const U64* Y, U64 b, const U64* X)
/* _______________________________________________________________________ */
    PUBPROC ecp_WordMulAdd

    SaveArg2
    SaveArg3
    SaveArg4

.equ  Z,  ARG1
.equ  Y,  ARG2M
.equ  b,  ARG3M
.equ  X,  ARG4M

    MULADD_W0 A0,(Y),b,(X)
    MULADD_W1 A1,8(Y),b,8(X)
    MULADD_W1 A2,16(Y),b,16(X)
    MULADD_W1 A3,24(Y),b,24(X)
    STOREA  Z
    xor     ACL,ACL
    add     32(Y),ACH
    adc     ACL,ACL
    mov     ACH,32(Z)

    RestoreArg4
    RestoreArg3
    RestoreArg2
    ret

/* _______________________________________________________________________
/*
/*   Y(5) = b*X(4)
/*   void ecp_WordMulSet(U64 *Y, U64 b, const U64* X)
/* _______________________________________________________________________ */
    PUBPROC ecp_WordMulSet

    SaveArg2
    SaveArg3

.equ  Y,  ARG1
.equ  b,  ARG2M
.equ  X,  ARG3M

    MULSET_W0 A0,b,(X)
    MULSET_W1 A1,b,8(X)
    MULSET_W1 A2,b,16(X)
    MULSET_W1 A3,b,24(X)
    STOREA  Y
    mov     ACH,32(Y)
    RestoreArg3
    RestoreArg2
    ret

# _______________________________________________________________________
#
#   Calculate: Y = [b:X] mod BPO
#   void eco_ReduceHiWord(U64* Y, U64 b, const U64* X)
#
#   Return Y = X + b*R mod BPO, where R = 2^256 mod BPO
#   Since -R is 129-bits, we can save some multiplication by
#   calculating: Y = X - b*(-R) mod BPO
#   -R mod BPO = { 0x812631A5CF5D3ED0,0x4DEF9DEA2F79CD65,1,0 }#
# _______________________________________________________________________
    PUBPROC eco_ReduceHiWord

    PushB
    SaveArg1

.equ  Y,  ARG1M
.equ  b,  ARG2
.equ  X,  ARG3

    mov     b,B2
    LOADA   X

    MULSET  B1,B0,$0x812631A5CF5D3ED0,B2
    MULT    $0x4DEF9DEA2F79CD65,B2
    xor     B3,B3
    add     ACL,B1
    adc     ACH,B2
    adc     B3,B3

    SUBA    B3,B2,B1,B0

    # Add BPO if there is a carry
    sbb     ACL,ACL

    # B = BPO & carry
    mov     $0x5812631A5CF5D3ED,B0
    mov     $0x14DEF9DEA2F79CD6,B1
    xor     B2,B2
    mov     $0x1000000000000000,B3

    and     ACL,B0
    and     ACL,B1
    and     ACL,B3
    ADDA    B3,B2,B1,B0

    STOREA  Y

    RestoreArg1
    PopB
    ret
  
