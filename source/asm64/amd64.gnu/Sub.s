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
/*   Z = X - Y
/*   U64 ecp_Sub(U64* Z, const U64* X, const U64* Y)
/* _______________________________________________________________________ */
    PUBPROC ecp_Sub
    
.equ  Z,  ARG1
.equ  X,  ARG2
.equ  Y,  ARG3M

    SaveArg3
    LOADA   X
    SUBA    24(Y),16(Y),8(Y),(Y)
    SBB     ACL,ACL
    STOREA  Z
    RestoreArg3
    ret
    
/* _______________________________________________________________________
/*
/*   Z = X - Y
/*   void ecp_SubReduce(U64* Z, const U64* X, const U64* Y)
/* _______________________________________________________________________ */
    PUBPROC ecp_SubReduce
    
    SaveArg3
    LOADA   X
    SUBA    24(Y),16(Y),8(Y),(Y)
    jnc.s   sr_2
sr_1:
    /* add maxP = 2*P */
    ADDA    $-1,$-1,$-1,$-38
    jnc.s   sr_1
sr_2:
    STOREA  Z
    RestoreArg3
    ret

/* _______________________________________________________________________
/*
/*   compare X and Y, return -1,0,+1
/*   int ecp_Cmp(const U64* X, const U64* Y)
/* _______________________________________________________________________ */
    PUBPROC ecp_Cmp
    
.equ  X,  ARG1
.equ  Y,  ARG2

    mov     24(X),ACL
    sub     24(Y),ACL
    jnz.s   cmp_1
    mov     16(X),ACL
    sub     16(Y),ACL
    jnz.s   cmp_1
    mov     8(X),ACL
    sub     8(Y),ACL
    jnz.s   cmp_1
    mov     (X),ACL
    sub     (Y),ACL
    jz.s    cmp_2
cmp_1:
    sbb     ACL,ACL
    lea     1(ACL,ACL),ACL
cmp_2:
    ret
    
    
