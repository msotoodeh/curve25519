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

    sbb     ACL,ACL
    and     $38,ACL
    SUBA    $0,$0,$0,ACL

    sbb     ACL,ACL
    and     $38,ACL
    SUBA    $0,$0,$0,ACL

    STOREA  Z
    RestoreArg3
    ret

/* _______________________________________________________________________
/*
/*   void ecp_Mod(U64* X)
/*   Constant-time
/* _______________________________________________________________________ */
    PUBPROC ecp_Mod
.equ  X,  ARG1

    push    C1
    or      $-1,C1
    LOADA   X
    mov     C1,ACH
    mov     $-19,ACL
    shr     $1,ACH
    SUBA    ACH,C1,C1,ACL

    /* Undo SUB if CF=1 */

    sbb     C1,C1               # 0 or -1
    and     C1,ACH              # 0 or 07fffffffffffffffh
    and     C1,ACL              # 0 or -19
    ADDA    ACH,C1,C1,ACL

    /* There could be second P there */
    or      $-1,C1
    mov     C1,ACH
    mov     $-19,ACL
    shr     $1,ACH
    SUBA    ACH,C1,C1,ACL

    /* Undo SUB if CF=1 */

    sbb     C1,C1               # 0 or -1
    and     C1,ACH              # 0 or 07fffffffffffffffh
    and     C1,ACL              # 0 or -19
    ADDA    ACH,C1,C1,ACL

    STOREA  X
    pop     C1
    ret

/* _______________________________________________________________________
/*
/*   compare X and Y, return non-zero if X<Y, else 0
/*   int ecp_CmpLT(const U64* X, const U64* Y)
/* _______________________________________________________________________ */
    PUBPROC ecp_CmpLT
    
.equ  X,  ARG1
.equ  Y,  ARG2

    LOADA   X
    SUBA    24(Y),16(Y),8(Y),(Y)
    SBB     ACL,ACL
    ret
    
/* _______________________________________________________________________
/*
/*   compare X and Y, return non-zero if X != Y, else 0
/*   int ecp_CmpNE(const U64* X, const U64* Y)
/* _______________________________________________________________________ */
    PUBPROC ecp_CmpNE
    
.equ  X,  ARG1
.equ  Y,  ARG2

    mov     24(X),ACL
    mov     16(X),A2
    xor     24(Y),ACL
    xor     16(Y),A2
    mov     8(X),A1
    or      A2,ACL
    xor     8(Y),A1
    mov     (X),A0
    or      A1,ACL
    xor     (Y),A0
    or      A0,ACL
    ret
    
