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
/*   Z = X + Y
/*   U64 ecp_Add(U64* Z, const U64* X, const U64* Y)
/* _______________________________________________________________________ */
.equ  Z,  ARG1
.equ  X,  ARG2
.equ  Y,  ARG3

    PUBPROC ecp_Add
    
    LOADA   Y
    xor     ACL,ACL
    ADDA    24(X),16(X),8(X),(X)
    adc     ACL,ACL
    STOREA  Z
    ret
    
/* _______________________________________________________________________
/*
/*   Z = X + Y
/*   void ecp_AddReduce(U64* Z, const U64* X, const U64* Y)
/*   Constant-time
/* _______________________________________________________________________ */

    PUBPROC ecp_AddReduce
    
    LOADA   Y
    ADDA    24(X),16(X),8(X),(X)
    
    sbb     ACL,ACL
    and     $38,ACL
    ADDA    $0,$0,$0,ACL
    
    sbb     ACL,ACL
    and     $38,ACL
    ADDA    $0,$0,$0,ACL
    
    STOREA  Z
    ret

