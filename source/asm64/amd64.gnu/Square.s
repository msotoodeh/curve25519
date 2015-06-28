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

/* _______________________________________________________________________ */
/* */
/*   void ecp_SqrReduce(U64* Y, const U64* X) */
/* _______________________________________________________________________ */
    PUBPROC ecp_SqrReduce

.equ  Y,  ARG1
.equ  X,  ARG2M

    PushB
    push    C1
    SaveArg2
    push    Y
    sub     $64,%rsp                /* T(8) */

.equ  T,  %rsp
                                    /* B3 | B2 | B1 | B0 | A3 | A2 | A1 | A0 */
    MULSET  A2,A1, (X),   8(X)      /*    |         |         |  x0*x1  |    */
    MULSET  B0,A3, (X),  24(X)      /*    |         |  x0*x3  |  x0*x1  |    */
    MULSET  B2,B1, 16(X),24(X)      /*    |  x2*x3  |  x0*x3  |  x0*x1  |    */
    
                                    /*           C1 | C0 | B3 | A0           */
    MULSET  B3,A0, (X), 16(X)       /*         |         |  x0*x2  |         */
    MULSET  C1,C0, 8(X),24(X)       /*         |  x1*x3  |         |         */
    MULADD  C0,B3, 8(X),16(X)       /* +  |         |  x1*x2  |              */
    adc     $0,C1                   /* carry will be 0 here always */

    ADD4    B1,B0,A3,A2, C1,C0,B3,A0
    adc     $0,B2
    
    /* Multiply by 2 */
    shl     $1,A1
    rcl     $1,A2
    rcl     $1,A3
    rcl     $1,B0
    rcl     $1,B1
    rcl     $1,B2
    sbb     B3,B3
    neg     B3
    
    /* add diagonal values           ; y7 | y6 | y5 | y4 | y3 | y2 | y1 | y0 */
    SQRSET  8(T), (T),    (X)       /*         |         |         |  x0*x0  */
    SQRSET  24(T),16(T), 8(X)       /*         |         |  x1*x1  |         */
    SQRSET  40(T),32(T),16(X)       /*         |  x2*x2  |         |         */
    SQRSET  56(T),48(T),24(X)       /*  x3*x3  |         |         |         */
    
    ADD4    32(T),24(T),16(T),8(T), B0,A3,A2,A1
    adc     B1,40(T)
    adc     B2,48(T)
    adc     B3,56(T)

    /* Now do the size reduction: T(4) + 38*U(4) */

    MULADD_W0 A0,(T),32(T),$38
    MULADD_W1 A1,8(T),40(T),$38
    MULADD_W1 A2,16(T),48(T),$38
    MULADD_W1 A3,24(T),56(T),$38

    MULT    $38,ACH
    ADDA    $0,$0,ACH,ACL
    
    sbb     ACL,ACL
    and     $38,ACL
    ADDA    $0,$0,$0,ACL

    add     $64,%rsp
    pop     ACH
    /* return result */
    STOREA  ACH

    RestoreArg2
    pop     C1
    PopB
    ret
    
    
