;  The MIT License (MIT)
; 
; Copyright (c) 2015 mehdi sotoodeh
; 
; Permission is hereby granted, free of charge, to any person obtaining 
; a copy of this software and associated documentation files (the 
; "Software"), to deal in the Software without restriction, including 
; without limitation the rights to use, copy, modify, merge, publish, 
; distribute, sublicense, and/or sell copies of the Software, and to 
; permit persons to whom the Software is furnished to do so, subject to 
; the following conditions:
; 
; The above copyright notice and this permission notice shall be included 
; in all copies or substantial portions of the Software.
; 
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
; OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
; IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
; CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
; TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
; SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
;

include defines.inc

; _______________________________________________________________________
;
;   Z[4] = Y[4] + b*X[4]    mod 2**255-19
;   void ecp_WordMulAddReduce(U64 *Z, const U64* Y, U64 b, const U64* X) 
; _______________________________________________________________________
PUBPROC ecp_WordMulAddReduce

    SaveArg2
    SaveArg3
    SaveArg4

Z   equ ARG1
Y   equ ARG2M
b   equ ARG3M
X   equ ARG4M

    MULADD_W0 A0,[Y],b,[X]
    MULADD_W1 A1,[Y+8],b,[X+8]
    MULADD_W1 A2,[Y+16],b,[X+16]
    MULADD_W1 A3,[Y+24],b,[X+24]

    ; ZF set if ACH == 0
    jz      wma_2
    MULT    38,ACH
    ADDA    0,0,ACH,ACL
    jnc     wma_2
    
wma_1:
    ADDA    0,0,0,38
    jc      wma_1
    
wma_2:
    ; return result
    STOREA  Z

    RestoreArg4
    RestoreArg3
    RestoreArg2
    ret
ENDPROC ecp_WordMulAddReduce
    
; _______________________________________________________________________
;
;   C:Z[5] = Y[5] + b*X[4]
;   U64 ecp_WordMulAdd(U64 *Z, const U64* Y, U64 b, const U64* X) 
; _______________________________________________________________________
PUBPROC ecp_WordMulAdd

    SaveArg2
    SaveArg3
    SaveArg4

Z   equ ARG1
Y   equ ARG2M
b   equ ARG3M
X   equ ARG4M

    MULADD_W0 A0,[Y],b,[X]
    MULADD_W1 A1,[Y+8],b,[X+8]
    MULADD_W1 A2,[Y+16],b,[X+16]
    MULADD_W1 A3,[Y+24],b,[X+24]
    STOREA  Z
    xor     ACL,ACL
    add     ACH,[Y+32]
    adc     ACL,ACL
    mov     [Z+32],ACH

    RestoreArg4
    RestoreArg3
    RestoreArg2
    ret
ENDPROC ecp_WordMulAdd

; _______________________________________________________________________
;
;   Y[5] = b*X[4]
;   void ecp_WordMulSet(U64 *Y, U64 b, const U64* X) 
; _______________________________________________________________________
PUBPROC ecp_WordMulSet

    SaveArg2
    SaveArg3

Y   equ ARG1
b   equ ARG2M
X   equ ARG3M

    MULSET_W0 A0,b,[X]
    MULSET_W1 A1,b,[X+8]
    MULSET_W1 A2,b,[X+16]
    MULSET_W1 A3,b,[X+24]
    STOREA  Y
    mov     [Y+32],ACH
    RestoreArg3
    RestoreArg2
    ret
ENDPROC ecp_WordMulSet
END