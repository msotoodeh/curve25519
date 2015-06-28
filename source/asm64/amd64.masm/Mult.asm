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
; MULSET_S0(YY,BB,XX)
; Out:  CARRY:Y = b*X
; _______________________________________________________________________

MULSET_S0 macro YY,BB,XX
    MULT    XX,BB
    mov     YY,ACL
    endm

; _______________________________________________________________________
; MULSET_S1(YY,BB,XX)
; Out: CARRY:Y = b*X + CARRY
; _______________________________________________________________________

MULSET_S1 macro YY,BB,XX
    mov     C0,ACH
    MULT    XX,BB
    add     ACL,C0
    adc     ACH,0
    mov     YY,ACL
    endm

; _______________________________________________________________________
; MULADD_S0(YY,BB,XX)
; Out:  CARYY:Y = b*X + Y
; _______________________________________________________________________

MULADD_S0 macro YY,BB,XX
    MULT    XX,BB
    add     YY,ACL
    adc     ACH,0
    endm
    
; _______________________________________________________________________
; MULADD_S1(YY,BB,XX)
; Out: CARRY:Y = b*X + Y + CARRY
;      ZF = set if no carry
; _______________________________________________________________________

MULADD_S1 macro YY,BB,XX
    mov     C0,ACH
    MULT    XX,BB
    add     ACL,C0
    adc     ACH,0
    add     YY,ACL
    adc     ACH,0
    endm
     
mulset macro YY,XX
    MULSET_S0 [YY],XX,A0
    MULSET_S1 [YY+8],XX,A1
    MULSET_S1 [YY+16],XX,A2
    MULSET_S1 [YY+24],XX,A3
    mov     [YY+32],ACH
    endm

muladd macro YY,XX
    MULADD_S0 [YY],XX,A0
    MULADD_S1 [YY+8],XX,A1
    MULADD_S1 [YY+16],XX,A2
    MULADD_S1 [YY+24],XX,A3
    mov     [YY+32],ACH
    endm

; _______________________________________________________________________
;
;   void ecp_MulReduce(U64* Z, const U64* X, const U64* Y)
; Uses: A, B, C0
; _______________________________________________________________________
PUBPROC ecp_MulReduce

Z   equ ARG1
X   equ ARG2
Y   equ ARG3

    PushB
    push    Z
    sub     rsp,64                  ; T[8]

T   equ rsp
U   equ rsp+32
    
    LOADA   Y
    LOADB   X

    mulset  T,B0
    muladd  T+8,B1
    muladd  T+16,B2
    muladd  T+24,B3

    ; Now do the size reduction: T[4] + 38*U[4]

    MULADD_W0 A0,[T],[U],38
    MULADD_W1 A1,[T+8],[U+8],38
    MULADD_W1 A2,[T+16],[U+16],38
    MULADD_W1 A3,[T+24],[U+24],38

    MULT    38,ACH
    ADDA    0,0,ACH,ACL

    sbb     ACL,ACL
    and     ACL,38
    ADDA    0,0,0,ACL

    add     rsp,64
    pop     Z
    ; return result
    STOREA  Z

    PopB
    ret
ENDPROC ecp_MulReduce

; _______________________________________________________________________
;
;   void ecp_Mul(U64* Z, const U64* X, const U64* Y)
; _______________________________________________________________________
PUBPROC ecp_Mul

Z   equ ARG1M
X   equ ARG2
Y   equ ARG3

    PushB
    SaveArg1
    LOADA   Y
    LOADB   X

    mulset  Z,B0
    muladd  Z+8,B1
    muladd  Z+16,B2
    muladd  Z+24,B3

    RestoreArg1
    PopB
    ret
ENDPROC ecp_Mul
END