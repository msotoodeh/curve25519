; 
; Copyright Mehdi Sotoodeh.  All rights reserved. 
; <mehdisotoodeh@gmail.com>
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that source code retains the 
; above copyright notice and following disclaimer.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
; A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
; OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
; SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
; LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

    ; ZF set if ACH == 0
    jz      mr_2
    MULT    38,ACH
    ADDA    0,0,ACH,ACL
    jnc     mr_2
    
mr_1:
    ADDA    0,0,0,38
    jc      mr_1
    
mr_2:
    add     rsp,64
    pop     Z
    ; return result
    STOREA  Z

    PopB
    ret
ENDPROC ecp_MulReduce
END
