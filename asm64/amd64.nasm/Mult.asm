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

%include "defines.inc"

; _______________________________________________________________________
; MULSET_S0(YY,BB,XX)
; Out:  CARRY:Y = b*X
; _______________________________________________________________________

%macro MULSET_S0 3
    MULT    %3,%2
    mov     %1,ACL
%endmacro

; _______________________________________________________________________
; MULSET_S1(YY,BB,XX)
; Out: CARRY:Y = b*X + CARRY
; _______________________________________________________________________

%macro MULSET_S1 3
    mov     C0,ACH
    MULT    %3,%2
    add     ACL,C0
    adc     ACH,0
    mov     %1,ACL
%endmacro

; _______________________________________________________________________
; MULADD_S0(YY,BB,XX)
; Out:  CARYY:Y = b*X + Y
; _______________________________________________________________________

%macro MULADD_S0 3
    MULT    %3,%2
    add     %1,ACL
    adc     ACH,0
%endmacro
    
; _______________________________________________________________________
; MULADD_S1(YY,BB,XX)
; Out: CARRY:Y = b*X + Y + CARRY
;      ZF = set if no carry
; _______________________________________________________________________

%macro MULADD_S1 3
    mov     C0,ACH
    MULT    %3,%2
    add     ACL,C0
    adc     ACH,0
    add     %1,ACL
    adc     ACH,0
%endmacro
     
%macro mulset 2
    MULSET_S0 [%1],%2,A0
    MULSET_S1 [%1+8],%2,A1
    MULSET_S1 [%1+16],%2,A2
    MULSET_S1 [%1+24],%2,A3
    mov     [%1+32],ACH
%endmacro

%macro muladd 2
    MULADD_S0 [%1],%2,A0
    MULADD_S1 [%1+8],%2,A1
    MULADD_S1 [%1+16],%2,A2
    MULADD_S1 [%1+24],%2,A3
    mov     [%1+32],ACH
%endmacro

; _______________________________________________________________________
;
;   void ecp_MulReduce(U64* Z, const U64* X, const U64* Y)
; Uses: A, B, C0
; _______________________________________________________________________
    PUBPROC ecp_MulReduce

%define Z   ARG1
%define X   ARG2
%define Y   ARG3

    PushB
    push    Z
    sub     rsp,64                  ; T[8]

%define T   rsp
%define U   rsp+32
    
    LOADA   Y
    LOADB   X

    mulset  T,   B0
    muladd  T+8, B1
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

; _______________________________________________________________________
;
;   void ecp_Mul(U64* Z, const U64* X, const U64* Y)
; _______________________________________________________________________
    PUBPROC ecp_Mul

%define Z   ARG1M
%define X   ARG2
%define Y   ARG3

    PushB
    SaveArg1
    
    LOADA   Y
    LOADB   X

    mulset  Z,   B0
    muladd  Z+8, B1
    muladd  Z+16,B2
    muladd  Z+24,B3

    RestoreArg1
    PopB
    ret