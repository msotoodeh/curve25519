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
    
;undef X
;undef Y
;undef Z
;undef b

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

;undef X
;undef Y
;undef Z
;undef b

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