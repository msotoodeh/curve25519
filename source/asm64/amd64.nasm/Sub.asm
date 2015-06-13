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
;
;   Z = X - Y
;   U64 ecp_Sub(U64* Z, const U64* X, const U64* Y) 
; _______________________________________________________________________
    PUBPROC ecp_Sub
    
%define Z   ARG1
%define X   ARG2
%define Y   ARG3M

    SaveArg3
    LOADA   X
    SUBA    [Y+24],[Y+16],[Y+8],[Y]
    SBB     ACL,ACL
    STOREA  Z
    RestoreArg3
    ret
    
; _______________________________________________________________________
;
;   Z = X - Y
;   void ecp_SubReduce(U64* Z, const U64* X, const U64* Y) 
; _______________________________________________________________________
    PUBPROC ecp_SubReduce
    
    SaveArg3
    LOADA   X
    SUBA    [Y+24],[Y+16],[Y+8],[Y]
    jnc     sr_2
sr_1:
    ; add maxP = 2*P
    ADDA    -1,-1,-1,-38
    jnc     sr_1
sr_2:
    STOREA  Z
    RestoreArg3
    ret

%undef X
%undef Y
%undef Z

; _______________________________________________________________________
;
;   compare X and Y, return -1,0,+1
;   int ecp_Cmp(const U64* X, const U64* Y) 
; _______________________________________________________________________
    PUBPROC ecp_Cmp
    
%define X   ARG1
%define Y   ARG2

    mov     ACL,[X+24]
    sub     ACL,[Y+24]
    jnz     cmp_1
    mov     ACL,[X+16]
    sub     ACL,[Y+16]
    jnz     cmp_1
    mov     ACL,[X+8]
    sub     ACL,[Y+8]
    jnz     cmp_1
    mov     ACL,[X]
    sub     ACL,[Y]
    jz      cmp_2
cmp_1:
    sbb     ACL,ACL
    lea     ACL,[ACL*2+1]
cmp_2:
    ret
    