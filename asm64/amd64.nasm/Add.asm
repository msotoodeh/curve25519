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
;   Z = X + Y
;   U64 ecp_Add(U64* Z, const U64* X, const U64* Y) 
; _______________________________________________________________________
%define Z   ARG1
%define X   ARG2
%define Y   ARG3M

    PUBPROC ecp_Add
    SaveArg3
    
    LOADA   X
    xor     ACL,ACL
    ADDA    [Y+24],[Y+16],[Y+8],[Y]
    adc     ACL,ACL
    STOREA  Z
    RestoreArg3
    ret
    
; _______________________________________________________________________
;
;   Z = X + Y
;   void ecp_AddReduce(U64* Z, const U64* X, const U64* Y) 
; _______________________________________________________________________

    PUBPROC ecp_AddReduce
    SaveArg3
    LOADA   X
    ADDA    [Y+24],[Y+16],[Y+8],[Y]
    jnc     short ar_2
ar_1:
    ADDA    0,0,0,38
    jc      short ar_1
ar_2:
    STOREA  Z
    RestoreArg3
    ret

