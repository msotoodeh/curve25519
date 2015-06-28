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
;   Z = X - Y
;   U64 ecp_Sub(U64* Z, const U64* X, const U64* Y) 
;   Constant-time
; _______________________________________________________________________
PUBPROC ecp_Sub
    
Z   equ ARG1
X   equ ARG2
Y   equ ARG3M

    SaveArg3
    LOADA   X
    SUBA    [Y+24],[Y+16],[Y+8],[Y]
    SBB     ACL,ACL
    STOREA  Z
    RestoreArg3
    ret

ENDPROC ecp_Sub
    
; _______________________________________________________________________
;
;   Z = X - Y
;   void ecp_SubReduce(U64* Z, const U64* X, const U64* Y) 
; _______________________________________________________________________
PUBPROC ecp_SubReduce

    SaveArg3
    LOADA   X
    SUBA    [Y+24],[Y+16],[Y+8],[Y]

    sbb     ACL,ACL
    and     ACL,38
    SUBA    0,0,0,ACL

    sbb     ACL,ACL
    and     ACL,38
    SUBA    0,0,0,ACL

    STOREA  Z
    RestoreArg3
    ret

ENDPROC ecp_SubReduce

; _______________________________________________________________________
;
;   void ecp_Mod(U64* X)
;   Constant-time
; _______________________________________________________________________
PUBPROC ecp_Mod
X   equ ARG1

    push    C1
    or      C1,-1
    LOADA   X
    mov     ACH,C1
    mov     ACL,-19
    shr     ACH,1
    SUBA    ACH,C1,C1,ACL

    ; Undo SUB if CF=1

    sbb     C1,C1               ; 0 or -1
    and     ACH,C1              ; 0 or 07fffffffffffffffh
    and     ACL,C1              ; 0 or -19
    ADDA    ACH,C1,C1,ACL

    ; There could be second P there 
    or      C1,-1
    mov     ACH,C1
    mov     ACL,-19
    shr     ACH,1
    SUBA    ACH,C1,C1,ACL

    ; Undo SUB if CF=1

    sbb     C1,C1               ; 0 or -1
    and     ACH,C1              ; 0 or 07fffffffffffffffh
    and     ACL,C1              ; 0 or -19
    ADDA    ACH,C1,C1,ACL

    STOREA  X
    pop     C1
    ret

ENDPROC ecp_Mod

; _______________________________________________________________________
;
;   Return non-zero if X < Y
;   U64 ecp_CmpLT(const U64* X, const U64* Y) 
;   Constant-time
; _______________________________________________________________________
PUBPROC ecp_CmpLT
    
X   equ ARG1
Y   equ ARG2

    LOADA   X
    SUBA    [Y+24],[Y+16],[Y+8],[Y]
    SBB     ACL,ACL
    ret

ENDPROC ecp_CmpLT
    
; _______________________________________________________________________
;
;   compare X and Y, return 0 if equal, non-zero if different
;   int ecp_CmpNE(const U64* X, const U64* Y) 
; _______________________________________________________________________
PUBPROC ecp_CmpNE
    
X   equ ARG1
Y   equ ARG2

    mov     ACL,[X+24]
    mov     A2,[X+16]
    xor     ACL,[Y+24]
    xor     A2,[Y+16]
    mov     A1,[X+8]
    or      ACL,A2
    xor     A1,[Y+8]
    mov     A0,[X]
    or      ACL,A1
    xor     A0,[Y]
    or      ACL,A0
    ret

ENDPROC ecp_CmpNE
END    