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
; RL_MSBS(AA,XX)
; Out: AA <<== upper bits of XX.hi, XX.lo
;      XX <<= 1
; _______________________________________________________________________
RL_MSBS macro AA,XX
    shl     XX,1
    rcl     AA,1
    bt      XX,32
    rcl     AA,1
    endm

; _______________________________________________________________________
; RL_MSB(AA,XX)
; Out: Shift in hi-bit of XX 
;      XX <<= 1
; _______________________________________________________________________
RL_MSB  macro AA,XX
    shl     XX,1
    rcl     AA,1
    endm

; _______________________________________________________________________
;
;   void ecp_4Folds(U8* Y, const U64* X)
;   Y is 64-bytes long
; _______________________________________________________________________

PUBPROC ecp_4Folds

Y   equ ARG1
X   equ ARG2

    LOADA   X
    mov     ah,64
f4t_1:
    mov     al,0
    RL_MSB  al,A3
    RL_MSB  al,A2
    RL_MSB  al,A1
    RL_MSB  al,A0
    mov     [Y],al
    inc     Y
    dec     ah
    jnz     short f4t_1
    ret
ENDPROC ecp_4Folds

; _______________________________________________________________________
;
;   void ecp_8Folds(U8* Y, const U64* X) 
;   Y is 32-bytes long
; _______________________________________________________________________

PUBPROC ecp_8Folds

Y   equ ARG1
X   equ ARG2

    LOADA   X
    mov     ah,32
f8t_1:
    RL_MSBS al,A3
    RL_MSBS al,A2
    RL_MSBS al,A1
    RL_MSBS al,A0
    mov     [Y],al
    inc     Y
    dec     ah
    jnz     short f8t_1
    ret
ENDPROC ecp_8Folds

END