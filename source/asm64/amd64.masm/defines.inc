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

; MASM macros

PUBPROC macro pname
_TEXT segment
PUBLIC pname
pname PROC
    endm

ENDPROC macro pname
pname ENDP
_TEXT ends
    endm

; Restore these registers across calls: rsp, rbx, rbp, rdi, rsi, r12,r13,r14,r15

; 128-bit accumulator
ACL     equ rax
ACH     equ rdx 
CARRY   equ ACH

; 256-bit accumulator-A
; Accumulator-A uses volatile registers
A0      equ r8
A1      equ r9
A2      equ r10
A3      equ r11

; 256-bit accumulator-B
B0      equ r12
B1      equ r13
B2      equ r14
B3      equ r15

C0      equ rcx
C1      equ rbx
C2      equ rdi
C3      equ rsi
C4      equ rbp

; From left to right
ARG1    equ rcx
ARG2    equ rdx
ARG3    equ r8
ARG4    equ r9

; ARG switching 
ARG1M   equ rdi
ARG2M   equ rsi
ARG3M   equ rbx
ARG4M   equ rbp

SaveArg1 macro
    push    ARG1M
    mov     ARG1M,ARG1
    endm

RestoreArg1 macro
    pop     ARG1M
    endm

SaveArg2 macro
    push    ARG2M
    mov     ARG2M,ARG2
    endm

RestoreArg2 macro
    pop     ARG2M
    endm

SaveArg3 macro
    push    ARG3M
    mov     ARG3M,ARG3
    endm

RestoreArg3 macro
    pop     ARG3M
    endm

SaveArg4 macro
    push    ARG4M
    mov     ARG4M,ARG4
    endm

RestoreArg4 macro
    pop     ARG4M
    endm

PushB macro
    push    B3
    push    B2
    push    B1
    push    B0
    endm

PopB macro
    pop     B0
    pop     B1
    pop     B2
    pop     B3
    endm

LOADA macro XX
    mov     A3,[XX+24]
    mov     A2,[XX+16]
    mov     A1,[XX+8]
    mov     A0,[XX]
    endm

STOREA macro XX
    mov     [XX+24],A3
    mov     [XX+16],A2
    mov     [XX+8],A1
    mov     [XX],A0
    endm

LOADB macro XX
    mov     B3,[XX+24]
    mov     B2,[XX+16]
    mov     B1,[XX+8]
    mov     B0,[XX]
    endm

STOREB macro XX
    mov     [XX+24],B3
    mov     [XX+16],B2
    mov     [XX+8],B1
    mov     [XX],B0
    endm

; _______________________________________________________________________
;
; Out:  Y += X
; _______________________________________________________________________

ADD4 macro y3,y2,y1,y0, x3,x2,x1,x0
    add     y0,x0
    adc     y1,x1
    adc     y2,x2
    adc     y3,x3
    endm

ADDA macro x3,x2,x1,x0
    ADD4 A3,A2,A1,A0, x3,x2,x1,x0
    endm

ADDB macro x3,x2,x1,x0
    ADD4 B3,B2,B1,B0, x3,x2,x1,x0
    endm

; _______________________________________________________________________
;
; Out:  Y -= X
; _______________________________________________________________________

SUB4 macro y3,y2,y1,y0, x3,x2,x1,x0
    sub     y0,x0
    sbb     y1,x1
    sbb     y2,x2
    sbb     y3,x3
    endm
    
SUBA macro x3,x2,x1,x0
    SUB4 A3,A2,A1,A0, x3,x2,x1,x0
    endm

SUBB macro x3,x2,x1,x0
    SUB4 B3,B2,B1,B0, x3,x2,x1,x0
    endm

; _______________________________________________________________________
; MULT(a,b)
; IN:   a, b
; Out:  ACH:ACL = a*b
; _______________________________________________________________________
MULT macro a,b
    mov     ACL,a
    mul     qword ptr b
    endm
   
; _______________________________________________________________________
; MULSET(u,v,a,b)
; IN:   a, b
; Out:  u:v = a*b
; _______________________________________________________________________
MULSET macro u,v,a,b
    MULT    a,b
    mov     v,ACL
    mov     u,ACH
    endm
   
; _______________________________________________________________________
; MULADD (u,v,a,b)
; IN:   a, b
; Out:  u:v += a*b
; _______________________________________________________________________
MULADD macro u,v,a,b
    MULT    a,b
    add     v,ACL
    adc     u,ACH
    endm

; _______________________________________________________________________
;
; IN:   a
; Out:  ACH:ACL = a*a
; _______________________________________________________________________
SQR  macro a
    mov     ACL,a
    mul     ACL
    endm

; _______________________________________________________________________
; SQRSET(u,v,a)
; IN:   a
; Out:  u:v = a*a
; _______________________________________________________________________
SQRSET macro u,v,a
    SQR     a
    mov     v,ACL
    mov     u,ACH
    endm

; _______________________________________________________________________
; SQRADD(u,v,a)
; IN:   a
; Out:  u:v += a*a
; _______________________________________________________________________
SQRADD macro u,v,a
    SQR     a
    add     v,ACL
    adc     u,ACH
    endm

; _______________________________________________________________________
; MULADD_W0(ZZ,YY,BB,XX)
; Out:  CARRY:Z = b*X + Y
; _______________________________________________________________________

MULADD_W0 macro ZZ,YY,BB,XX
    MULT    XX,BB
    add     ACL,YY
    adc     ACH,0
    mov     ZZ,ACL
    endm

; _______________________________________________________________________
; MULADD_W1(ZZ,YY,BB,XX)
; Out: CARRY:Z = b*X + Y + CARRY
;      ZF = set if no carry
; _______________________________________________________________________

MULADD_W1 macro ZZ,YY,BB,XX
    mov     ZZ,ACH
    MULT    XX,BB
    add     ACL,YY
    adc     ACH,0
    add     ZZ,ACL
    adc     ACH,0
    endm

; _______________________________________________________________________
; MULSET_W0(YY,BB,XX)
; Out:  CARRY:Y = b*X
; _______________________________________________________________________

MULSET_W0 macro YY,BB,XX
    MULT    XX,BB
    mov     YY,ACL
    endm

; _______________________________________________________________________
; MULSET_W1(YY,BB,XX)
; Out: CARRY:Y = b*X + CARRY
;      ZF = set if no carry
; _______________________________________________________________________

MULSET_W1 macro YY,BB,XX
    mov     YY,ACH
    MULT    XX,BB
    add     YY,ACL
    adc     ACH,0
    endm

