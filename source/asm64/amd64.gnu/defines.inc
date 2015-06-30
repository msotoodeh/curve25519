/* The MIT License (MIT)
 * 
 * Copyright (c) 2015 mehdi sotoodeh
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject to 
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
    Definitions for GNU assembler
    ABI: gcc
 */

/* Restore these registers across calls: rsp, rbx, rbp, r12,r13,r14,r15 */

/* 128-bit accumulator */
.equ ACL,     %rax
.equ ACH,     %rdx 
.equ CARRY,   ACH

/* 256-bit accumulator-A */
/* Accumulator-A uses volatile registers */
.equ A0,      %r8
.equ A1,      %r9
.equ A2,      %r10
.equ A3,      %r11

/* 256-bit accumulator-B */
.equ B0,      %r12
.equ B1,      %r13
.equ B2,      %r14
.equ B3,      %r15

.equ C0,      %rcx
.equ C1,      %rbx
.equ C2,      %rdi
.equ C3,      %rsi
.equ C4,      %rbp

.ifdef MSVC
/* From left to right */
.equ ARG1,    %rcx
.equ ARG2,    %rdx
.equ ARG3,    %r8
.equ ARG4,    %r9

/* ARG switching */
.equ ARG1M,   %rdi
.equ ARG2M,   %rsi
.equ ARG3M,   %rbx
.equ ARG4M,   %rbp

.macro  SaveArg1
    push    ARG1M
    mov     ARG1,ARG1M
.endm

.macro  RestoreArg1
    pop     ARG1M
.endm

.macro  SaveArg2
    push    ARG2M
    mov     ARG2,ARG2M
.endm

.macro  RestoreArg2
    pop     ARG2M
.endm

.macro  SaveArg3
    push    ARG3M
    mov     ARG3,ARG3M
.endm

.macro  RestoreArg3
    pop     ARG3M
.endm

.macro  SaveArg4
    push    ARG4M
    mov     ARG4,ARG4M
.endm

.macro  RestoreArg4
    pop     ARG4M
.endm
.else
/* From left to right */
.equ ARG1,    %rdi
.equ ARG2,    %rsi
.equ ARG3,    %rdx
.equ ARG4,    %rcx
.equ ARG5,    %r8
.equ ARG6,    %r9

/* ARG switching */
.equ ARG1M,   %rdi
.equ ARG2M,   %rsi
.equ ARG3M,   %rbx
.equ ARG4M,   %rbp

.macro  SaveArg1
.endm

.macro  RestoreArg1
.endm

.macro  SaveArg2
.endm

.macro  RestoreArg2
.endm

.macro  SaveArg3
    push    ARG3M
    mov     ARG3,ARG3M
.endm

.macro  RestoreArg3
    pop     ARG3M
.endm

.macro  SaveArg4
    push    ARG4M
    mov     ARG4,ARG4M
.endm

.macro  RestoreArg4
    pop     ARG4M
.endm
.endif

.macro  PUBPROC pname
.text
.align 8
.globl \pname
\pname:
.endm

.macro  PushB
    push    B3
    push    B2
    push    B1
    push    B0
.endm

.macro  PopB
    pop     B0
    pop     B1
    pop     B2
    pop     B3
.endm

.macro  LOADA addr
    mov     24(\addr),A3
    mov     16(\addr),A2
    mov     8(\addr),A1
    mov     (\addr),A0
.endm

.macro  STOREA addr
    mov     A3,24(\addr)
    mov     A2,16(\addr)
    mov     A1,8(\addr)
    mov     A0,(\addr)
.endm

.macro  LOADB addr
    mov     24(\addr),B3
    mov     16(\addr),B2
    mov     8(\addr),B1
    mov     (\addr),B0
.endm

.macro  STOREB addr
    mov     B3,24(\addr)
    mov     B2,16(\addr)
    mov     B1,8(\addr)
    mov     B0,(\addr)
.endm

/* _______________________________________________________________________ 
// 
// Out:  Y += X 
// _______________________________________________________________________ */

.macro  ADD4 y3,y2,y1,y0, x3,x2,x1,x0
    add     \x0, \y0
    adc     \x1, \y1
    adc     \x2, \y2
    adc     \x3, \y3
.endm

.macro  ADDA x3,x2,x1,x0
    ADD4 A3,A2,A1,A0, \x3,\x2,\x1,\x0
.endm

.macro  ADDB x3,x2,x1,x0
    ADD4 B3,B2,B1,B0, \x3,\x2,\x1,\x0
.endm

/* _______________________________________________________________________ 
// 
// Out:  Y -= X 
// _______________________________________________________________________ */

.macro  SUB4 y3,y2,y1,y0, x3,x2,x1,x0
    sub     \x0, \y0
    sbb     \x1, \y1
    sbb     \x2, \y2
    sbb     \x3, \y3
.endm
    
.macro  SUBA x3,x2,x1,x0
    SUB4 A3,A2,A1,A0, \x3,\x2,\x1,\x0
.endm

.macro  SUBB x3,x2,x1,x0
    SUB4 B3,B2,B1,B0, \x3,\x2,\x1,\x0
.endm

/* _______________________________________________________________________ 
// MULT(a,b) 
// IN:   a, b 
// Out:  ACH:ACL = a*b 
// _______________________________________________________________________ */
.macro  MULT XX,YY
    mov     \XX,ACL
    mulq    \YY
.endm
   
/* _______________________________________________________________________
// MULSET(u,v,a,b)
// IN:   a, b
// Out:  u:v = a*b
// _______________________________________________________________________ */
.macro  MULSET u,v,a,b
    MULT    \a,\b
    mov     ACL,\v
    mov     ACH,\u
.endm
   
/* _______________________________________________________________________
// MULADD (u,v,a,b)
// IN:   a, b
// Out:  u:v += a*b
// _______________________________________________________________________ */
.macro  MULADD u,v,a,b
    MULT    \a,\b
    add     ACL,\v
    adc     ACH,\u
.endm

/* _______________________________________________________________________
//
// IN:   a
// Out:  ACH:ACL = a*a
// _______________________________________________________________________ */
.macro  SQR  a
    mov     \a,ACL
    mul     ACL
.endm

/* _______________________________________________________________________
// SQRSET(u,v,a)
// IN:   a
// Out:  u:v = a*a
// _______________________________________________________________________ */
.macro  SQRSET u,v,a
    SQR     \a
    mov     ACL,\v
    mov     ACH,\u
.endm

/* _______________________________________________________________________
// SQRADD(u,v,a)
// IN:   a
// Out:  u:v += a*a
// _______________________________________________________________________ */
.macro  SQRADD u,v,a
    SQR     \a
    add     ACL,\v
    adc     ACH,\u
.endm

/* _______________________________________________________________________
// MULADD_W0(ZZ,YY,BB,XX)
// Out:  CARRY:Z = b*X + Y
// _______________________________________________________________________ */

.macro  MULADD_W0 ZZ,YY,BB,XX
    MULT    \XX,\BB
    add     \YY,ACL
    adc     $0,ACH
    mov     ACL,\ZZ
.endm

/* _______________________________________________________________________
// MULADD_W1(ZZ,YY,BB,XX)
// Out: CARRY:Z = b*X + Y + CARRY
//      ZF = set if no carry
// _______________________________________________________________________ */

.macro  MULADD_W1 ZZ,YY,BB,XX
    mov     ACH,\ZZ
    MULT    \XX,\BB
    add     \YY,ACL
    adc     $0,ACH
    add     ACL,\ZZ
    adc     $0,ACH
.endm

/* _______________________________________________________________________
// MULSET_W0(YY,BB,XX)
// Out:  CARRY:Y = b*X
// _______________________________________________________________________ */

.macro  MULSET_W0 YY,BB,XX
    MULT    \XX,\BB
    mov     ACL,\YY
.endm

/* _______________________________________________________________________
// MULSET_W1(YY,BB,XX)
// Out: CARRY:Y = b*X + CARRY
//      ZF = set if no carry
// _______________________________________________________________________ */

.macro  MULSET_W1 YY,BB,XX
    mov     ACH,\YY
    MULT    \XX,\BB
    add     ACL,\YY
    adc     $0,ACH
.endm

