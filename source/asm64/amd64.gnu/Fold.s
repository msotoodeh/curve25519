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

.include "defines.inc"

/* _______________________________________________________________________
// RL_MSBS(AA,XX) */
// Out: AA <<== upper bits of XX.hi
//      XX <<= 1
// _______________________________________________________________________ */
.macro    RL_MSB AA,XX
    shl     $1,\XX
    rcl     $1,\AA
.endm

/* _______________________________________________________________________
//
//   void ecp_4Folds(U8* Y, const U64* X)
// _______________________________________________________________________ */

.equ  Y,  ARG1
.equ  X,  ARG2

    PUBPROC ecp_4Folds

    LOADA   X
    mov     $64,%ah
f4t_1:
    mov     $0,%al
    RL_MSB  %al,A3
    RL_MSB  %al,A2
    RL_MSB  %al,A1
    RL_MSB  %al,A0
    mov     %al,(Y)
    inc     Y
    dec     %ah
    jnz.s   f4t_1
    ret

/* _______________________________________________________________________
// RL_MSBS(AA,XX)
// Out: AA <<== upper bits of XX.hi, XX.lo
//      XX <<= 1
// _______________________________________________________________________ */
.macro    RL_MSBS AA,XX
    shl     $1,\XX
    rcl     $1,\AA
    bt      $32,\XX
    rcl     $1,\AA
.endm

/* _______________________________________________________________________
//
//   void ecp_8Folds(U8* Y, const U64* X)
// _______________________________________________________________________ */

.equ  Y,  ARG1
.equ  X,  ARG2

    PUBPROC ecp_8Folds

    LOADA   X
    mov     $32,%ah
f8t_1:
    RL_MSBS %al,A3
    RL_MSBS %al,A2
    RL_MSBS %al,A1
    RL_MSBS %al,A0
    mov     %al,(Y)
    inc     Y
    dec     %ah
    jnz.s   f8t_1
    ret
    
    
