/* 
 * Copyright Mehdi Sotoodeh.  All rights reserved. 
 * <mehdisotoodeh@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that source code retains the 
 * above copyright notice and following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "curve25519_mehdi.h"

/* Trim private key   */
void ecp_TrimSecretKey(U8 *X)
{
    X[0] &= 0xf8;
    X[31] = (X[31] | 0x40) & 0x7f;
}

/* Convert big-endian byte array to little-endian byte array and vice versa */
U8* ecp_ReverseByteOrder(OUT U8 *Y, IN const U8 *X)
{
    int i;
    for (i = 0; i < 32; i++) Y[i] = X[31-i];
    return Y;
}

/* Convert little-endian byte array to little-endian word array */
U64* ecp_BytesToWords(OUT U64 *Y, IN const U8 *X)
{
    int i;
    M64 m;
    
    for (i = 0; i < 4; i++)
    {
        m.u8.b0 = *X++;
        m.u8.b1 = *X++;
        m.u8.b2 = *X++;
        m.u8.b3 = *X++;
        m.u8.b4 = *X++;
        m.u8.b5 = *X++;
        m.u8.b6 = *X++;
        m.u8.b7 = *X++;
        
        Y[i] = m.u64;
    }
    return Y;
}

/* Convert little-endian word array to little-endian byte array */
U8* ecp_WordsToBytes(OUT U8 *Y, IN const U64 *X)
{
    int i;
    M64 m;
    
    for (i = 0; i < 32;)
    {
        m.u64 = *X++;
        Y[i++] = m.u8.b0;
        Y[i++] = m.u8.b1;
        Y[i++] = m.u8.b2;
        Y[i++] = m.u8.b3;
        Y[i++] = m.u8.b4;
        Y[i++] = m.u8.b5;
        Y[i++] = m.u8.b6;
        Y[i++] = m.u8.b7;
    }
    return Y;
}

U8* ecp_EncodeInt(OUT U8 *Y, IN const U64 *X, IN U8 parity)
{
    int i;
    M64 m;
    
    for (i = 0; i < 24;)
    {
        m.u64 = *X++;
        Y[i++] = m.u8.b0;
        Y[i++] = m.u8.b1;
        Y[i++] = m.u8.b2;
        Y[i++] = m.u8.b3;
        Y[i++] = m.u8.b4;
        Y[i++] = m.u8.b5;
        Y[i++] = m.u8.b6;
        Y[i++] = m.u8.b7;
    }

    m.u64 = *X;
    Y[24] = m.u8.b0;
    Y[25] = m.u8.b1;
    Y[26] = m.u8.b2;
    Y[27] = m.u8.b3;
    Y[28] = m.u8.b4;
    Y[29] = m.u8.b5;
    Y[30] = m.u8.b6;
    Y[31] = (U8)((m.u8.b7 & 0x7f) | (parity << 7));

    return Y;
}

U8 ecp_DecodeInt(OUT U64 *Y, IN const U8 *X)
{
    int i;
    M64 m;
    
    for (i = 0; i < 3; i++)
    {
        m.u8.b0 = *X++;
        m.u8.b1 = *X++;
        m.u8.b2 = *X++;
        m.u8.b3 = *X++;
        m.u8.b4 = *X++;
        m.u8.b5 = *X++;
        m.u8.b6 = *X++;
        m.u8.b7 = *X++;
        
        Y[i] = m.u64;
    }

    m.u8.b0 = *X++;
    m.u8.b1 = *X++;
    m.u8.b2 = *X++;
    m.u8.b3 = *X++;
    m.u8.b4 = *X++;
    m.u8.b5 = *X++;
    m.u8.b6 = *X++;
    m.u8.b7 = *X & 0x7f;
        
    Y[3] = m.u64;

    return (U8)((*X >> 7) & 1);
}