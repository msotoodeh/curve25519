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

// Trim private key  
void ecp_TrimSecretKey(U8 *X)
{
    X[0] &= 0xf8;
    X[31] = (X[31] | 0x40) & 0x7f;
}

// Convert big-endian byte array to little-endian byte array and vice versa
U8* ecp_ReverseByteOrder(OUT U8 *Y, IN const U8 *X)
{
    int i;
    for (i = 0; i < 32; i++) Y[i] = X[31-i];
    return Y;
}

// Convert little-endian byte array to little-endian word array
U32* ecp_BytesToWords(OUT U32 *Y, IN const U8 *X)
{
    int i, j;
    for (i = j = 0; j < 8; i += 4, j++)
    {
        Y[j] = ((U32)X[i+0]      ) |
               ((U32)X[i+1] <<  8) |
               ((U32)X[i+2] << 16) |
               ((U32)X[i+3] << 24);
    }
    return Y;
}

// Convert little-endian word array to little-endian byte array
U8* ecp_WordsToBytes(OUT U8 *Y, IN const U32 *X)
{
    int i, j;
    for (i = j = 0; j < 8; j++)
    {
        Y[i++] = (U8)(X[j]      );
        Y[i++] = (U8)(X[j] >>  8);
        Y[i++] = (U8)(X[j] >> 16);
        Y[i++] = (U8)(X[j] >> 24);
    }
    return Y;
}
