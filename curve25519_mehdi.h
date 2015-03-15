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
#ifndef __curve25519_mehdi_h__
#define __curve25519_mehdi_h__

#ifdef __cplusplus
extern "C" {
#endif

#include "BaseTypes.h"

#define ECP_VERSION_STR     "1.0.0"

extern const U8 ecp_BasePoint[32];

// Return point Q = k*P
void ecp_PointMultiply(OUT U8 *Q, IN const U8 *P, IN const U8 *K, IN int len);

// Calculate point.Y from point.X
void ecp_CalculateY(OUT U8 *Y, IN const U8 *X);

// Set low and high bits
void ecp_TrimSecretKey(U8 *X);

// -- utils -----------------------------------------------------------------

// Convert big-endian byte array to little-endian byte array and vice versa
U8* ecp_ReverseByteOrder(OUT U8 *Y, IN const U8 *X);
// Convert little-endian byte array to little-endian word array
U32* ecp_BytesToWords(OUT U32 *Y, IN const U8 *X);
// Convert little-endian word array to little-endian byte array
U8* ecp_WordsToBytes(OUT U8 *Y, IN const U32 *X);

// -- base point order ------------------------------------------------------

// Z = (X*Y)/R mod BPO
void eco_MontMul(OUT U32 *Z, IN const U32 *X, IN const U32 *Y);
// Return Y = X*R mod BPO
void eco_ToMont(OUT U32 *Y, IN const U32 *X);
// Return Y = X/R mod BPO
void eco_FromMont(OUT U32 *Y, IN const U32 *X);
// Calculate Y = X**E mod BPO
void eco_ExpModBPO(OUT U32 *Y, IN const U32 *X, IN const U8 *E, IN int bytes);
// Calculate Y = 1/X mod BPO
void eco_InvModBPO(OUT U32 *Y, IN const U32 *X);
// Z = X*Y mod BPO
void eco_MulMod(OUT U32 *Z, IN const U32 *X, IN const U32 *Y);

#ifdef __cplusplus
}
#endif
#endif  // __curve25519_mehdi_h__
