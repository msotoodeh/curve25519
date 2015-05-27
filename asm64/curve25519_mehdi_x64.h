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
#ifndef __curve25519_x64_h__
#define __curve25519_x64_h__

#ifdef __cplusplus
extern "C" {
#endif

#include "BaseTypes.h"

#define ECP_VERSION_STR     "1.1.0"

#ifdef WORDSIZE_IS_64BITS
#define U_WORD          U64
#define S_WORD          S64
#define WORDSIZE_64
#else
#define U_WORD          U32
#define S_WORD          S32
#define WORDSIZE_32
#endif

#define K_BYTES         32
#define K_WORDS         (K_BYTES/sizeof(U_WORD))

// Affine coordinates
typedef struct {
    U_WORD x[K_WORDS];
    U_WORD y[K_WORDS];
} Affine_POINT;

// Projective coordinates
typedef struct {
    U_WORD x[K_WORDS];  // x/z
    U_WORD y[K_WORDS];  // y/z
    U_WORD z[K_WORDS];
    U_WORD t[K_WORDS];  // xy/z
} Ext_POINT;

// pre-computed, extended point
typedef struct
{
    U_WORD YpX[K_WORDS];        // Y+X
    U_WORD YmX[K_WORDS];        // Y-X
    U_WORD T2d[K_WORDS];        // 2d*T
    U_WORD Z2[K_WORDS];         // 2*Z
} Pre_POINT;

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
U64* ecp_BytesToWords(OUT U64 *Y, IN const U8 *X);
// Convert little-endian word array to little-endian byte array
U8* ecp_WordsToBytes(OUT U8 *Y, IN const U64 *X);
U8* ecp_EncodeInt(OUT U8 *Y, IN const U64 *X, IN U8 parity);
U8 ecp_DecodeInt(OUT U64 *Y, IN const U8 *X);

// -- base point order ------------------------------------------------------

// Z = (X*Y)/R mod BPO
void eco_MontMul(OUT U64 *Z, IN const U64 *X, IN const U64 *Y);
// Return Y = X*R mod BPO
void eco_ToMont(OUT U64 *Y, IN const U64 *X);
// Return Y = X/R mod BPO
void eco_FromMont(OUT U64 *Y, IN const U64 *X);
// Calculate Y = X**E mod BPO
void eco_ExpModBPO(OUT U64 *Y, IN const U64 *X, IN const U8 *E, IN int bytes);
// Calculate Y = 1/X mod BPO
void eco_InvModBPO(OUT U64 *Y, IN const U64 *X);
// Z = X*Y mod BPO
void eco_MulMod(OUT U64 *Z, IN const U64 *X, IN const U64 *Y);
// Z = X*Y mod BPO
void eco_MulReduce(OUT U64 *Z, IN const U64 *X, IN const U64 *Y);
// X mod BPO
void eco_Mod(U64 *X);
// Z = X + Y mod BPO
void eco_AddReduce(OUT U64 *Z, IN const U64 *X, IN const U64 *Y);
// Z = X + Y mod BPO
void eco_AddMod(OUT U64 *Z, IN const U64 *X, IN const U64 *Y);
// Return Y = D mod BPO where D is 512-bit message digest (i.e SHA512 digest)
void eco_DigestToWords( OUT U64 *Y, IN const U8 *md);

// -- asm insterfaces ------------------------------------------------------
// Computes Z = X+Y
extern U64 ecp_Add(U64* Z, const U64* X, const U64* Y);
// Computes Z = X-Y
extern S64 ecp_Sub(U64* Z, const U64* X, const U64* Y);
// Computes Z = X+Y mod P
void ecp_AddReduce(U64* Z, const U64* X, const U64* Y);
// Computes Z = X-Y mod P
void ecp_SubReduce(U64* Z, const U64* X, const U64* Y);
// Compares X-Y
int ecp_Cmp(const U64* X, const U64* Y);
// Computes Z = Y + b*X and return carry
U64 ecp_WordMulAdd(U64 *Z, const U64* Y, U64 b, const U64* X);
// Computes Z = Y + b*X mod P
void ecp_WordMulAddReduce(U64 *Z, const U64* Y, U64 b, const U64* X);
// Computes Y = b*X
void ecp_WordMulSet(U64 *Y, U64 b, const U64* X);
// Computes Z = X*Y
void ecp_Mul(U64* Z, const U64* X, const U64* Y);
// Computes Z = X*Y mod P
void ecp_MulReduce(U64* Z, const U64* X, const U64* Y);
// Computes Z = X*X
void ecp_SqrReduce(U64* Y, const U64* X);

// -- internal insterfaces -------------------------------------------------
// Set X = value
void ecp_SetValue(U64* X, U64 value);
// Y = X
void ecp_Copy(U64* Y, const U64* X);
// Computes Z = X*Y mod P.
void ecp_MulMod(U64* Z, const U64* X, const U64* Y);
// Y = X ** E mod P
// E is in little-endian format
void ecp_ExpMod(U64* Y, const U64* X, const U8* E, int bytes);
// Return Y = 1/X mod P
void ecp_Inverse(U64 *Y, const U64 *X);


#ifdef __cplusplus
}
#endif
#endif  // __curve25519_x64_h__