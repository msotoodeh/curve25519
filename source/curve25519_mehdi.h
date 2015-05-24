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


extern const U8 ecp_BasePoint[K_BYTES];

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
U_WORD* ecp_BytesToWords(OUT U_WORD *Y, IN const U8 *X);
// Convert little-endian word array to little-endian byte array
U8* ecp_WordsToBytes(OUT U8 *Y, IN const U_WORD *X);
// Return parity(X): 0 = even, 1 = odd
U8 ecp_CalcParity(IN const U_WORD *X);
U8* ecp_EncodeInt(OUT U8 *Y, IN const U32 *X, IN U8 parity);
U8 ecp_DecodeInt(OUT U32 *Y, IN const U8 *X);

// -- base point order ------------------------------------------------------

// Z = (X*Y)/R mod BPO
void eco_MontMul(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y);
// Return Y = X*R mod BPO
void eco_ToMont(OUT U_WORD *Y, IN const U_WORD *X);
// Return Y = X/R mod BPO
void eco_FromMont(OUT U_WORD *Y, IN const U_WORD *X);
// Calculate Y = X**E mod BPO
void eco_ExpModBPO(OUT U_WORD *Y, IN const U_WORD *X, IN const U8 *E, IN int bytes);
// Calculate Y = 1/X mod BPO
void eco_InvModBPO(OUT U_WORD *Y, IN const U_WORD *X);
// Z = X*Y mod BPO
void eco_MulReduce(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y);
// Z = X*Y mod BPO
void eco_MulMod(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y);
// Return Y = D mod BPO where D is 512-bit big-endian byte array (i.e SHA512 digest)
void eco_DigestToWords( OUT U_WORD *Y, IN const U8 *D);
// Z = X + Y mod BPO
void eco_AddMod(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y);
// X mod BPO
void eco_Mod(U_WORD *X);

#define ed25519_PackPoint(buff, Y, parity) ecp_EncodeInt(buff, Y, (U8)(parity & 1))

// -- big-number ------------------------------------------------------
U_WORD ecp_Add(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
S_WORD ecp_Sub(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_SetValue(U_WORD* X, U_WORD value);
void ecp_Copy(U_WORD* Y, const U_WORD* X);
void ecp_AddReduce(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_SubReduce(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_MulReduce(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_SqrReduce(U_WORD* Y, const U_WORD* X);
int  ecp_Cmp(const U_WORD* X, const U_WORD* Y);
void ecp_ModExp2523(U_WORD *Y, const U_WORD *X);
void ecp_Inverse(U_WORD *out, const U_WORD *z);
void ecp_MulMod(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_ExpMod(U_WORD* Y, const U_WORD* X, const U8* E, int bytes);

void ed25519_BasePointMultiply(OUT Affine_POINT *Q, IN const U8 *sk);
void ed25519_AddBasePoint(Ext_POINT *r, const Ext_POINT *p);
void ed25519_DoublePoint(Ext_POINT *p);


#ifdef __cplusplus
}
#endif
#endif  // __curve25519_mehdi_h__
