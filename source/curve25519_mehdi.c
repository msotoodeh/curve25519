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
#include <memory.h>
#include "curve25519_mehdi.h"

/*
    The curve used is y2 = x^3 + 486662x^2 + x, a Montgomery curve, over 
    the prime field defined by the prime number 2^255 - 19, and it uses the 
    base point x = 9. 
    Protocol uses compressed elliptic point (only X coordinates), so it 
    allows for efficient use of the Montgomery ladder for ECDH, using only 
    XZ coordinates.

    The curve is birationally equivalent to Ed25519 (Twisted Edwards curve).

    b = 256
    p = 2**255 - 19
    l = 2**252 + 27742317777372353535851937790883648493
*/

// Pick a modular inverse method. One of:
//#define ECP_INVERSE_METHOD_EXPMOD
#define ECP_INVERSE_METHOD_DJB
//#define ECP_INVERSE_METHOD_EUCLID

typedef struct
{
    U32 X[8];   // x = X/Z
    U32 Z[8];   // 
} XZ_POINT;

static const U32 _w_P[8] = {
    0xFFFFFFED,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x7FFFFFFF
};

// Maximum number of prime p that fits into 256-bits
static const U32 _w_maxP[8] = {   // 2*P < 2**256
    0xFFFFFFDA,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF
};

static const U32 _w_I[8] = {
    0x4A0EA0B0,0xC4EE1B27,0xAD2FE478,0x2F431806,
    0x3DFBD7A7,0x2B4D0099,0x4FC1DF0B,0x2B832480
};

static const U8 _b_Pp3d8[32] = {    // (P+3)/8
    0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x0F };

// x coordinate of base point
const U8 ecp_BasePoint[32] = { 
    9,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 };

static const U32 _w_V38[8] = { 38,0,0,0,0,0,0,0 };

void ecp_Inverse(U32 *out, const U32 *z);

#define ECP_MOD(X)  while (ecp_Cmp(X, _w_P) >= 0) ecp_Sub(X, X, _w_P)

static void ecp_SetValue(U32* X, U32 value)
{
    X[0] = value;
    X[1] = X[2] = X[3] = X[4] = X[5] = X[6] = X[7] = 0;
}

// Y = X
void ecp_Copy(U32* Y, const U32* X)
{
    memcpy(Y, X, 8*sizeof(U32));
}

#define ECP_ADD32(Z,X,Y) c.u64 = (U64)(X) + (Y); Z = c.u32.lo;
#define ECP_ADC32(Z,X,Y) c.u64 = (U64)(X) + (U64)(Y) + c.u32.hi; Z = c.u32.lo;

// Computes Z = X+Y
U32 ecp_Add(U32* Z, const U32* X, const U32* Y) 
{
    M64 c;

    ECP_ADD32(Z[0], X[0], Y[0]);
    ECP_ADC32(Z[1], X[1], Y[1]);
    ECP_ADC32(Z[2], X[2], Y[2]);
    ECP_ADC32(Z[3], X[3], Y[3]);
    ECP_ADC32(Z[4], X[4], Y[4]);
    ECP_ADC32(Z[5], X[5], Y[5]);
    ECP_ADC32(Z[6], X[6], Y[6]);
    ECP_ADC32(Z[7], X[7], Y[7]);
    return c.u32.hi;
}

#define ECP_SUB32(Z,X,Y) b.s64 = (S64)(X) - (Y); Z = b.s32.lo;
#define ECP_SBC32(Z,X,Y) b.s64 = (S64)(X) - (U64)(Y) + b.s32.hi; Z = b.s32.lo;

// Computes Z = X-Y
S32 ecp_Sub(U32* Z, const U32* X, const U32* Y) 
{
    M64 b;
    ECP_SUB32(Z[0], X[0], Y[0]);
    ECP_SBC32(Z[1], X[1], Y[1]);
    ECP_SBC32(Z[2], X[2], Y[2]);
    ECP_SBC32(Z[3], X[3], Y[3]);
    ECP_SBC32(Z[4], X[4], Y[4]);
    ECP_SBC32(Z[5], X[5], Y[5]);
    ECP_SBC32(Z[6], X[6], Y[6]);
    ECP_SBC32(Z[7], X[7], Y[7]);
    return b.s32.hi;
}

// Computes Z = X+Y mod P
static void ecp_AddReduce(U32* Z, const U32* X, const U32* Y) 
{
    U32 c = ecp_Add(Z, X, Y);
    while (c != 0) c = ecp_Add(Z, Z, _w_V38);
}

// Computes Z = X-Y mod P
static void ecp_SubReduce(U32* Z, const U32* X, const U32* Y) 
{
    S32 b = ecp_Sub(Z, X, Y);
    while (b != 0) { b += ecp_Add(Z, Z, _w_maxP); }
}

// Compares X-Y
int ecp_Cmp(const U32* X, const U32* Y) 
{
    int words = 8;
    while (words-- > 0)
    {
        if (X[words] != Y[words])
            return (X[words] > Y[words]) ? +1 : -1;
    }
    return 0;
}

#define ECP_MULSET_W0(Y,b,X) c.u64 = (U64)(b)*(X); Y = c.u32.lo;
#define ECP_MULSET_W1(Y,b,X) c.u64 = (U64)(b)*(X) + c.u32.hi; Y = c.u32.lo;

// Computes Y = b*X
static void ecp_mul_set(U32* Y, U32 b, const U32* X) 
{
    M64 c;
    ECP_MULSET_W0(Y[0], b, X[0]);
    ECP_MULSET_W1(Y[1], b, X[1]);
    ECP_MULSET_W1(Y[2], b, X[2]);
    ECP_MULSET_W1(Y[3], b, X[3]);
    ECP_MULSET_W1(Y[4], b, X[4]);
    ECP_MULSET_W1(Y[5], b, X[5]);
    ECP_MULSET_W1(Y[6], b, X[6]);
    ECP_MULSET_W1(Y[7], b, X[7]);
    Y[8] = c.u32.hi;
}

#define ECP_MULADD_W0(Z,Y,b,X) c.u64 = (U64)(b)*(X) + (Y); Z = c.u32.lo;
#define ECP_MULADD_W1(Z,Y,b,X) c.u64 = (U64)(b)*(X) + (U64)(Y) + c.u32.hi; Z = c.u32.lo;

// Computes Y += b*X
// Assumes upper-word of Y is 0 on entry
// Addition is performed on lower 8-words of Y
static void ecp_mul_add(U32* Y, U32 b, const U32* X) 
{
    M64 c;
    ECP_MULADD_W0(Y[0], Y[0], b, X[0]);
    ECP_MULADD_W1(Y[1], Y[1], b, X[1]);
    ECP_MULADD_W1(Y[2], Y[2], b, X[2]);
    ECP_MULADD_W1(Y[3], Y[3], b, X[3]);
    ECP_MULADD_W1(Y[4], Y[4], b, X[4]);
    ECP_MULADD_W1(Y[5], Y[5], b, X[5]);
    ECP_MULADD_W1(Y[6], Y[6], b, X[6]);
    ECP_MULADD_W1(Y[7], Y[7], b, X[7]);
    Y[8] = c.u32.hi;
}

#define ECP_ADD_C1(Y,X) c.u64 = (U64)(X) + c.u32.hi; Y = c.u32.lo;

// Computes Z = Y + b*X and return carry
static void ecp_WordMulAdd(U32 *Z, const U32* Y, U32 b, const U32* X) 
{
    M64 c;
    ECP_MULADD_W0(Z[0], Y[0], b, X[0]);
    ECP_MULADD_W1(Z[1], Y[1], b, X[1]);
    ECP_MULADD_W1(Z[2], Y[2], b, X[2]);
    ECP_MULADD_W1(Z[3], Y[3], b, X[3]);
    ECP_MULADD_W1(Z[4], Y[4], b, X[4]);
    ECP_MULADD_W1(Z[5], Y[5], b, X[5]);
    ECP_MULADD_W1(Z[6], Y[6], b, X[6]);
    ECP_MULADD_W1(Z[7], Y[7], b, X[7]);

    while (c.u32.hi != 0)
    {
        ECP_MULADD_W0(Z[0], Z[0], c.u32.hi, 38);
        ECP_ADD_C1(Z[1], Z[1]);
        ECP_ADD_C1(Z[2], Z[2]);
        ECP_ADD_C1(Z[3], Z[3]);
        ECP_ADD_C1(Z[4], Z[4]);
        ECP_ADD_C1(Z[5], Z[5]);
        ECP_ADD_C1(Z[6], Z[6]);
        ECP_ADD_C1(Z[7], Z[7]);
    }
}

// Computes Z = X*Y mod P.
// Output fits into 8 words but could be greater than P
static void ecp_MulReduce(U32* Z, const U32* X, const U32* Y) 
{
    U32 T[16];

    ecp_mul_set(T+0, X[0], Y);
    ecp_mul_add(T+1, X[1], Y);
    ecp_mul_add(T+2, X[2], Y);
    ecp_mul_add(T+3, X[3], Y);
    ecp_mul_add(T+4, X[4], Y);
    ecp_mul_add(T+5, X[5], Y);
    ecp_mul_add(T+6, X[6], Y);
    ecp_mul_add(T+7, X[7], Y);

    // We have T = X*Y, now do the reduction in size

    ecp_WordMulAdd(Z, T, 38, T+8);
}

// Computes Z = X*Y mod P.
static void ecp_SqrReduce(U32* Y, const U32* X) 
{
    // TBD: Implementation is based on multiply
    //      Optimize for squaring

    U32 T[16];

    ecp_mul_set(T+0, X[0], X);
    ecp_mul_add(T+1, X[1], X);
    ecp_mul_add(T+2, X[2], X);
    ecp_mul_add(T+3, X[3], X);
    ecp_mul_add(T+4, X[4], X);
    ecp_mul_add(T+5, X[5], X);
    ecp_mul_add(T+6, X[6], X);
    ecp_mul_add(T+7, X[7], X);

    // We have T = X*X, now do the reduction in size

    ecp_WordMulAdd(Y, T, 38, T+8);
}

// Computes Z = X*Y mod P.
static void ecp_MulMod(U32* Z, const U32* X, const U32* Y) 
{
    ecp_MulReduce(Z, X, Y);
    ECP_MOD(Z);
}

// Y = X ** E mod P
// E is in little-endian format
static void ecp_ExpMod(U32* Y, const U32* X, const U8* E, int bytes)
{
    int i;
    ecp_SetValue(Y, 1);
    while (bytes-- > 0)
    {
        U8 e = E[bytes];
        for (i = 0; i < 8; i++)
        {
            ecp_SqrReduce(Y, Y);
            if (e & 0x80) ecp_MulReduce(Y, Y, X);
            e <<= 1;
        }
    }
    ECP_MOD(Y);
}

#if 0
// Z = X + Y
static void ecp_MontAdd(XZ_POINT *Z, const XZ_POINT *X, const XZ_POINT *Y, IN const U32 *Base)
{
    U32 A[8], B[8], C[8];
    // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2*zb      // zb=1
    // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*xb      // xb=Base
    ecp_SubReduce(A, X->X, X->Z);       // A = x1-z1
    ecp_AddReduce(B, Y->X, Y->Z);       // B = x2+z2
    ecp_MulReduce(A, A, B);             // A = (x1-z1)(x2+z2)
    ecp_AddReduce(B, X->X, X->Z);       // B = x1+z1
    ecp_SubReduce(C, Y->X, Y->Z);       // C = x2-z2
    ecp_MulReduce(B, B, C);             // B = (x1+z1)(x2-z2)
    ecp_AddReduce(C, A, B);             // C = (x1-z1)(x2+z2) + (x1+z1)(x2-z2)
    ecp_SubReduce(B, A, B);             // B = (x1-z1)(x2+z2) - (x1+z1)(x2-z2)
    ecp_SqrReduce(Z->X, C);             // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2
    ecp_SqrReduce(A, B);                // A = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2
    ecp_MulReduce(Z->Z, A, Base);       // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*Base
}
#endif

// Y = X + X
static void ecp_MontDouble(XZ_POINT *Y, const XZ_POINT *X)
{
    U32 A[8], B[8];
    //  x2 = (x+z)^2 * (x-z)^2
    //  z2 = ((x+z)^2 - (x-z)^2)*((x+z)^2 + ((A-2)/4)((x+z)^2 - (x-z)^2))
    ecp_AddReduce(A, X->X, X->Z);       // A = (x+z)
    ecp_SubReduce(B, X->X, X->Z);       // B = (x-z)
    ecp_SqrReduce(A, A);                // A = (x+z)^2
    ecp_SqrReduce(B, B);                // B = (x-z)^2
    ecp_MulReduce(Y->X, A, B);          // x2 = (x+z)^2 * (x-z)^2
    ecp_SubReduce(B, A, B);             // B = (x+z)^2 - (x-z)^2
    // (486662-2)/4 = 121665
    ecp_WordMulAdd(A, A, 121665, B);
    ecp_MulReduce(Y->Z, A, B);          // z2 = (B)*((x+z)^2 + ((A-2)/4)(B))
}

// return P = P + Q, Q = 2Q
static void ecp_Mont(XZ_POINT *P, XZ_POINT *Q, IN const U32 *Base)
{
    U32 A[8], B[8], C[8], D[8], E[8];
    // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2*zb      // zb=1
    // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*xb      // xb=Base
    ecp_SubReduce(A, P->X, P->Z);   // A = x1-z1
    ecp_AddReduce(B, P->X, P->Z);   // B = x1+z1
    ecp_SubReduce(C, Q->X, Q->Z);   // C = x2-z2
    ecp_AddReduce(D, Q->X, Q->Z);   // D = x2+z2
    ecp_MulReduce(A, A, D);         // A = (x1-z1)(x2+z2)
    ecp_MulReduce(B, B, C);         // B = (x1+z1)(x2-z2)
    ecp_AddReduce(E, A, B);         // E = (x1-z1)(x2+z2) + (x1+z1)(x2-z2)
    ecp_SubReduce(B, A, B);         // B = (x1-z1)(x2+z2) - (x1+z1)(x2-z2)
    ecp_SqrReduce(P->X, E);         // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2
    ecp_SqrReduce(A, B);            // A = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2
    ecp_MulReduce(P->Z, A, Base);   // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*Base

    // x4 = (x2+z2)^2 * (x2-z2)^2
    // z4 = ((x2+z2)^2 - (x2-z2)^2)*((x2+z2)^2 + 121665((x2+z2)^2 - (x2-z2)^2))
    // C = (x2-z2)
    // D = (x2+z2)
    ecp_SqrReduce(A, D);            // A = (x2+z2)^2
    ecp_SqrReduce(B, C);            // B = (x2-z2)^2
    ecp_MulReduce(Q->X, A, B);      // x4 = (x2+z2)^2 * (x2-z2)^2
    ecp_SubReduce(B, A, B);         // B = (x2+z2)^2 - (x2-z2)^2
    ecp_WordMulAdd(A, A, 121665, B);
    ecp_MulReduce(Q->Z, A, B);      // z4 = B*((x2+z2)^2 + 121665*B)
}

// Constant-time measure:
// Use different set of parameters for bit=0 or bit=1 with no conditional jump
//
#define ECP_MONT(n) j = (k >> n) & 1; ecp_Mont(PP[j], QP[j], X)

// --------------------------------------------------------------------------
// Implementations that use if-else logic are prone to side channel attacks
// due to side effects of conditional jump that can leak data due to branch
// prediction, cache/instruction queue flushing and in general un-balanced 
// instruction execution on each condition.
// if(bit) { op(1) } else { op(0) } 
//      if bit==1: op(1); jump $$2
//      if bit==0: jump $$1; $$1:op(0); $$2:
// --------------------------------------------------------------------------
// Return point Q = k*P
// K in a little-endian byte array
void ecp_PointMultiply(
    OUT U8 *PublicKey, 
    IN const U8 *BasePoint, 
    IN const U8 *SecretKey, 
    IN int len)
{
    int i, j, k;
    U32 X[8];
    XZ_POINT P, Q, *PP[2], *QP[2];

    ecp_BytesToWords(X, BasePoint);

    // 1: P = (2k+1)G, Q = (2k+2)G
    // 0: Q = (2k+1)G, P = (2k)G

    // Find first non-zero bit
    while (len-- > 0)
    {
        k = SecretKey[len];
        for (i = 0; i < 8; i++, k <<= 1)
        {
            // P = kG, Q = (k+1)G
            if (k & 0x80)
            {
                // We have first non-zero bit
                ecp_Copy(P.X, X);
                ecp_SetValue(P.Z, 1);
                ecp_MontDouble(&Q, &P);

                PP[1] = &P; PP[0] = &Q;
                QP[1] = &Q; QP[0] = &P;

                while (++i < 8) { k <<= 1; ECP_MONT(7); }
                while (len-- > 0)
                {
                    k = SecretKey[len];
                    ECP_MONT(7);
                    ECP_MONT(6);
                    ECP_MONT(5);
                    ECP_MONT(4);
                    ECP_MONT(3);
                    ECP_MONT(2);
                    ECP_MONT(1);
                    ECP_MONT(0);
                }

                ecp_Inverse(Q.Z, P.Z);
                ecp_MulMod(X, P.X, Q.Z);
                ecp_WordsToBytes(PublicKey, X);
                return;
            }
        }
    }
    // K is 0
    memset(PublicKey, 0, 32);
}

void ecp_CalculateY(OUT U8 *Y, IN const U8 *X)
{
    U32 A[8], B[8], T[8];

    ecp_BytesToWords(T, X);
    ecp_SetValue(A, 486662);
    ecp_AddReduce(A, A, T);     // x + 486662
    ecp_MulReduce(A, A, T);     // x^2 + 486662x
    ecp_MulReduce(A, A, T);     // x^3 + 486662x^2
    ecp_AddReduce(A, A, T);     // x^3 + 486662x^2 + x
    ecp_ExpMod(T, A, _b_Pp3d8, 32);
    // if T*T != A: T *= sqrt(-1)
    ecp_MulMod(B, T, T);
    if (ecp_Cmp(B, A) != 0) ecp_MulMod(T, T, _w_I);
    ecp_WordsToBytes(Y, T);
}

#ifdef ECP_INVERSE_METHOD_EXPMOD
static const U8 _b_Pm2[32] = {      // p-2
    0xEB,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F };

// Y = 1/X mod P
void ecp_Inverse(U32* Y, const U32* X)
{
    // TBD: use Ext. Euclid instead
    ecp_ExpMod(Y, X, _b_Pm2, 32);
}
#endif

#ifdef ECP_INVERSE_METHOD_DJB
// Donna's implementation for reference
// Return out = 1/z mod P
void ecp_Inverse(U32 *out, const U32 *z) 
{
  int i;
  U32 t0[8],t1[8],z2[8],z9[8],z11[8];
  U32 z2_5_0[8],z2_10_0[8],z2_20_0[8],z2_50_0[8],z2_100_0[8];

  /* 2 */               ecp_SqrReduce(z2,z);
  /* 4 */               ecp_SqrReduce(t1,z2);
  /* 8 */               ecp_SqrReduce(t0,t1);
  /* 9 */               ecp_MulReduce(z9,t0,z);
  /* 11 */              ecp_MulReduce(z11,z9,z2);
  /* 22 */              ecp_SqrReduce(t0,z11);
  /* 2^5 - 2^0 = 31 */  ecp_MulReduce(z2_5_0,t0,z9);

  /* 2^6 - 2^1 */       ecp_SqrReduce(t0,z2_5_0);
  /* 2^7 - 2^2 */       ecp_SqrReduce(t1,t0);
  /* 2^8 - 2^3 */       ecp_SqrReduce(t0,t1);
  /* 2^9 - 2^4 */       ecp_SqrReduce(t1,t0);
  /* 2^10 - 2^5 */      ecp_SqrReduce(t0,t1);
  /* 2^10 - 2^0 */      ecp_MulReduce(z2_10_0,t0,z2_5_0);

  /* 2^11 - 2^1 */      ecp_SqrReduce(t0,z2_10_0);
  /* 2^12 - 2^2 */      ecp_SqrReduce(t1,t0);
  /* 2^20 - 2^10 */     for (i = 2;i < 10;i += 2) { 
                            ecp_SqrReduce(t0,t1); 
                            ecp_SqrReduce(t1,t0); }
  /* 2^20 - 2^0 */      ecp_MulReduce(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */      ecp_SqrReduce(t0,z2_20_0);
  /* 2^22 - 2^2 */      ecp_SqrReduce(t1,t0);
  /* 2^40 - 2^20 */     for (i = 2;i < 20;i += 2) { 
                            ecp_SqrReduce(t0,t1); 
                            ecp_SqrReduce(t1,t0); }
  /* 2^40 - 2^0 */      ecp_MulReduce(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */      ecp_SqrReduce(t1,t0);
  /* 2^42 - 2^2 */      ecp_SqrReduce(t0,t1);
  /* 2^50 - 2^10 */     for (i = 2;i < 10;i += 2) { 
                            ecp_SqrReduce(t1,t0); 
                            ecp_SqrReduce(t0,t1); }
  /* 2^50 - 2^0 */      ecp_MulReduce(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */      ecp_SqrReduce(t0,z2_50_0);
  /* 2^52 - 2^2 */      ecp_SqrReduce(t1,t0);
  /* 2^100 - 2^50 */    for (i = 2;i < 50;i += 2) { 
                            ecp_SqrReduce(t0,t1); 
                            ecp_SqrReduce(t1,t0); }
  /* 2^100 - 2^0 */     ecp_MulReduce(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */     ecp_SqrReduce(t1,z2_100_0);
  /* 2^102 - 2^2 */     ecp_SqrReduce(t0,t1);
  /* 2^200 - 2^100 */   for (i = 2;i < 100;i += 2) { 
                            ecp_SqrReduce(t1,t0); 
                            ecp_SqrReduce(t0,t1); }
  /* 2^200 - 2^0 */     ecp_MulReduce(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */     ecp_SqrReduce(t0,t1);
  /* 2^202 - 2^2 */     ecp_SqrReduce(t1,t0);
  /* 2^250 - 2^50 */    for (i = 2;i < 50;i += 2) { 
                            ecp_SqrReduce(t0,t1); 
                            ecp_SqrReduce(t1,t0); }
  /* 2^250 - 2^0 */     ecp_MulReduce(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */     ecp_SqrReduce(t1,t0);
  /* 2^252 - 2^2 */     ecp_SqrReduce(t0,t1);
  /* 2^253 - 2^3 */     ecp_SqrReduce(t1,t0);
  /* 2^254 - 2^4 */     ecp_SqrReduce(t0,t1);
  /* 2^255 - 2^5 */     ecp_SqrReduce(t1,t0);
  /* 2^255 - 21 */      ecp_MulReduce(out,t1,z11);
}
#endif

#ifdef ECP_INVERSE_METHOD_EUCLID
static const U32 _w_ONE[8] = { 1,0,0,0,0,0,0,0 };

#define ECP_SHR_W0(X) c.u32.hi = c0; c.u32.lo = X; X = (U32)(c.u64 >> 1)
#define ECP_SHR_W1(X) c.u32.hi = c.u32.lo; c.u32.lo = X; X = (U32)(c.u64 >> 1)

// Calculate X >>= 1
static U32 ecp_ShiftRightOne(
    IN OUT U32* X,
    IN U32 c0)
{
    M64 c;
    ECP_SHR_W0(X[7]);
    ECP_SHR_W1(X[6]);
    ECP_SHR_W1(X[5]);
    ECP_SHR_W1(X[4]);
    ECP_SHR_W1(X[3]);
    ECP_SHR_W1(X[2]);
    ECP_SHR_W1(X[1]);
    ECP_SHR_W1(X[0]);
    return c.u32.lo & 1;
}

// Return Y = 1/X mod p using Euclid's binary algorithm
void ecp_Inverse(OUT U32 *Y, IN const U32 *X)
{ 
    // ecp_EuclidAlgo() kills the input arrays, make temps
    U32 A[8] = {1}, B[8] = {0}, U[8], V[8], c;

    ecp_Copy(U, X);
    ecp_Copy(V, _w_P);
    ECP_MOD(U);

    while (ecp_Cmp(U, _w_ONE) > 0 && ecp_Cmp(V, _w_ONE) > 0)
    {
        while ((U[0] & 1) == 0)
        {
            c = ecp_ShiftRightOne(U, 0);
            if (A[0] & 1) c = ecp_Add(A, A, _w_P);
            ecp_ShiftRightOne(A, c);
        }   
        while ((V[0] & 1) == 0)
        {
            c = ecp_ShiftRightOne(V, 0);
            if (B[0] & 1) c = ecp_Add(B, B, _w_P);
            ecp_ShiftRightOne(B, c);
        }   
        if (ecp_Cmp(U, V) > 0)
        {
            ecp_Sub(U, U, V);
            //ecp_Sub(T, _w_P, B);
            //c = ecp_Add(A, A, T);
            if (ecp_Sub(A, A, B)) ecp_Add(A, A, _w_P);
        }
        else
        {
            ecp_Sub(V, V, U);
            if (ecp_Sub(B, B, A)) ecp_Add(B, B, _w_P);
        }
    }
    ecp_Copy(Y, (ecp_Cmp(U, _w_ONE) == 0) ? A : B);
}
#endif

#ifdef ECP_SELF_TEST
#include "../test/curve25519.selftest"
#endif
