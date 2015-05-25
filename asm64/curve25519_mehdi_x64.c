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
#include "curve25519_mehdi_x64.h"

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

typedef struct
{
    U64 X[4];   // x = X/Z
    U64 Z[4];   // 
} XZ_POINT;

const U64 _w_P[4] = {
    0xFFFFFFFFFFFFFFED,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0x7FFFFFFFFFFFFFFF };

// Maximum multiple of prime p < 2**256
const U64 _w_maxP[4] = {   // 2*P
    0xFFFFFFFFFFFFFFDA,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF };

const U64 _w_I[4] = {
    0xC4EE1B274A0EA0B0,0x2F431806AD2FE478,0x2B4D00993DFBD7A7,0x2B8324804FC1DF0B };

static const U8 _b_Pp3d8[32] = {    // (P+3)/8
    0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x0F };

// x coordinate of base point
const U8 ecp_BasePoint[32] = { 
    9,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 };

#define ECP_MOD(X) while (ecp_Cmp(X, _w_P) >= 0) ecp_Sub(X, X, _w_P)

void ecp_SetValue(U64* X, U64 value)
{
    X[0] = value;
    X[1] = X[2] = X[3] = 0;
}

// Y = X
void ecp_Copy(U64* Y, const U64* X)
{
    memcpy(Y, X, 4*sizeof(U64));
}

// Computes Z = X*Y mod P.
void ecp_MulMod(U64* Z, const U64* X, const U64* Y) 
{
    ecp_MulReduce(Z, X, Y);
    ECP_MOD(Z);
}

#define EXP_MOD_BIT(n) ecp_SqrReduce(Y, Y); if (e&n) ecp_MulReduce(Y, Y, X)

// Y = X ** E mod P
// E is in little-endian format
void ecp_ExpMod(U64* Y, const U64* X, const U8* E, int bytes)
{
    ecp_SetValue(Y, 1);
    while (bytes > 0)
    {
        U8 e = E[--bytes];
        EXP_MOD_BIT(0x80);
        EXP_MOD_BIT(0x40);
        EXP_MOD_BIT(0x20);
        EXP_MOD_BIT(0x10);
        EXP_MOD_BIT(0x08);
        EXP_MOD_BIT(0x04);
        EXP_MOD_BIT(0x02);
        EXP_MOD_BIT(0x01);
    }
    ECP_MOD(Y);
}

#if 0
// Z = X + Y
static void ecp_MontAdd(XZ_POINT *Z, const XZ_POINT *X, const XZ_POINT *Y, IN const U64 *Base)
{
    U64 A[4], B[4], C[4];
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
void ecp_MontDouble(XZ_POINT *Y, const XZ_POINT *X)
{
    U64 A[4], B[4];
    //  x2 = (x+z)^2 * (x-z)^2
    //  z2 = ((x+z)^2 - (x-z)^2)*((x+z)^2 + ((A-2)/4)((x+z)^2 - (x-z)^2))
    ecp_AddReduce(A, X->X, X->Z);       // A = (x+z)
    ecp_SubReduce(B, X->X, X->Z);       // B = (x-z)
    ecp_SqrReduce(A, A);                // A = (x+z)^2
    ecp_SqrReduce(B, B);                // B = (x-z)^2
    ecp_MulReduce(Y->X, A, B);          // x2 = (x+z)^2 * (x-z)^2
    ecp_SubReduce(B, A, B);             // B = (x+z)^2 - (x-z)^2
    // (486662-2)/4 = 121665
    ecp_WordMulAddReduce(A, A, 121665, B);
    ecp_MulReduce(Y->Z, A, B);          // z2 = (B)*((x+z)^2 + ((A-2)/4)(B))
}

// return P = P + Q, Q = 2Q
void ecp_Mont(XZ_POINT *P, XZ_POINT *Q, IN const U64 *Base)
{
    U64 A[4], B[4], C[4], D[4], E[4];
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
    ecp_WordMulAddReduce(A, A, 121665, B);
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
    U64 X[4];
    XZ_POINT P, Q, *PP[2], *QP[2];

    ecp_BytesToWords(X, BasePoint);

    // 1: P = (2k+1)G, Q = (2k+2)G
    // 0: Q = (2k+1)G, P = (2k)G

    // Find first non-zero bit
    while (len > 0)
    {
        k = SecretKey[--len];
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
    U64 A[4], B[4], T[4];

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
void ecp_Inverse(U64* Y, const U64* X)
{
    // TBD: use Ext. Euclid instead
    ecp_ExpMod(Y, X, _b_Pm2, 32);
}
#endif

#ifdef ECP_INVERSE_METHOD_DJB
// Donna's implementation for reference
// Return out = 1/z mod P
void ecp_Inverse(U64 *out, const U64 *z) 
{
  int i;
  U64 t0[4],t1[4],z2[4],z9[4],z11[4];
  U64 z2_5_0[4],z2_10_0[4],z2_20_0[4],z2_50_0[4],z2_100_0[4];

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

// Return public key associated with sk
void curve25519_dh_CalculatePublicKey(
    unsigned char *pk,          // [32-bytes] OUT: Public key
    unsigned char *sk)          // [32-bytes] IN/OUT: Your secret key
{
    ecp_TrimSecretKey(sk);
    ecp_PointMultiply(pk, ecp_BasePoint, sk, 32);
}

void curve25519_dh_CreateSharedKey(
    unsigned char *shared,      // [32-bytes] OUT: Created shared key
    const unsigned char *pk,    // [32-bytes] IN: Other side's public key
    unsigned char *sk)          // [32-bytes] IN/OUT: Your secret key
{
    ecp_TrimSecretKey(sk);
    ecp_PointMultiply(shared, pk, sk, 32);
}
