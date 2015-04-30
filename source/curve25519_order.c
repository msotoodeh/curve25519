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

/*
  This library provides support for mod BPO (Base Point Order) operations

    BPO = 2**252 + 27742317777372353535851937790883648493
    BPO = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

  If you keep adding points together, the result repeats every BPO times.
  Based on this, you may use:

        public_key = (private_key mod BPO)*BasePoint
  Split key example:
        k1 = random()
        k2 = 1/k1 mod BPO   --> k1*k2 = 1 mod BPO
        P1 = k1*P0 --> P2 = k2*P1 = k2*k1*P0 = P0
    See selftest code for some examples of BPO usage

    This library is used for implementation of ECDSA sign/verify.
*/

extern void ecp_Copy(U32* Y, const U32* X);
extern S32 ecp_Sub(U32* Z, const U32* X, const U32* Y);
extern int ecp_Cmp(const U32* X, const U32* Y);

const U8 curve25519_BasePointOrder[32] = {  // order of the base point
    0xED,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

static const U32 _w_BPO[8] = { // BPO as words
    0x5CF5D3ED,0x5812631A,0xA2F79CD6,0x14DEF9DE,
    0x00000000,0x00000000,0x00000000,0x10000000 };

static const U32 _w_maxBPO[8] = { // 15*BPO fits into 8 words
    0x72676AE3,0x2913CE8B,0x8C82308F,0x3910A40B,
    0x00000001,0x00000000,0x00000000,0xF0000000 };

static const U8 _b_BPOm2[32] = {      // BasePointOrder - 2
    0xEB,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

// R = 2**256 mod BPO
// R = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC6EF5BF4737DCF70D6EC31748D98951D
 static const U32 _w_R[8] = {   // R mod BPO
    0x8D98951D,0xD6EC3174,0x737DCF70,0xC6EF5BF4,
    0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF };

// R2 = R**2 mod BPO
// R2 = 0x0399411B7C309A3DCEEC73D217F5BE65D00E1BA768859347A40611E3449C0F01
static const U32 _w_R2[8] = {   // R**2 mod BPO
    0x449C0F01,0xA40611E3,0x68859347,0xD00E1BA7,
    0x17F5BE65,0xCEEC73D2,0x7C309A3D,0x0399411B };

static const U32 _w_One[8] = { 1,0,0,0,0,0,0 };

#define BPO_MINV32  0x12547E1B  // -1/BPO mod 2**32

#define ECP_MULADD_W0(Z,Y,b,X) c.u64 = (U64)(b)*(X) + (Y); Z = c.u32.lo;
#define ECP_MULADD_W1(Z,Y,b,X) c.u64 = (U64)(b)*(X) + (U64)(Y) + c.u32.hi; Z = c.u32.lo;

// Computes Z = Y + b*X and return carry
static U32 eco_WordMulAdd(U32 *Z, const U32* Y, U32 b, const U32* X) 
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
    c.u64 = (U64)Y[8] + c.u32.hi;
    Z[8] = c.u32.lo;
    return c.u32.hi;    // 0 or 1 as the carry out
}

// Z = (X*Y)/R mod BPO
void eco_MontMul(OUT U32 *Z, IN const U32 *X, IN const U32 *Y)
{
    int i;
    U32 T[10] = {0};
    for (i = 0; i < 8; i++)
    {
        T[9]  = eco_WordMulAdd(T, T+1, X[i], Y);     // T = (T>>32) + X[i]*Y
        T[9] += eco_WordMulAdd(T, T, BPO_MINV32 * T[0], _w_BPO);
        // T + (-1/BPO)*T*BPO mod 2**32 = 0 --> T[0] = 0
    }
    // T[9] could be 2 at most
    while (T[9] != 0) T[9] += ecp_Sub(T+1, T+1, _w_maxBPO);
    ecp_Copy(Z, T+1);
}

// Return Y = X*R mod BPO
void eco_ToMont(OUT U32 *Y, IN const U32 *X)
{
    eco_MontMul(Y, X, _w_R2);
}

// Return Y = X/R mod BPO
void eco_FromMont(OUT U32 *Y, IN const U32 *X)
{
    eco_MontMul(Y, X, _w_One);
    while(ecp_Cmp(Y, _w_BPO) >= 0) ecp_Sub(Y, Y, _w_BPO);
}

#define ECO_MONT(n) eco_MontMul(V,V,V); if(e & (1<<n)) eco_MontMul(V,V,U)

// Calculate Y = X**E mod BPO
void eco_ExpModBPO(OUT U32 *Y, IN const U32 *X, IN const U8 *E, IN int bytes)
{
    U8 e;
    U32 U[8], V[8];

    eco_ToMont(U, X);
    ecp_Copy(V, _w_R);

    while (bytes > 0)
    {
        e = E[--bytes];
        ECO_MONT(7);
        ECO_MONT(6);
        ECO_MONT(5);
        ECO_MONT(4);
        ECO_MONT(3);
        ECO_MONT(2);
        ECO_MONT(1);
        ECO_MONT(0);
    }
    eco_FromMont(Y, V);
}

// Calculate Y = 1/X mod BPO
void eco_InvModBPO(OUT U32 *Y, IN const U32 *X)
{
    eco_ExpModBPO(Y, X, _b_BPOm2, 32);
}

// Z = X*Y mod BPO
void eco_MulMod(OUT U32 *Z, IN const U32 *X, IN const U32 *Y)
{
    U32 T[8];
    eco_MontMul(T, X, _w_R2);   // T = X*(R*R)/R = X*R
    eco_MontMul(Z, Y, T);       // Z = Y*(X*R)/R = X*Y
    while(ecp_Cmp(Z, _w_BPO) >= 0) ecp_Sub(Z, Z, _w_BPO);
}
