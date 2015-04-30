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
#include "curve25519_mehdi_x64.h"

/*
  This library provides support for mod BPO (Base Point Order) operations

    BPO = 2**252 + 27742317777372353535851937790883648493
    BPO = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

  If you keep adding points together, the result repeats every BPO times.
  Based on this, you may use:

        public_key = (private_key mod BPO)*BasePoint

  This library is used for implementation of ECDSA sign/verify.
*/

const U8 curve25519_BasePointOrder[32] = {  // order of the base point
    0xED,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

static const U64 _w_BPO[4] = { // BPO as words
    0x5812631A5CF5D3ED,0x14DEF9DEA2F79CD6,0x0000000000000000,0x1000000000000000 };

static const U64 _w_maxBPO[4] = { // 15*BPO fits into 8 words
    0x2913CE8B72676AE3,0x3910A40B8C82308F,0x0000000000000001,0xF000000000000000 };

static const U8 _b_BPOm2[32] = {      // BasePointOrder - 2
    0xEB,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

// R = 2**256 mod BPO
// R = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC6EF5BF4737DCF70D6EC31748D98951D
 static const U64 _w_R[4] = {   // R mod BPO
    0xD6EC31748D98951D,0xC6EF5BF4737DCF70,0xFFFFFFFFFFFFFFFE,0x0FFFFFFFFFFFFFFF };

// R2 = R**2 mod BPO
// R2 = 0x0399411B7C309A3DCEEC73D217F5BE65D00E1BA768859347A40611E3449C0F01
static const U64 _w_R2[4] = {   // R**2 mod BPO
    0xA40611E3449C0F01,0xD00E1BA768859347,0xCEEC73D217F5BE65,0x0399411B7C309A3D };

static const U64 _w_One[4] = { 1,0,0,0 };

#define BPO_MINV32  0xD2B51DA312547E1B // -1/BPO mod 2**64

// Z = (X*Y)/R mod BPO
void eco_MontMul(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 T[6];
    ecp_WordMulSet(T, X[0], Y);                 // T = X[0]*Y
    T[5]  = ecp_WordMulAdd(T, T, BPO_MINV32 * T[0], _w_BPO);
    T[5]  = ecp_WordMulAdd(T, T+1, X[1], Y);    // T = (T>>64) + X[1]*Y
    T[5] += ecp_WordMulAdd(T, T, BPO_MINV32 * T[0], _w_BPO);
    T[5]  = ecp_WordMulAdd(T, T+1, X[2], Y);    // T = (T>>64) + X[2]*Y
    T[5] += ecp_WordMulAdd(T, T, BPO_MINV32 * T[0], _w_BPO);
    T[5]  = ecp_WordMulAdd(T, T+1, X[3], Y);    // T = (T>>64) + X[3]*Y
    T[5] += ecp_WordMulAdd(T, T, BPO_MINV32 * T[0], _w_BPO);
    // T + (-1/BPO)*T*BPO mod 2**64 = 0 --> T[0] = 0
    // T[9] could be 2 at most
    while (T[5] != 0) T[5] += ecp_Sub(T+1, T+1, _w_maxBPO);
    ecp_Copy(Z, T+1);   // return T>>64
}

// Return Y = X*R mod BPO
void eco_ToMont(OUT U64 *Y, IN const U64 *X)
{
    eco_MontMul(Y, X, _w_R2);
}

// Return Y = X/R mod BPO
void eco_FromMont(OUT U64 *Y, IN const U64 *X)
{
    eco_MontMul(Y, X, _w_One);
    while(ecp_Cmp(Y, _w_BPO) >= 0) ecp_Sub(Y, Y, _w_BPO);
}

#define ECO_MONT(n) eco_MontMul(V,V,V); if(e & n) eco_MontMul(V,V,U)

// Calculate Y = X**E mod BPO
void eco_ExpModBPO(OUT U64 *Y, IN const U64 *X, IN const U8 *E, IN int bytes)
{
    U8 e;
    U64 U[4], V[4];

    eco_ToMont(U, X);
    ecp_Copy(V, _w_R);

    while (bytes > 0)
    {
        e = E[--bytes];
        ECO_MONT(0x80);
        ECO_MONT(0x40);
        ECO_MONT(0x20);
        ECO_MONT(0x10);
        ECO_MONT(0x08);
        ECO_MONT(0x04);
        ECO_MONT(0x02);
        ECO_MONT(0x01);
    }
    eco_FromMont(Y, V);
}

// Calculate Y = 1/X mod BPO
void eco_InvModBPO(OUT U64 *Y, IN const U64 *X)
{
    eco_ExpModBPO(Y, X, _b_BPOm2, 32);
}

// Z = X*Y mod BPO
void eco_MulMod(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 T[4];
    eco_MontMul(T, X, _w_R2);   // T = X*(R*R)/R = X*R
    eco_MontMul(Z, Y, T);       // Z = Y*(X*R)/R = X*Y
    while(ecp_Cmp(Z, _w_BPO) >= 0) ecp_Sub(Z, Z, _w_BPO);
}

