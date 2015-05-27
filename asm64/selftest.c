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
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "curve25519_mehdi_x64.h"
#include "curve25519_donna.h"

extern void ecp_PrintHexBytes(IN const char *name, IN const U8 *data, IN U32 size);
extern void ecp_PrintHexWords(IN const char *name, IN const U64 *data, IN U32 size);

/*
    The curve: y2 = x^3 + 486662x^2 + x  over 2^255 - 19
    base point x = 9. 

    b = 256
    p = 2**255 - 19
    l = 2**252 + 27742317777372353535851937790883648493

    p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
    l = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    d = -121665 * inv(121666)
    I = expmod(2,(p-1)/4,p)
    d = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
    I = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0
    -------------------------------------------------------------------------
    Internal points are represened as X/Z and maintained as a single array
    of 16 words: {X[4]:Z[4]}
*/
static const U64 inv_5[4] = {   // 1/5 mod p
    0x9999999999999996,0x9999999999999999,0x9999999999999999,0x1999999999999999 };

static const U64 _w_Pm1[4] = {
    0xFFFFFFFFFFFFFFEC,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0x7FFFFFFFFFFFFFFF };

static const U64 _w_D[4] = {
    0x75EB4DCA135978A3,0x00700A4D4141D8AB,0x8CC740797779E898,0x52036CEE2B6FFE73 };

static const U8 _b_Pm1d2[32] = {    // (p-1)/d
    0xF6,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3F };

static const U8 _b_Pm1[32] = {      // p-1
    0xEC,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F };

static const U8 _b_Om1[32] = {      // O-1
    0xEC,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

static const U8 _b_O[32] = {        // O    order of the base point
    0xED,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

// k1*k2 = 1 mod l ==> Q1 = k1.Q0 --> k2.Q1 = k2.k1.Q0 = Q0
static const U8 _b_k1[32] = {
    0x0B,0xE3,0xBE,0x63,0xBC,0x01,0x6A,0xAA,0xC9,0xE5,0x27,0x9F,0xB7,0x90,0xFB,0x44,
    0x37,0x2B,0x2D,0x4D,0xA1,0x73,0x5B,0x5B,0xB0,0x1A,0xC0,0x31,0x8D,0x89,0x21,0x03 };

static const U8 _b_k2[32] = {
    0x39,0x03,0xE3,0x27,0x7E,0x41,0x93,0x61,0x2D,0x3D,0x40,0x19,0x3D,0x60,0x68,0x21,
    0x60,0x25,0xEF,0x90,0xB9,0x8B,0x24,0xF2,0x50,0x60,0x94,0x21,0xD4,0x74,0x36,0x05 };

static const U8 pk1[32] = {
    0x46,0xF9,0xD2,0x09,0xC7,0x53,0x69,0xAC,0x5F,0x97,0xA3,0x28,0xA1,0x66,0x7A,0xC7,
    0xF8,0x6D,0x5E,0xC9,0xB2,0x0D,0x51,0x5C,0x11,0x39,0xA2,0x56,0x3B,0x10,0x13,0x60 };

static const U8 pk2[32] = {
    0x5A,0x26,0x6A,0xD3,0xD0,0x8D,0x9E,0x9B,0x8B,0xD9,0x2A,0xCC,0xCD,0x87,0xD5,0xB9,
    0x96,0xD1,0xDB,0xBA,0xB6,0xBC,0xC9,0x75,0x62,0x76,0xD7,0x61,0xF9,0x37,0x5F,0xA7 };

static const U64 _w_One[4] = {  1,0,0,0 };
static const U64 _w_Two[4] = {  2,0,0,0 };
static const U64 _w_V19[4] = { 19,0,0,0 };

// G = Base Point
static const U64 _w_Gx[4] = {  9,0,0,0 };
static const U64 _w_Gy[4] = {
    0x29E9C5A27ECED3D9,0x923D4D7E6D7C61B2,0xE01EDD2C7748D14C,0x20AE19A1B8A086B4 };

static const U64 _w_IxD[4] = {
    0x71C41B459E451EDD,0x498008497FBCC19E,0xF4C5CE99BBCB7C34,0x024AEE07B32C1AB4 };

static const U64 _w_I[4] = {
    0xC4EE1B274A0EA0B0,0x2F431806AD2FE478,0x2B4D00993DFBD7A7,0x2B8324804FC1DF0B };

static const U64 _w_P[4] = {
    0xFFFFFFFFFFFFFFED,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0x7FFFFFFFFFFFFFFF };

#define ECP_MOD(X)  while (ecp_Cmp(X, _w_P) >= 0) ecp_Sub(X, X, _w_P)

int ecp_IsZero(IN const U64 *X)
{
    return (X[0] | X[1] | X[2] | X[3]) == 0;
}

int curve25519_SelfTest(int level)
{
    int rc = 0;
    U64 A[4], B[4], C[4];
    U8 a[32], b[32], c[32], d[32];

    ecp_AddReduce(A, _w_I, _w_P);
    ECP_MOD(A);
    if (ecp_Cmp(A, _w_I) != 0)
    {
        rc++;
        printf("assert I+p == I mod p FAILED!!\n");
        ecp_PrintHexWords("A_1", A, 4);
    }

    if (ecp_Cmp(_w_I, _w_P) >= 0)
    {
        rc++;
        printf("assert I < P FAILED!!\n");
    }

    if (ecp_Cmp(_w_P, _w_I) <= 0)
    {
        rc++;
        printf("assert P > I FAILED!!\n");
    }

    ecp_MulReduce(B, _w_I, _w_D);
    ECP_MOD(B);
    if (ecp_Cmp(B, _w_IxD) != 0)
    {
        rc++;
        printf("assert I*D FAILED!!\n");
        ecp_PrintHexWords("A_2", B, 4);
    }

    // assert I*I == p-1
    ecp_MulMod(A, _w_I, _w_I);
    if (ecp_Cmp(A, _w_Pm1) != 0)
    {
        rc++;
        printf("assert mul(I,I) == p-1 FAILED!!\n");
        ecp_PrintHexWords("A_3", A, 4);
    }

    // assert I**2 == p-1
    ecp_SqrReduce(B, _w_I);
    ECP_MOD(B);
    if (ecp_Cmp(B, _w_Pm1) != 0)
    {
        rc++;
        printf("assert square(I) == p-1 FAILED!!\n");
        ecp_PrintHexWords("B_4", B, 4);
    }

    // assert (-I)*(-I) == p-1
    ecp_Sub(B, _w_P, _w_I);
    ecp_MulMod(A, B, B);
    if (ecp_Cmp(A, _w_Pm1) != 0)
    {
        rc++;
        printf("assert mul(-I,-I) == p-1 FAILED!!\n");
        ecp_PrintHexWords("A_5", A, 4);
        ecp_PrintHexWords("B_5", B, 4);
    }

    ecp_SetValue(A, 50153);
    ecp_Inverse(B, A);
    ecp_MulMod(A, A, B);
    if (ecp_Cmp(A, _w_One) != 0)
    {
        rc++;
        printf("invmod FAILED!!\n");
        ecp_PrintHexWords("inv_50153", B, 4);
        ecp_PrintHexWords("expected_1", A, 4);
    }

    // assert expmod(d,(p-1)/2,p) == p-1
    ecp_ExpMod(A, _w_D, _b_Pm1d2, 32);
    if (ecp_Cmp(A, _w_Pm1) != 0)
    {
        rc++;
        printf("assert expmod(d,(p-1)/2,p) == p-1 FAILED!!\n");
        ecp_PrintHexWords("A_3", A, 4);
    }

    ecp_CalculateY(a, ecp_BasePoint);
    ecp_BytesToWords(A, a);
    if (ecp_Cmp(A, _w_Gy) != 0)
    {
        rc++;
        printf("assert clacY(Base) == Base.y FAILED!!\n");
        ecp_PrintHexBytes("Calculated_Base.y", a, 32);
    }

    ecp_PointMultiply(a, ecp_BasePoint, _b_Om1, 32);
    if (memcmp(a, ecp_BasePoint, 32) != 0)
    {
        rc++;
        printf("assert (l-1).Base == Base FAILED!!\n");
        ecp_PrintHexBytes("A_5", a, 32);
    }

    ecp_PointMultiply(a, ecp_BasePoint, _b_O, 32);
    ecp_BytesToWords(A, a);
    if (!ecp_IsZero(A))
    {
        rc++;
        printf("assert l.Base == 0 FAILED!!\n");
        ecp_PrintHexBytes("A_6", a, 32);
    }

    // Key generation
    ecp_PointMultiply(a, ecp_BasePoint, pk1, 32);
    ecp_PrintHexBytes("PublicKey1", a, 32);
    ecp_PointMultiply(b, ecp_BasePoint, pk2, 32);
    ecp_PrintHexBytes("PublicKey2", b, 32);

    // ECDH - key exchange
    ecp_PointMultiply(c, b, pk1, 32);
    ecp_PrintHexBytes("SharedKey1", c, 32);
    ecp_PointMultiply(d, a, pk2, 32);
    ecp_PrintHexBytes("SharedKey2", d, 32);
    if (memcmp(c, d, 32) != 0)
    {
        rc++;
        printf("ECDH key exchange FAILED!!\n");
    }

    memset(a, 0x44, 32);        // our secret key
    ecp_PointMultiply(b, ecp_BasePoint, a, 32); // public key
    ecp_PointMultiply(c, b, _b_k1, 32);
    ecp_PointMultiply(d, c, _b_k2, 32);
    if (memcmp(d, b, 32) != 0)
    {
        rc++;
        printf("assert k1.k2.D == D FAILED!!\n");
        ecp_PrintHexBytes("D", d, 4);
        ecp_PrintHexBytes("C", c, 4);
        ecp_PrintHexBytes("A", a, 4);
    }

    ecp_BytesToWords(A, _b_k1);
    ecp_BytesToWords(B, _b_k2);
    eco_InvModBPO(C, A);
    if (ecp_Cmp(C, B) != 0)
    {
        rc++;
        printf("assert 1/k1 == k2 mod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", C, 4);
        ecp_PrintHexWords("Expt", B, 4);
    }

    eco_MulMod(C, A, B);
    if (ecp_Cmp(C, _w_One) != 0)
    {
        rc++;
        printf("assert k1*k2 == 1 mod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", C, 4);
    }
    return rc;
}