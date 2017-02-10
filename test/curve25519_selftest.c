/* The MIT License (MIT)
 * 
 * Copyright (c) 2015 mehdi sotoodeh
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject to 
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
    of 16 words: {X[K_WORDS]:Z[K_WORDS]}
*/
#ifdef ECP_SELF_TEST

#include <stdio.h>
#include <stdlib.h>
#include "../include/external_calls.h"
#include "../source/curve25519_mehdi.h"
#include "curve25519_donna.h"
#include "../source/sha512.h"

void ecp_PrintHexBytes(IN const char *name, IN const U8 *data, IN U32 size);
void ecp_PrintHexWords(IN const char *name, IN const U_WORD *data, IN U32 size);
void ecp_PrintWords(IN const char *name, IN const U_WORD *data, IN U32 size);
void GetRandomBytes(unsigned char *buffer, int size);

extern const U_WORD _w_P[K_WORDS];
extern const U_WORD _w_maxP[K_WORDS];
extern const U_WORD _w_I[K_WORDS];
extern const U_WORD _w_2d[K_WORDS];
extern const U_WORD _w_NxBPO[16][K_WORDS];
extern const PA_POINT _w_base_folding8[256];

#define _w_BPO      _w_NxBPO[1]
#define _w_maxBPO   _w_NxBPO[15]

static const U8 _b_Pp3d8[32] = {    /* (P+3)/8 */
    0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x0F };

#define _w_Zero     _w_base_folding8[0].T2d
#define _w_One      _w_base_folding8[0].YpX

static const U_WORD inv_5[K_WORDS] = /* 1/5 mod p */
    W256(0x99999996,0x99999999,0x99999999,0x99999999,0x99999999,0x99999999,0x99999999,0x19999999);

static const U_WORD _w_Pm1[K_WORDS] =
    W256(0xFFFFFFEC,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x7FFFFFFF);

static const U_WORD _w_D[K_WORDS] =
    W256(0x135978A3,0x75EB4DCA,0x4141D8AB,0x00700A4D,
    0x7779E898,0x8CC74079,0x2B6FFE73,0x52036CEE);

static const U8 _b_Pm1d2[32] = {    /* (p-1)/d */
    0xF6,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3F };

static const U8 _b_Pm1[32] = {      /* p-1 */
    0xEC,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F };

static const U8 _b_Om1[32] = {      /* O-1 */
    0xEC,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

static const U8 _b_O[32] = {        /* O    order of the base point */
    0xED,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

/* k1*k2 = 1 mod l ==> Q1 = k1.Q0 --> k2.Q1 = k2.k1.Q0 = Q0 */
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

static const U_WORD _w_Two[K_WORDS] = W256( 2,0,0,0,0,0,0,0);
static const U_WORD _w_V19[K_WORDS] = W256(19,0,0,0,0,0,0,0);

/* G = Base Point */
static const U_WORD _w_Gx[K_WORDS] = W256(9,0,0,0,0,0,0,0);
static const U_WORD _w_Gy[K_WORDS] = 
    W256(0x7ECED3D9,0x29E9C5A2,0x6D7C61B2,0x923D4D7E,0x7748D14C,0xE01EDD2C,0xB8A086B4,0x20AE19A1);

static const U_WORD _w_IxD[K_WORDS] =
    W256(0x9E451EDD,0x71C41B45,0x7FBCC19E,0x49800849,0xBBCB7C34,0xF4C5CE99,0xB32C1AB4,0x024AEE07);

static const U_WORD _w_IxDmodBPO[K_WORDS] = /* I*D mod BPO */
    W256(0xFDC0315D,0x598EF460,0xE11649F4,0x2DEBEE7C,0x0278EFB4,0x331877FE,0xFBE03ECE,0x00A63CC5);

static const U8 sha512_abc[] = {    /* 'abc' */
    0xDD,0xAF,0x35,0xA1,0x93,0x61,0x7A,0xBA,0xCC,0x41,0x73,0x49,0xAE,0x20,0x41,0x31,
    0x12,0xE6,0xFA,0x4E,0x89,0xA9,0x7E,0xA2,0x0A,0x9E,0xEE,0xE6,0x4B,0x55,0xD3,0x9A,
    0x21,0x92,0x99,0x2A,0x27,0x4F,0xC1,0xA8,0x36,0xBA,0x3C,0x23,0xA3,0xFE,0xEB,0xBD,
    0x45,0x4D,0x44,0x23,0x64,0x3C,0xE8,0x0E,0x2A,0x9A,0xC9,0x4F,0xA5,0x4C,0xA4,0x9F };

static const U8 sha512_ax1m[] = {   /* 'a' repeated 1,000,000 times */
    0xE7,0x18,0x48,0x3D,0x0C,0xE7,0x69,0x64,0x4E,0x2E,0x42,0xC7,0xBC,0x15,0xB4,0x63,
    0x8E,0x1F,0x98,0xB1,0x3B,0x20,0x44,0x28,0x56,0x32,0xA8,0x03,0xAF,0xA9,0x73,0xEB,
    0xDE,0x0F,0xF2,0x44,0x87,0x7E,0xA6,0x0A,0x4C,0xB0,0x43,0x2C,0xE5,0x77,0xC3,0x1B,
    0xEB,0x00,0x9C,0x5C,0x2C,0x49,0xAA,0x2E,0x4E,0xAD,0xB2,0x17,0xAD,0x8C,0xC0,0x9B };

static const U8 _b_BPOm2[32] = {      /* BasePointOrder - 2 */
    0xEB,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

/* R = 2**256 mod BPO */
/* R = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC6EF5BF4737DCF70D6EC31748D98951D */
 static const U_WORD _w_R[K_WORDS] = /* R mod BPO */
    W256(0x8D98951D,0xD6EC3174,0x737DCF70,0xC6EF5BF4,
         0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF);

/* R2 = R**2 mod BPO */
/* R2 = 0x0399411B7C309A3DCEEC73D217F5BE65D00E1BA768859347A40611E3449C0F01 */
static const U_WORD _w_R2[K_WORDS] = /* R**2 mod BPO */
    W256(0x449C0F01,0xA40611E3,0x68859347,0xD00E1BA7,
         0x17F5BE65,0xCEEC73D2,0x7C309A3D,0x0399411B);

int ecp_IsZero(IN const U_WORD *X)
{
    return (X[0] | X[1] | X[2] | X[3]
#ifndef WORDSIZE_64
        | X[4] | X[5] | X[6] | X[7]
#endif
        ) == 0;
}

/* Z = X + Y mod BPO */
void eco_AddMod(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y)
{
    eco_AddReduce(Z, X, Y);
    eco_Mod(Z);
}

/* Z = X*Y mod BPO */
void eco_MulMod(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y)
{
    eco_MulReduce(Z, X, Y);
    eco_Mod(Z);
}

#ifdef WORDSIZE_32
#define BPO_MINV32  0x12547E1B  /* -1/BPO mod 2**32 */

#define ECP_MULADD_W0(Z,Y,b,X) c.u64 = (U64)(b)*(X) + (Y); Z = c.u32.lo;
#define ECP_MULADD_W1(Z,Y,b,X) c.u64 = (U64)(b)*(X) + (U64)(Y) + c.u32.hi; Z = c.u32.lo;

/* Computes Z = Y + b*X and return carry */
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
    return c.u32.hi;    /* 0 or 1 as the carry out */
}

/* Z = (X*Y)/R mod BPO */
void eco_MontMul(OUT U32 *Z, IN const U32 *X, IN const U32 *Y)
{
    int i;
    U32 T[10] = {0};
    for (i = 0; i < 8; i++)
    {
        T[9]  = eco_WordMulAdd(T, T+1, X[i], Y);     /* T = (T>>32) + X[i]*Y */
        T[9] += eco_WordMulAdd(T, T, BPO_MINV32 * T[0], _w_BPO);
        /* T + (-1/BPO)*T*BPO mod 2**32 = 0 --> T[0] = 0 */
    }
    /* T[9] could be 2 at most */
    while (T[9] != 0) T[9] += ecp_Sub(T+1, T+1, _w_maxBPO);
    ecp_Copy(Z, T+1);
}
#else
#define BPO_MINV64  0xD2B51DA312547E1B /* -1/BPO mod 2**64 */

/* Z = (X*Y)/R mod BPO */
void eco_MontMul(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 T[6];
    ecp_WordMulSet(T, X[0], Y);                 /* T = X[0]*Y */
    T[5]  = ecp_WordMulAdd(T, T, BPO_MINV64 * T[0], _w_BPO);
    T[5]  = ecp_WordMulAdd(T, T+1, X[1], Y);    /* T = (T>>64) + X[1]*Y */
    T[5] += ecp_WordMulAdd(T, T, BPO_MINV64 * T[0], _w_BPO);
    T[5]  = ecp_WordMulAdd(T, T+1, X[2], Y);    /* T = (T>>64) + X[2]*Y */
    T[5] += ecp_WordMulAdd(T, T, BPO_MINV64 * T[0], _w_BPO);
    T[5]  = ecp_WordMulAdd(T, T+1, X[3], Y);    /* T = (T>>64) + X[3]*Y */
    T[5] += ecp_WordMulAdd(T, T, BPO_MINV64 * T[0], _w_BPO);
    /* T + (-1/BPO)*T*BPO mod 2**64 = 0 --> T[0] = 0 */
    /* T[5] could be 2 at most */
    while (T[5] != 0) T[5] += ecp_Sub(T+1, T+1, _w_maxBPO);
    ecp_Copy(Z, T+1);   /* return T>>64 */
    //eco_ReduceHiWord(Z, T[5], T+1);
}
#endif

/* Return Y = X*R mod BPO */
void eco_ToMont(OUT U_WORD *Y, IN const U_WORD *X)
{
    eco_MontMul(Y, X, _w_R2);
}

/* Return Y = X/R mod BPO */
void eco_FromMont(OUT U_WORD *Y, IN const U_WORD *X)
{
    eco_MontMul(Y, X, _w_One);
}

#define ECO_SQRMUL(n) eco_MulReduce(Y,Y,Y); if(e & n) eco_MulReduce(Y,Y,X)

/* Calculate Y = X**E mod BPO */
void eco_ExpModBPO(OUT U_WORD *Y, IN const U_WORD *X, IN const U8 *E, IN int bytes)
{
    U8 e;
    ecp_SetValue(Y, 1);

    while (bytes > 0)
    {
        e = E[--bytes];
        ECO_SQRMUL(0x80);
        ECO_SQRMUL(0x40);
        ECO_SQRMUL(0x20);
        ECO_SQRMUL(0x10);
        ECO_SQRMUL(0x08);
        ECO_SQRMUL(0x04);
        ECO_SQRMUL(0x02);
        ECO_SQRMUL(0x01);
    }
}

/* Calculate Y = 1/X mod BPO */
void eco_InvModBPO(OUT U_WORD *Y, IN const U_WORD *X)
{
    eco_ExpModBPO(Y, X, _b_BPOm2, 32);
}

// check if y^2 == x^3 + 486662x^2 + x  mod 2^255 - 19
int x25519_IsOnCurve(IN const U_WORD *X, IN const U_WORD *Y)
{
    U_WORD A[K_WORDS], B[K_WORDS];

    ecp_SetValue(A, 486662);
    ecp_AddReduce(A, A, X);     /* x + 486662 */
    ecp_MulReduce(A, A, X);     /* x^2 + 486662x */
    ecp_MulReduce(A, A, X);     /* x^3 + 486662x^2 */
    ecp_AddReduce(A, A, X);     /* x^3 + 486662x^2 + x */
    ecp_SqrReduce(B, Y);
    ecp_Mod(A);
    ecp_Mod(B);
    if (ecp_CmpNE(B, A) == 0) return 1;
    // check if sqrt(-1) was applied incorrectly
    ecp_Sub(B, _w_P, B);
    return (ecp_CmpNE(B, A) == 0) ? 1 : 0;
}

int hash_test(int level)
{
    int i, rc = 0;
    SHA512_CTX H;
    U8 buff[100], md[SHA512_DIGEST_LENGTH];

    /* [a:b] = H(sk) */
    SHA512_Init(&H);
    SHA512_Update(&H, "abc", 3);
    SHA512_Final(md, &H);
    if (memcmp(md, sha512_abc, SHA512_DIGEST_LENGTH) != 0)
    {
        rc++;
        printf("KAT: SHA512('abc') FAILED!!\n");
        ecp_PrintHexBytes("H_1", md, SHA512_DIGEST_LENGTH);
    }

    SHA512_Init(&H);
    mem_fill (buff, 'a', 100);
    for (i = 0; i < 10000; i++) SHA512_Update(&H, buff, 100);
    SHA512_Final(md, &H);
    if (memcmp(md, sha512_ax1m, SHA512_DIGEST_LENGTH) != 0)
    {
        rc++;
        printf("KAT: SHA512('a'*1000000) FAILED!!\n");
        ecp_PrintHexBytes("H_2", md, SHA512_DIGEST_LENGTH);
    }
    return rc;
}

/*
    Calculate: point R = a*P + b*Q  where P is base point
*/
void edp_DualPointMultiply(
    Affine_POINT *r,
    const U8 *a, const U8 *b, const Affine_POINT *q)
{
    int i, j;
    M32 k;
    Ext_POINT S;
    PA_POINT U;
    PE_POINT V;

    /* U = pre-compute(Q) */
    ecp_AddReduce(U.YpX, q->y, q->x);
    ecp_SubReduce(U.YmX, q->y, q->x);
    ecp_MulReduce(U.T2d, q->y, q->x);
    ecp_MulReduce(U.T2d, U.T2d, _w_2d);

    /* set V = pre-compute(P + Q) */
    ecp_Copy(S.x, q->x);
    ecp_Copy(S.y, q->y);
    ecp_SetValue(S.z, 1);
    ecp_MulReduce(S.t, S.x, S.y);
    edp_AddBasePoint(&S);   /* S = P + Q */
    /*  */
    ecp_AddReduce(V.YpX, S.y, S.x);
    ecp_SubReduce(V.YmX, S.y, S.x);
    ecp_MulReduce(V.T2d, S.t, _w_2d);
    ecp_AddReduce(V.Z2, S.z, S.z);

    /* Set S = (0,1) */
    ecp_SetValue(S.x, 0);
    ecp_SetValue(S.y, 1);
    ecp_SetValue(S.z, 1);
    ecp_SetValue(S.t, 0);

    for (i = 32; i-- > 0;)
    {
        k.u8.b0 = a[i];
        k.u8.b1 = b[i];
        for (j = 0; j < 8; j++)
        {
            edp_DoublePoint(&S);
            switch (k.u32 & 0x8080)
            {
            case 0x0080: edp_AddBasePoint(&S); break;
            case 0x8000: edp_AddAffinePoint(&S, &U); break;
            case 0x8080: edp_AddPoint(&S, &S, &V); break;
            }
            k.u32 <<= 1;
        }
    }
    ecp_Inverse(S.z, S.z);
    ecp_MulMod(r->x, S.x, S.z);
    ecp_MulMod(r->y, S.y, S.z);
}

void print_words(IN const char *txt, IN const U_WORD *data, IN U32 size)
{
    U32 i;
    printf("%s0x%08X", txt, *data++);
    for (i = 1; i < size; i++) printf(",0x%08X", *data++);
}

void pre_compute_base_point()
{
    Ext_POINT P = {{0},{1},{1},{0}};
    PA_POINT R;
    int i;
    printf("\nconst PA_POINT pre_BaseMultiples[16] = \n{\n");
    for (i = 0; i < 16; i++)
    {
        printf("  { /* %d*P */\n", i);
        ecp_AddReduce(R.YpX, P.y, P.x); ecp_Mod(R.YpX);
        ecp_SubReduce(R.YmX, P.y, P.x); ecp_Mod(R.YmX);
        ecp_MulMod(R.T2d, P.t, _w_2d);

        print_words("    W256(",R.YpX, K_WORDS);
        print_words("),\n    W256(",R.YmX, K_WORDS);
        print_words("),\n    W256(",R.T2d, K_WORDS);
        if (i == 15)
        {
            printf(")\n  }\n};\n");
            break;
        }
        printf(")\n  },\n");

        edp_AddBasePoint(&P);
        /* make it affine */
        ecp_Inverse(P.z, P.z);
        ecp_MulMod(P.x, P.x, P.z);
        ecp_MulMod(P.y, P.y, P.z);
        ecp_MulMod(P.t, P.x, P.y);
        ecp_SetValue(P.z, 1);
    }
}

static const Ext_POINT _w_BasePoint = {   /* y = 4/5 mod P */
    W256(0x8F25D51A,0xC9562D60,0x9525A7B2,0x692CC760,0xFDD6DC5C,0xC0A4E231,0xCD6E53FE,0x216936D3),
    W256(0x66666658,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666),
    W256(0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000),
    W256(0xA5B7DDA3,0x6DDE8AB3,0x775152F5,0x20F09F80,0x64ABE37D,0x66EA4E8E,0xD78B7665,0x67875F0F)
};

void Ext2Affine(PA_POINT *r, Ext_POINT *p)
{
    ecp_Inverse(p->z, p->z);
    ecp_MulMod(p->x, p->x, p->z);
    ecp_MulMod(p->y, p->y, p->z);
    ecp_MulMod(p->t, p->x, p->y);
    ecp_SetValue(p->z, 1);

    ecp_AddReduce(r->YpX, p->y, p->x); ecp_Mod(r->YpX);
    ecp_SubReduce(r->YmX, p->y, p->x); ecp_Mod(r->YmX);
    ecp_MulMod(r->T2d, p->t, _w_2d);
}

void pre_compute_base_folding4()
{
    Ext_POINT S = _w_BasePoint;
    PA_POINT P0, P1, P2, P3;
    PA_POINT R;
    int i, j;

    /* Calculate: P0=base, P1=(2^64)*P0, P2=(2^64)*P1, P3=(2^64)*P2 */
    Ext2Affine(&P0, &S);
    for (j = 0; j < 64; j++) edp_DoublePoint(&S);
    Ext2Affine(&P1, &S);
    for (j = 0; j < 64; j++) edp_DoublePoint(&S);
    Ext2Affine(&P2, &S);
    for (j = 0; j < 64; j++) edp_DoublePoint(&S);
    Ext2Affine(&P3, &S);

    printf("\nconst PA_POINT _w_base_folding4[16] = \n{\n");
    for (i = 0; i < 16; i++)
    {
        ecp_SetValue(S.x, 0);
        ecp_SetValue(S.y, 1);
        ecp_SetValue(S.z, 1);
        ecp_SetValue(S.t, 0);

        if (i & 1) edp_AddAffinePoint(&S, &P0);
        if (i & 2) edp_AddAffinePoint(&S, &P1);
        if (i & 4) edp_AddAffinePoint(&S, &P2);
        if (i & 8) edp_AddAffinePoint(&S, &P3);
        Ext2Affine(&R, &S);

        printf("  { /* P{%d} */\n", i);
        print_words("    W256(",R.YpX, K_WORDS);
        print_words("),\n    W256(",R.YmX, K_WORDS);
        print_words("),\n    W256(",R.T2d, K_WORDS);
        if (i == 15)
        {
            printf(")\n  }\n};\n");
            break;
        }
        printf(")\n  },\n");
    }
}

void pre_compute_base_folding8()
{
    Ext_POINT S = _w_BasePoint;
    PA_POINT P0, P1, P2, P3, P4, P5, P6, P7;
    PA_POINT R;
    int i, j;

    // Calculate: P0=base, P1=(2^64)*P0, P2=(2^64)*P1, P3=(2^64)*P2
    Ext2Affine(&P0, &S);
    for (j = 0; j < 32; j++) edp_DoublePoint(&S);
    Ext2Affine(&P1, &S);
    for (j = 0; j < 32; j++) edp_DoublePoint(&S);
    Ext2Affine(&P2, &S);
    for (j = 0; j < 32; j++) edp_DoublePoint(&S);
    Ext2Affine(&P3, &S);
    for (j = 0; j < 32; j++) edp_DoublePoint(&S);
    Ext2Affine(&P4, &S);
    for (j = 0; j < 32; j++) edp_DoublePoint(&S);
    Ext2Affine(&P5, &S);
    for (j = 0; j < 32; j++) edp_DoublePoint(&S);
    Ext2Affine(&P6, &S);
    for (j = 0; j < 32; j++) edp_DoublePoint(&S);
    Ext2Affine(&P7, &S);

    printf("\nconst PA_POINT _w_base_folding8[16] = \n{\n");
    for (i = 0; i < 256; i++)
    {
        ecp_SetValue(S.x, 0);
        ecp_SetValue(S.y, 1);
        ecp_SetValue(S.z, 1);
        ecp_SetValue(S.t, 0);

        if (i & 1) edp_AddAffinePoint(&S, &P0);
        if (i & 2) edp_AddAffinePoint(&S, &P1);
        if (i & 4) edp_AddAffinePoint(&S, &P2);
        if (i & 8) edp_AddAffinePoint(&S, &P3);
        if (i & 16) edp_AddAffinePoint(&S, &P4);
        if (i & 32) edp_AddAffinePoint(&S, &P5);
        if (i & 64) edp_AddAffinePoint(&S, &P6);
        if (i & 128) edp_AddAffinePoint(&S, &P7);
        Ext2Affine(&R, &S);

        printf("  { /* P{%d} */\n", i);
        print_words("    W256(",R.YpX, K_WORDS);
        print_words("),\n    W256(",R.YmX, K_WORDS);
        print_words("),\n    W256(",R.T2d, K_WORDS);
        if (i == 255)
        {
            printf(")\n  }\n};\n");
            break;
        }
        printf(")\n  },\n");
    }
}



/* Y = X ** E mod P */
/* E is in little-endian format */
void ecp_ExpMod(U_WORD* Y, const U_WORD* X, const U8* E, int bytes)
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
    ecp_Mod(Y);
}


void ecp_CalculateY(OUT U8 *Y, IN const U8 *X)
{
    U_WORD A[K_WORDS], B[K_WORDS], T[K_WORDS];

    ecp_BytesToWords(T, X);
    ecp_SetValue(A, 486662);
    ecp_AddReduce(A, A, T);     /* x + 486662 */
    ecp_MulReduce(A, A, T);     /* x^2 + 486662x */
    ecp_MulReduce(A, A, T);     /* x^3 + 486662x^2 */
    ecp_AddReduce(A, A, T);     /* x^3 + 486662x^2 + x */
    ecp_ExpMod(T, A, _b_Pp3d8, 32);
    /* if T*T != A: T *= sqrt(-1) */
    ecp_MulMod(B, T, T);
    if (ecp_CmpNE(B, A)) ecp_MulMod(T, T, _w_I);
    ecp_WordsToBytes(Y, T);
}

static const U_WORD _w_NxRmodBPO[8][K_WORDS] = { /* n*R+1 mod BPO */
    W256(1,0,0,0,0,0,0,0),
    W256(0x8D98951E,0xD6EC3174,0x737DCF70,0xC6EF5BF4,0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF),
    W256(0xBE3B564E,0x55C5FFCE,0x4404020B,0x78FFBE0A,0xFFFFFFFD,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF),
    W256(0xEEDE177E,0xD49FCE28,0x148A34A5,0x2B102020,0xFFFFFFFC,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF),
    W256(0x1F80D8AE,0x53799C83,0xE5106740,0xDD208235,0xFFFFFFFA,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF),
    W256(0x502399DE,0xD2536ADD,0xB59699DA,0x8F30E44B,0xFFFFFFF9,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF),
    W256(0x80C65B0E,0x512D3937,0x861CCC75,0x41414661,0xFFFFFFF8,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF),
    W256(0xB1691C3E,0xD0070791,0x56A2FF0F,0xF351A877,0xFFFFFFF6,0xFFFFFFFF,0xFFFFFFFF,0x0FFFFFFF)
};

int curve25519_SelfTest(int level)
{
    int i, rc = 0;
    M32 m;
    U_WORD A[K_WORDS], B[K_WORDS], C[K_WORDS], T[2*K_WORDS];
    U8 a[32], b[32], c[32], d[32];

    /* Make sure library is built with correct byte ordering */
    m.u32 = 0x12345678;
    if (m.u16.w1 != 0x1234 || m.u16.w0 != 0x5678 ||
        m.u8.b3 != 0x12 || m.u8.b2 != 0x34 || m.u8.b1 != 0x56 || m.u8.b0 != 0x78)
    {
        rc++;
        if (m.bytes[0] == 0x12) /* big-endian  */
            printf("Incorrect byte order configuration used (define ECP_BIG_ENDIAN).\n");
        if (m.bytes[0] == 0x78) /* little-endian  */
            printf("Incorrect byte order configuration used (define ECP_LITTLE_ENDIAN).\n");
        return rc;
    }

    /* Make sure we handle overflow conditions correctly */
    for (i = 0; i < 8; i++)
    {
        ecp_SetValue(A, 1);    
        eco_ReduceHiWord(B, (U32)i, A);
        eco_Mod(B);
        if (ecp_CmpNE(B, _w_NxRmodBPO[i]))
        {
            rc++;
            printf("eco_ReduceHiWord(%d) FAILED!!\n", i);
            ecp_PrintHexWords("Calc", B, K_WORDS);
            ecp_PrintHexWords("Expt", _w_NxRmodBPO[i], K_WORDS);
        }
    }
    
    rc = hash_test(level);

    ecp_AddReduce(A, _w_I, _w_P);
    ecp_Mod(A);
    if (ecp_CmpNE(A, _w_I))
    {
        rc++;
        printf("assert I+p == I mod p FAILED!!\n");
        ecp_PrintHexWords("A_1", A, K_WORDS);
    }
    ecp_MulReduce(B, _w_I, _w_D);
    ecp_Mod(B);
    if (ecp_CmpNE(B, _w_IxD))
    {
        rc++;
        printf("assert I*D FAILED!!\n");
        ecp_PrintHexWords("A_2", B, K_WORDS);
    }

    /* calculate I*D mod BPO using different interfaces */
    eco_ToMont(A, _w_I);
    eco_ToMont(B, _w_D);
    eco_MontMul(C, A, B);
    eco_FromMont(A, C);
    eco_Mod(A);
    if (ecp_CmpNE(A, _w_IxDmodBPO))
    {
        rc++;
        printf("methods 1 of I*D mod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", A, K_WORDS);
        ecp_PrintHexWords("Expt", _w_IxDmodBPO, K_WORDS);
    }

    eco_MulMod(B, _w_I, _w_D);
    if (ecp_CmpNE(B, _w_IxDmodBPO))
    {
        rc++;
        printf("methods 2 of I*D mod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", B, K_WORDS);
        ecp_PrintHexWords("Expt", _w_IxDmodBPO, K_WORDS);
    }

    ecp_Mul(T, _w_I, _w_D);
    eco_ReduceHiWord(T+3, T[7], T+3);
    eco_ReduceHiWord(T+2, T[6], T+2);
    eco_ReduceHiWord(T+1, T[5], T+1);
    eco_ReduceHiWord(T+0, T[4], T+0);
    eco_Mod(T);
    if (ecp_CmpNE(B, _w_IxDmodBPO))
    {
        rc++;
        printf("methods 3 of I*D mod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", B, K_WORDS);
        ecp_PrintHexWords("Expt", _w_IxDmodBPO, K_WORDS);
    }

    for (i = 0; i < 1000; i++)
    {
        ecp_SetValue(C, C[0]+i);
        // method 1
        eco_ToMont(A, C);
        eco_ToMont(B, _w_D);
        eco_MontMul(T, A, B);
        eco_FromMont(A, T);
        eco_Mod(A);
        // method 2
        ecp_Mul(T, C, _w_D);
        eco_ReduceHiWord(B, T[K_WORDS], T);
        eco_Mod(B);
        if (ecp_CmpNE(A, B))
        {
            rc++;
            printf("methods 2 MulMod BPO FAILED!!\n");
            ecp_PrintHexWords("Calc", B, K_WORDS);
            ecp_PrintHexWords("Expt", A, K_WORDS);
        }
    }
    ecp_SetValue(A, 50153);
    ecp_Inverse(B, A);
    ecp_MulMod(A, A, B);
    if (ecp_CmpNE(A, _w_One))
    {
        rc++;
        printf("invmod FAILED!!\n");
        ecp_PrintHexWords("inv_50153", B, K_WORDS);
        ecp_PrintHexWords("expected_1", A, K_WORDS);
    }

    /* assert expmod(d,(p-1)/2,p) == p-1 */
    ecp_ExpMod(A, _w_D, _b_Pm1d2, 32);
    if (ecp_CmpNE(A, _w_Pm1))
    {
        rc++;
        printf("assert expmod(d,(p-1)/2,p) == p-1 FAILED!!\n");
        ecp_PrintHexWords("A_3", A, K_WORDS);
    }
    /* assert I**2 == p-1 */
    ecp_MulMod(A, _w_I, _w_I);
    if (ecp_CmpNE(A, _w_Pm1))
    {
        rc++;
        printf("assert expmod(I,2,p) == p-1 FAILED!!\n");
        ecp_PrintHexWords("A_4", A, K_WORDS);
    }

    ecp_CalculateY(a, ecp_BasePoint);
    ecp_BytesToWords(A, a);
    if (ecp_CmpNE(A, _w_Gy))
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

    /* Key generation */
    ecp_PointMultiply(a, ecp_BasePoint, pk1, 32);
    ecp_PointMultiply(b, ecp_BasePoint, pk2, 32);

    /* ECDH - key exchange */
    ecp_PointMultiply(c, b, pk1, 32);
    ecp_PointMultiply(d, a, pk2, 32);
    if (memcmp(c, d, 32) != 0)
    {
        rc++;
        printf("ECDH key exchange FAILED!!\n");
        ecp_PrintHexBytes("PublicKey1", a, 32);
        ecp_PrintHexBytes("PublicKey2", b, 32);
        ecp_PrintHexBytes("SharedKey1", c, 32);
        ecp_PrintHexBytes("SharedKey2", d, 32);
    }

    mem_fill(a, 0x44, 32);        /* our secret key */
    ecp_PointMultiply(b, ecp_BasePoint, a, 32); /* public key */
    ecp_PointMultiply(c, b, _b_k1, 32);
    ecp_PointMultiply(d, c, _b_k2, 32);
    if (memcmp(d, b, 32) != 0)
    {
        rc++;
        printf("assert k1.k2.D == D FAILED!!\n");
        ecp_PrintHexBytes("D", d, K_WORDS);
        ecp_PrintHexBytes("C", c, K_WORDS);
        ecp_PrintHexBytes("A", a, K_WORDS);
    }

    ecp_BytesToWords(A, _b_k1);
    ecp_BytesToWords(B, _b_k2);
    eco_InvModBPO(C, A);
    eco_Mod(C);
    if (ecp_CmpNE(C, B))
    {
        rc++;
        printf("assert 1/k1 == k2 mod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", C, K_WORDS);
        ecp_PrintHexWords("Expt", B, K_WORDS);
    }

    eco_MulMod(C, A, B);
    if (ecp_CmpNE(C, _w_One))
    {
        rc++;
        printf("assert k1*k2 == 1 mod BPO FAILED!!\n");
        ecp_PrintHexWords("Calc", C, K_WORDS);
    }

#if 0
    /* expriment:
        pick x and find its associated y
            - check if P=(x,y) is on the curve
            - check order of P is same as BPO (same sub-group as base point)
        interestingly:
        OnCurve=True  Order=DIFFERENT
        x = 0x000000000000000000000000000000000000000000000000000000000000000A
        y = 0x7FA11E2C10248F175E1C49E162A38AF68B311C6719C9B2F6A042B8742E891F65
        OnCurve=FALSE  Order=DIFFERENT
        x = 0x000000000000000000000000000000000000000000000000000000000000000C
        y = 0x79F72F9D93C775B921FB784C4B441492F5DCBECBAA69F549FA7CB8CEB80FD0DE
        OnCurve=True  Order=BPO
        x = 0x0000000000000000000000000000000000000000000000000000000000000010
        y = 0x36B20194B9EE7885E888642D2006D60CDCC836D17F615E8416989556B3941598
    */
    mem_fill(b, 0, 32);
    for (i = 0; i < 100; i++)
    {
        int order_test, on_curve;
        //GetRandomBytes(b, 32);
        b[0] = (U8)(i+10);
        b[31] &= 0x7f;
        /*ecp_PointMultiply(b, ecp_BasePoint, b, 32); */
        ecp_PointMultiply(a, b, _b_Om1, 32);
        order_test = (memcmp(a, b, 32) == 0) ? 1 : 0;

        /* It it on the curve? */
        ecp_CalculateY(a, b);
        ecp_BytesToWords(A, a);
        ecp_BytesToWords(B, b);
        on_curve = x25519_IsOnCurve(B, A);
        if (on_curve) printf("OnCurve=True"); else printf("OnCurve=FALSE");
        if (order_test) printf("  Order=BPO\n"); else printf("  Order=DIFFERENT\n");
        ecp_PrintHexBytes("x", b, 32);
        ecp_PrintHexBytes("y", a, 32);
    }
#endif
    /*pre_compute_base_point(); */
    /*pre_compute_base_powers(); */

    return rc;
}

static U8 m_6[32] = {6};
static U8 m_7[32] = {7};
static U8 m_11[32] = {11};
static U8 m_50[32] = {50};

/* Pre-calculate base point values */
static const Affine_POINT ed25519_BasePoint = {   /* y = 4/5 mod P */
    W256(0x8F25D51A,0xC9562D60,0x9525A7B2,0x692CC760,0xFDD6DC5C,0xC0A4E231,0xCD6E53FE,0x216936D3),
    W256(0x66666658,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666)
};

void ecp_PrintHexWords(IN const char *name, IN const U_WORD *data, IN U32 size);

void edp_DualPointMultiply(
    Affine_POINT *r,
    const U8 *a, const U8 *b, const Affine_POINT *q);

/* Use this version if optimizing for memory usage */
int alt_ed25519_VerifySignature(
    const unsigned char *signature,             /* IN: signature (R,S) */
    const unsigned char *publicKey,             /* IN: public key */
    const unsigned char *msg, size_t msg_size)  /* IN: message to sign */
{
    SHA512_CTX H;
    Affine_POINT Q, T;
    U_WORD h[K_WORDS];
    U8 md[SHA512_DIGEST_LENGTH];

    md[0] = ecp_DecodeInt(Q.y, publicKey);
    ed25519_CalculateX(Q.x, Q.y, ~md[0]);       /* Invert parity for -Q */

    /* TODO: Validate Q is a point on the curve */

    /* h = H(enc(R) + pk + m)  mod BPO */
    SHA512_Init(&H);
    SHA512_Update(&H, signature, 32);
    SHA512_Update(&H, publicKey, 32);
    SHA512_Update(&H, msg, msg_size);
    SHA512_Final(md, &H);
    eco_DigestToWords(h, md);
    eco_Mod(h);

    /* T = s*P + h*(-Q) = (s - h*a)*P = r*P = R */

    ecp_WordsToBytes(md, h);
    edp_DualPointMultiply(&T, signature+32, md, &Q);
    ed25519_PackPoint(md, T.y, T.x[0]);

    return (memcmp(md, signature, 32) == 0);
}

int ed25519_selftest()
{
    int rc = 0;
    U8 pp[32], m1[32], m2[32];
    U_WORD u[K_WORDS], v[K_WORDS];
    Affine_POINT a, b, c, d;

    ed25519_PackPoint(pp, ed25519_BasePoint.y, ed25519_BasePoint.x[0] & 1);
    ed25519_UnpackPoint(&a, pp);
    if (ecp_CmpNE(a.x, ed25519_BasePoint.x))
    {
        rc++;
        printf("-- Unpack error.");
        ecp_PrintHexWords("a_x", a.x, K_WORDS);
    }

    /* a = 7*B */
    ecp_SetValue(u, 7);
    edp_BasePointMultiply(&a, u, 0);

    /* b = 11*B */
    ecp_SetValue(u, 11);
    edp_BasePointMultiply(&b, u, 0);

    /* c = 50*B + 7*b = 127*B */
    edp_DualPointMultiply(&c, m_50, m_7, &b);

    /* d = 127*B */
    ecp_SetValue(u, 127);
    edp_BasePointMultiply(&d, u, 0);

    /* check c == d */
    if (ecp_CmpNE(c.y, d.y) || ecp_CmpNE(c.x, d.x))
    {
        rc++;
        printf("-- edp_DualPointMultiply(1) FAILED!!");
        ecp_PrintHexWords("c_x", c.x, K_WORDS);
        ecp_PrintHexWords("c_y", c.y, K_WORDS);
        ecp_PrintHexWords("d_x", d.x, K_WORDS);
        ecp_PrintHexWords("d_y", d.y, K_WORDS);
    }

    /* c = 11*b + 6*B = 127*B */
    edp_DualPointMultiply(&c, m_6, m_11, &b);
    /* check c == d */
    if (ecp_CmpNE(c.y, d.y) || ecp_CmpNE(c.x, d.x))
    {
        rc++;
        printf("-- edp_DualPointMultiply(2) FAILED!!");
        ecp_PrintHexWords("c_x", c.x, K_WORDS);
        ecp_PrintHexWords("c_y", c.y, K_WORDS);
        ecp_PrintHexWords("d_x", d.x, K_WORDS);
        ecp_PrintHexWords("d_y", d.y, K_WORDS);
    }

    ecp_SetValue(u, 0x11223344);
    edp_BasePointMultiply(&a, u, 0);   /* a = u*B */
    eco_MulMod(v, u, u);
    ecp_Sub(v, _w_BPO, v);          /* v = -u^2 */
    ecp_WordsToBytes(m1, u);
    ecp_WordsToBytes(m2, v);
    edp_DualPointMultiply(&a, m2, m1, &a);  /* v*B + u*A = (-u^2 + u*u)*B */
    /* assert a == infinty */
    if (ecp_CmpNE(a.x, _w_Zero) || ecp_CmpNE(a.y, _w_One))
    {
        rc++;
        printf("-- edp_DualPointMultiply(3) FAILED!!");
        ecp_PrintHexWords("a_x", a.x, K_WORDS);
        ecp_PrintHexWords("a_y", a.y, K_WORDS);
    }

    return rc;
}

#endif /* ECP_SELF_TEST */