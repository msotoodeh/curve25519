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

 #include "curve25519_mehdi.h"

/*
  This library provides support for mod BPO (Base Point Order) operations

    BPO = 2**252 + 27742317777372353535851937790883648493
    BPO = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

  If you keep adding points together, the result repeats every BPO times.
  Based on this, you may use:

        public_key = (private_key mod BPO)*BasePoint

  This library is used for implementation of ECDSA sign/verify.
*/

const U64 _w_BPO[4] = { /* BPO as words */
    0x5812631A5CF5D3ED,0x14DEF9DEA2F79CD6,0x0000000000000000,0x1000000000000000 };

static const U64 _w_maxBPO[4] = { /* 15*BPO fits into 8 words */
    0x2913CE8B72676AE3,0x3910A40B8C82308F,0x0000000000000001,0xF000000000000000 };

static const U8 _b_BPOm2[32] = {      /* BasePointOrder - 2 */
    0xEB,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

/* R = 2**256 mod BPO */
/* R = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC6EF5BF4737DCF70D6EC31748D98951D */
 static const U64 _w_R[4] = {   /* R mod BPO */
    0xD6EC31748D98951D,0xC6EF5BF4737DCF70,0xFFFFFFFFFFFFFFFE,0x0FFFFFFFFFFFFFFF };

/* R2 = R**2 mod BPO */
/* R2 = 0x0399411B7C309A3DCEEC73D217F5BE65D00E1BA768859347A40611E3449C0F01 */
static const U64 _w_R2[4] = {   /* R**2 mod BPO */
    0xA40611E3449C0F01,0xD00E1BA768859347,0xCEEC73D217F5BE65,0x0399411B7C309A3D };

static const U64 _w_One[4] = { 1,0,0,0 };

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
    /* T[9] could be 2 at most */
    while (T[5] != 0) T[5] += ecp_Sub(T+1, T+1, _w_maxBPO);
    ecp_Copy(Z, T+1);   /* return T>>64 */
}

/* Return Y = X*R mod BPO */
void eco_ToMont(OUT U64 *Y, IN const U64 *X)
{
    eco_MontMul(Y, X, _w_R2);
}

/* Return Y = X/R mod BPO */
void eco_FromMont(OUT U64 *Y, IN const U64 *X)
{
    eco_MontMul(Y, X, _w_One);
    while(ecp_Cmp(Y, _w_BPO) >= 0) ecp_Sub(Y, Y, _w_BPO);
}

#define ECO_MONT(n) eco_MontMul(V,V,V); if(e & n) eco_MontMul(V,V,U)

/* Calculate Y = X**E mod BPO */
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

/* Calculate Y = 1/X mod BPO */
void eco_InvModBPO(OUT U64 *Y, IN const U64 *X)
{
    eco_ExpModBPO(Y, X, _b_BPOm2, 32);
}

/* Z = X*Y mod BPO */
void eco_MulReduce(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 T[8];
    ecp_Mul(T, X, Y);               /* [T2:T1] = X*Y */
    eco_MontMul(T+4, T+4, _w_R2);   /* T2*(R*R)/R == T2*R mod BPO */
    eco_AddReduce(Z, T+4, T);       /* Z = T2*R + T1 = X*Y mod BPO */
}

/* Z = X*Y mod BPO */
void eco_MulMod(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 T[8];
    ecp_Mul(T, X, Y);               /* [T2:T1] = X*Y */
    eco_MontMul(T+4, T+4, _w_R2);   /* T2*(R*R)/R == T2*R mod BPO */
    eco_AddMod(Z, T+4, T);          /* Z = T2*R + T1 = X*Y mod BPO */
}

/* X mod BPO */
void eco_Mod(U64 *X)
{
    while(ecp_Cmp(X, _w_BPO) >= 0) ecp_Sub(X, X, _w_BPO);
}

/* Z = X + Y mod BPO */
void eco_AddReduce(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 c = ecp_Add(Z, X, Y);
    while(c != 0) c += ecp_Sub(Z, Z, _w_maxBPO);
}

/* Z = X + Y mod BPO */
void eco_AddMod(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 c = ecp_Add(Z, X, Y);
    while(c != 0) c += ecp_Sub(Z, Z, _w_maxBPO);
    while(ecp_Cmp(Z, _w_BPO) >= 0) ecp_Sub(Z, Z, _w_BPO);
}

/* Return Y = D mod BPO where D is 512-bit message digest (i.e SHA512 digest) */
void eco_DigestToWords( OUT U64 *Y, IN const U8 *md)
{
    U64 H[4], L[4];

    /* We use digest value as little-endian byte array. */
    ecp_BytesToWords(L, md);
    ecp_BytesToWords(H, md+32);

    /* Value of digest is equal to H*2^256 + L = H*R + L = mont(H,R**2) + L mod BPO */
    /* This is way simpler and faster than Barrett reduction */
    eco_MontMul(H, H, _w_R2);       /* H*(R*R)/R = H*R */
    eco_AddReduce(Y, H, L);         /* Y = H*R + L  */
}
