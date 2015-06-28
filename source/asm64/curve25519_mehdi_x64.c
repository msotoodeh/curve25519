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

const U_WORD _w_P[K_WORDS] = 
    W256(0xFFFFFFED,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x7FFFFFFF);

/* Maximum number of prime p that fits into 256-bits */
const U_WORD _w_maxP[K_WORDS] = /* 2*P < 2**256 */
    W256(0xFFFFFFDA,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF);

void ecp_SetValue(U64* X, U64 value)
{
    X[0] = value;
    X[1] = X[2] = X[3] = 0;
}

/* Y = X */
void ecp_Copy(U64* Y, const U64* X)
{
    memcpy(Y, X, 4*sizeof(U64));
}

/* Computes Z = X*Y mod P. */
void ecp_MulMod(U64* Z, const U64* X, const U64* Y) 
{
    ecp_MulReduce(Z, X, Y);
    ecp_Mod(Z);
}

/* Courtesy of DJB */
/* Return out = 1/z mod P */
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

