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

const U_WORD _w_NxBPO[16][K_WORDS] = {  /* n*BPO */
    W256(0,0,0,0,0,0,0,0),
    W256(0x5CF5D3ED,0x5812631A,0xA2F79CD6,0x14DEF9DE,0,0,0,0x10000000),
    W256(0xB9EBA7DA,0xB024C634,0x45EF39AC,0x29BDF3BD,0,0,0,0x20000000),
    W256(0x16E17BC7,0x0837294F,0xE8E6D683,0x3E9CED9B,0,0,0,0x30000000),
    W256(0x73D74FB4,0x60498C69,0x8BDE7359,0x537BE77A,0,0,0,0x40000000),
    W256(0xD0CD23A1,0xB85BEF83,0x2ED6102F,0x685AE159,0,0,0,0x50000000),
    W256(0x2DC2F78E,0x106E529E,0xD1CDAD06,0x7D39DB37,0,0,0,0x60000000),
    W256(0x8AB8CB7B,0x6880B5B8,0x74C549DC,0x9218D516,0,0,0,0x70000000),
    W256(0xE7AE9F68,0xC09318D2,0x17BCE6B2,0xA6F7CEF5,0,0,0,0x80000000),
    W256(0x44A47355,0x18A57BED,0xBAB48389,0xBBD6C8D3,0,0,0,0x90000000),
    W256(0xA19A4742,0x70B7DF07,0x5DAC205F,0xD0B5C2B2,0,0,0,0xA0000000),
    W256(0xFE901B2F,0xC8CA4221,0x00A3BD35,0xE594BC91,0,0,0,0xB0000000),
    W256(0x5B85EF1C,0x20DCA53C,0xA39B5A0C,0xFA73B66F,0,0,0,0xC0000000),
    W256(0xB87BC309,0x78EF0856,0x4692F6E2,0x0F52B04E,1,0,0,0xD0000000),
    W256(0x157196F6,0xD1016B71,0xE98A93B8,0x2431AA2C,1,0,0,0xE0000000),
    W256(0x72676AE3,0x2913CE8B,0x8C82308F,0x3910A40B,1,0,0,0xF0000000)
};

/* Z = X + Y mod BPO */
void eco_AddReduce(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 c = ecp_Add(Z, X, Y);
    eco_ReduceHiWord(Z, c, Z);
}

/* Z = X*Y mod BPO */
void eco_MulReduce(OUT U64 *Z, IN const U64 *X, IN const U64 *Y)
{
    U64 T[8];
    ecp_Mul(T, X, Y);                 /* T = X*Y */
    eco_ReduceHiWord(T+3, T[7], T+3);
    eco_ReduceHiWord(T+2, T[6], T+2);
    eco_ReduceHiWord(T+1, T[5], T+1);
    eco_ReduceHiWord(Z, T[4], T+0);
}

/* X mod BPO */
void eco_Mod(U64 *X)
{
    S64 c = ecp_Sub(X, X, _w_NxBPO[X[3] >> 60]);
    ecp_Add(X, X, _w_NxBPO[-c]);
}

/* Return Y = D mod BPO where D is 512-bit message digest (i.e SHA512 digest) */
void eco_DigestToWords( OUT U64 *Y, IN const U8 *md)
{
    U64 T[8];

    /* We use digest value as little-endian byte array. */
    ecp_BytesToWords(T, md);
    ecp_BytesToWords(T+4, md+32);

    /* Reduce T mod BPO */
    eco_ReduceHiWord(T+3, T[7], T+3);
    eco_ReduceHiWord(T+2, T[6], T+2);
    eco_ReduceHiWord(T+1, T[5], T+1);
    eco_ReduceHiWord(Y, T[4], T+0);
}
