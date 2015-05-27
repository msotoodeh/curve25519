
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
#include "ed25519_signature.h"
#include "sha512.h"

/*
 * Arithmetic on twisted Edwards curve y^2 - x^2 = 1 + dx^2y^2
 * with d = -(121665/121666) mod p
 *      d = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
 *      p = 2**255 - 19
 *      p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
 * Base point: y=4/5 mod p
 *      x = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
 *      y = 0x6666666666666666666666666666666666666666666666666666666666666658
 * Base point order:
 *      l = 2**252 + 27742317777372353535851937790883648493
 *      l = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
 */

extern const U_WORD _w_P[K_WORDS];
extern const U_WORD _w_maxP[K_WORDS];
extern const U_WORD _w_I[K_WORDS];
extern const U_WORD _w_BPO[K_WORDS];
extern const U_WORD _w_2d[K_WORDS];

extern const Pre_POINT pre_BaseMultiples[16];

#define _w_Zero     pre_BaseMultiples[0].T2d
#define _w_One      pre_BaseMultiples[0].YpX
#define _w_Two      pre_BaseMultiples[0].Z2

static const U_WORD _w_d[K_WORDS] =
    W256(0x135978A3,0x75EB4DCA,0x4141D8AB,0x00700A4D,0x7779E898,0x8CC74079,0x2B6FFE73,0x52036CEE);

void ed25519_CalculateX(OUT U_WORD *X, IN const U_WORD *Y, U_WORD parity)
{
    U_WORD u[K_WORDS], v[K_WORDS], a[K_WORDS], b[K_WORDS];

    // Calculate sqrt((y^2 - 1)/(d*y^2 + 1))

    ecp_SqrReduce(u, Y);            // u = y^2
    ecp_MulReduce(v, u, _w_d);      // v = dy^2
    ecp_SubReduce(u, u, _w_One);    // u = y^2-1
    ecp_AddReduce(v, v, _w_One);    // v = dy^2+1

    // Calculate:  sqrt(u/v) = u*v^3 * (u*v^7)^((p-5)/8)

    ecp_SqrReduce(b, v);
    ecp_MulReduce(a, u, b);
    ecp_MulReduce(a, a, v);         // a = u*v^3
    ecp_SqrReduce(b, b);            // b = v^4
    ecp_MulReduce(b, a, b);         // b = u*v^7
    ecp_ModExp2523(b, b);
    ecp_MulReduce(X, b, a);

    // Check if we have correct sqrt, else, multiply by sqrt(-1)

    ecp_SqrReduce(b, X);
    ecp_MulReduce(b, b, v);
    ecp_SubReduce(b, b, u);
    while (ecp_Cmp(b, _w_P) >= 0) ecp_Sub(b, b, _w_P);
    if (ecp_Cmp(b, _w_Zero) != 0) ecp_MulReduce(X, X, _w_I);

    while (ecp_Cmp(X, _w_P) >= 0) ecp_Sub(X, X, _w_P);

    // match parity
    if (((X[0] ^ parity) & 1) != 0)
        ecp_Sub(X, _w_P, X);
}


void ed25519_UnpackPoint(Affine_POINT *r, const unsigned char *p)
{
    U8 parity = ecp_DecodeInt(r->y, p);
    ed25519_CalculateX(r->x, r->y, parity);
}

void ecp_SrqMulReduce(U_WORD *Z, const U_WORD *X, int n, const U_WORD *Y)
{
    U_WORD t[K_WORDS];
    ecp_SqrReduce(t, X);
    while (n-- > 1) ecp_SqrReduce(t, t);
    ecp_MulReduce(Z, t, Y);
}

void ecp_ModExp2523(U_WORD *Y, const U_WORD *X)
{
    U_WORD x2[K_WORDS], x9[K_WORDS], x11[K_WORDS], x5[K_WORDS], x10[K_WORDS];
    U_WORD x20[K_WORDS], x50[K_WORDS], x100[K_WORDS], t[K_WORDS];

    ecp_SqrReduce(x2, X);                       // 2
    ecp_SrqMulReduce(x9, x2, 2, X);             // 9
    ecp_MulReduce(x11, x9, x2);                 // 11
    ecp_SqrReduce(t, x11);                      // 22
    ecp_MulReduce(x5, t, x9);                   // 31 = 2^5 - 2^0
    ecp_SrqMulReduce(x10, x5, 5, x5);           // 2^10 - 2^0
    ecp_SrqMulReduce(x20, x10, 10, x10);        // 2^20 - 2^0
    ecp_SrqMulReduce(t, x20, 20, x20);          // 2^40 - 2^0
    ecp_SrqMulReduce(x50, t, 10, x10);          // 2^50 - 2^0
    ecp_SrqMulReduce(x100, x50, 50, x50);       // 2^100 - 2^0
    ecp_SrqMulReduce(t, x100, 100, x100);       // 2^200 - 2^0
    ecp_SrqMulReduce(t, t, 50, x50);            // 2^250 - 2^0
    ecp_SqrReduce(t, t); ecp_SqrReduce(t, t);   // 2^252 - 2^2
    ecp_MulReduce(Y, t, X);                     // 2^252 - 3
}

/*
    Assumptions: pre-computed q
    Cost: 8M + 6add
    Return: P = P + Q
*/
static void ed25519_AddPoint(Ext_POINT *p, const Pre_POINT *q)
{
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];

    ecp_SubReduce(a, p->y, p->x);           /* A = (Y1-X1)*(Y2-X2) */
    ecp_MulReduce(a, a, q->YmX);
    ecp_AddReduce(b, p->y, p->x);           /* B = (Y1+X1)*(Y2+X2) */
    ecp_MulReduce(b, b, q->YpX);
    ecp_MulReduce(c, p->t, q->T2d);         /* C = T1*2d*T2 */
    ecp_MulReduce(d, p->z, q->Z2);          /* D = Z1*2*Z2 */
    ecp_SubReduce(e, b, a);                 /* E = B-A */
    ecp_AddReduce(b, b, a);                 /* H = B+A */
    ecp_SubReduce(a, d, c);                 /* F = D-C */
    ecp_AddReduce(d, d, c);                 /* G = D+C */

    ecp_MulReduce(p->x, e, a);              /* E*F */
    ecp_MulReduce(p->y, b, d);              /* H*G */
    ecp_MulReduce(p->t, e, b);              /* E*H */
    ecp_MulReduce(p->z, d, a);              /* G*F */
}

/*
Calculate: point R = a*P + b*Q  where P is base point
*/
static void ed25519_DualPointMultiply(
    Affine_POINT *r,
    const U8 *a, const U8 *b, const Affine_POINT *q)
{
    int i, j;
    M32 k;
    Ext_POINT S;
    Pre_POINT U, V;

    // U = pre-compute(Q)
    ecp_AddReduce(U.YpX, q->y, q->x);
    ecp_SubReduce(U.YmX, q->y, q->x);
    ecp_MulReduce(U.T2d, q->y, q->x);
    ecp_MulReduce(U.T2d, U.T2d, _w_2d);
    ecp_SetValue(U.Z2, 2);

    // set V = pre-compute(P + Q)
    ecp_Copy(S.x, q->x);
    ecp_Copy(S.y, q->y);
    ecp_SetValue(S.z, 1);
    ecp_MulReduce(S.t, S.x, S.y);
    ed25519_AddBasePoint(&S);   // S = P + Q
    // 
    ecp_AddReduce(V.YpX, S.y, S.x);
    ecp_SubReduce(V.YmX, S.y, S.x);
    ecp_MulReduce(V.T2d, S.t, _w_2d);
    ecp_AddReduce(V.Z2, S.z, S.z);

    // Set S = (0,1)
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
            ed25519_DoublePoint(&S);
            switch (k.u32 & 0x8080)
            {
            case 0x0080: ed25519_AddBasePoint(&S); break;
            case 0x8000: ed25519_AddAffinePoint(&S, &U); break;
            case 0x8080: ed25519_AddPoint(&S, &V); break;
            }
            k.u32 <<= 1;
        }
    }
    ecp_Inverse(S.z, S.z);
    ecp_MulMod(r->x, S.x, S.z);
    ecp_MulMod(r->y, S.y, S.z);
}

int ed25519_VerifySignature(
    const unsigned char *signature,             // IN: signature (R,S)
    const unsigned char *publicKey,             // IN: public key
    const unsigned char *msg, size_t msg_size)  // IN: message to sign
{
    SHA512_CTX H;
    Affine_POINT Q, T;
    U_WORD h[K_WORDS];
    U8 md[SHA512_DIGEST_LENGTH];

    md[0] = ecp_DecodeInt(Q.y, publicKey);
    ed25519_CalculateX(Q.x, Q.y, ~md[0]);       // Invert parity for -Q

    // TODO: Validate Q is a point on the curve

    // h = H(enc(R) + pk + m)  mod BPO
    SHA512_Init(&H);
    SHA512_Update(&H, signature, 32);
    SHA512_Update(&H, publicKey, 32);
    SHA512_Update(&H, msg, msg_size);
    SHA512_Final(md, &H);
    eco_DigestToWords(h, md);
    eco_Mod(h);

    // T = s*P + h*(-Q) = (s - h*a)*P = r*P = R

    ecp_WordsToBytes(md, h);
    ed25519_DualPointMultiply(&T, signature+32, md, &Q);
    ed25519_PackPoint(md, T.y, T.x[0]);

    return (memcmp(md, signature, 32) == 0);
}

#ifdef ECP_SELF_TEST
#include <stdio.h>

static U8 m_6[32] = {6};
static U8 m_7[32] = {7};
static U8 m_11[32] = {11};
static U8 m_50[32] = {50};
static U8 m_127[32] = {127};

// Pre-calculate base point values
static const Affine_POINT ed25519_BasePoint = {   // y = 4/5 mod P
    W256(0x8F25D51A,0xC9562D60,0x9525A7B2,0x692CC760,0xFDD6DC5C,0xC0A4E231,0xCD6E53FE,0x216936D3),
    W256(0x66666658,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666,0x66666666)
};

void ecp_PrintHexWords(IN const char *name, IN const U_WORD *data, IN U32 size);

int ed25519_selftest()
{
    int rc = 0;
    U8 pp[32], m1[32], m2[32];
    U_WORD u[K_WORDS], v[K_WORDS];
    Affine_POINT a, b, c, d;

    ed25519_PackPoint(pp, ed25519_BasePoint.y, ed25519_BasePoint.x[0] & 1);
    ed25519_UnpackPoint(&a, pp);
    if (ecp_Cmp(a.x, ed25519_BasePoint.x) != 0)
    {
        rc++;
        printf("-- Unpack error.");
        ecp_PrintHexWords("a_x", a.x, K_WORDS);
    }

    // a = 7*B
    ed25519_BasePointMultiply(&a, m_7);

    // b = 11*B
    ed25519_BasePointMultiply(&b, m_11);

    // c = 50*B + 7*b = 127*B
    ed25519_DualPointMultiply(&c, m_50, m_7, &b);

    // d = 127*B
    ed25519_BasePointMultiply(&d, m_127);

    // check c == d
    if (ecp_Cmp(c.y, d.y) != 0 || ecp_Cmp(c.x, d.x) != 0)
    {
        rc++;
        printf("-- ecp_DualPointMultiply(1) FAILED!!");
        ecp_PrintHexWords("c_x", c.x, K_WORDS);
        ecp_PrintHexWords("c_y", c.y, K_WORDS);
        ecp_PrintHexWords("d_x", d.x, K_WORDS);
        ecp_PrintHexWords("d_y", d.y, K_WORDS);
    }

    // c = 11*b + 6*B = 127*B
    ed25519_DualPointMultiply(&c, m_6, m_11, &b);
    // check c == d
    if (ecp_Cmp(c.y, d.y) != 0 || ecp_Cmp(c.x, d.x) != 0)
    {
        rc++;
        printf("-- ecp_DualPointMultiply(2) FAILED!!");
        ecp_PrintHexWords("c_x", c.x, K_WORDS);
        ecp_PrintHexWords("c_y", c.y, K_WORDS);
        ecp_PrintHexWords("d_x", d.x, K_WORDS);
        ecp_PrintHexWords("d_y", d.y, K_WORDS);
    }

    ecp_SetValue(u, 0x11223344);
    ecp_WordsToBytes(m1, u);
    ed25519_BasePointMultiply(&a, m1);      // a = u*B
    eco_MulMod(v, u, u);
    ecp_Sub(v, _w_BPO, v);          // v = -u^2
    ecp_WordsToBytes(m2, v);
    ed25519_DualPointMultiply(&a, m2, m1, &a);  // v*B + u*A = (-u^2 + u*u)*B
    // assert a == infinty
    if (ecp_Cmp(a.x, _w_Zero) != 0 || ecp_Cmp(a.y, _w_One) != 0)
    {
        rc++;
        printf("-- ecp_DualPointMultiply(3) FAILED!!");
        ecp_PrintHexWords("a_x", a.x, K_WORDS);
        ecp_PrintHexWords("a_y", a.y, K_WORDS);
    }

    return rc;
}

#endif