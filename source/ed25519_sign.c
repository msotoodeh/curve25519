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

#ifdef PRINT_DETAILS
void ecp_PrintHexBytes(IN const char *name, IN const U8 *data, IN U32 size);
void ecp_PrintHexWords(IN const char *name, IN const U_WORD *data, IN U32 size);

#define PrintHexBytes(name,data,size) ecp_PrintHexBytes(name,data,size)
#define PrintHexWords(name,data,size) ecp_PrintHexWords(name,data,size)
#else
#define PrintHexBytes(name,data,size)
#define PrintHexWords(name,data,size)
#endif

typedef struct
{
    U_WORD X[K_WORDS];   // x = X/Z
    U_WORD Z[K_WORDS];   // 
} XZ_POINT;

void ecp_Mont(XZ_POINT *P, XZ_POINT *Q, IN const U32 *Base);
void ecp_MontDouble(XZ_POINT *Y, const XZ_POINT *X);

#ifdef WORDSIZE_64
static const U_WORD _w_2d[K_WORDS] = {    // 2d mod p
    0xEBD69B9426B2F159,0x00E0149A8283B156,
    0x198E80F2EEF3D130,0x2406D9DC56DFFCE7
};
#else
static const U_WORD _w_2d[K_WORDS] = {   /* 2*d */
    0x26B2F159,0xEBD69B94,0x8283B156,0x00E0149A,
    0xEEF3D130,0x198E80F2,0x56DFFCE7,0x2406D9DC,
};
#endif

extern const U_WORD _w_maxP[K_WORDS];

// Pre-calculate base point values
#ifdef WORDSIZE_64
const Ext_POINT ed25519_BasePoint = {   // y = 4/5 mod P
  { 0xC9562D608F25D51A,0x692CC7609525A7B2,
    0xC0A4E231FDD6DC5C,0x216936D3CD6E53FE },
  { 0x6666666666666658,0x6666666666666666,
    0x6666666666666666,0x6666666666666666 },
  { 1,0,0,0 },
  { 0x6DDE8AB3A5B7DDA3,0x20F09F80775152F5,
    0x66EA4E8E64ABE37D,0x67875F0FD78B7665 }
};
static const U_WORD _w_edbase_YpX[K_WORDS] = {  // Y+X
    0x2FBC93C6F58C3B85,0xCF932DC6FB8C0E19,
    0x270B4898643D42C2,0x07CF9D3A33D4BA65
};

static const U_WORD _w_edbase_YmX[K_WORDS] = {  // Y-X
    0x9D103905D740913E,0xFD399F05D140BEB3,
    0xA5C18434688F8A09,0x44FD2F9298F81267
};

static const U_WORD _w_edbase_2dT[K_WORDS] = {  // 2d*T
    0xABC91205877AAA68,0x26D9E823CCAAC49E,
    0x5A1B7DCBDD43598C,0x6F117B689F0C65A8
};
#else
static const U_WORD _w_edbase_YpX[K_WORDS] = {  // Y+X
    0xF58C3B85,0x2FBC93C6,0xFB8C0E19,0xCF932DC6,
    0x643D42C2,0x270B4898,0x33D4BA65,0x07CF9D3A
};

static const U_WORD _w_edbase_YmX[K_WORDS] = {  // Y-X
    0xD740913E,0x9D103905,0xD140BEB3,0xFD399F05,
    0x688F8A09,0xA5C18434,0x98F81267,0x44FD2F92
};

static const U_WORD _w_edbase_2dT[K_WORDS] = {  // 2d*T
    0x877AAA68,0xABC91205,0xCCAAC49E,0x26D9E823,
    0xDD43598C,0x5A1B7DCB,0x9F0C65A8,0x6F117B68
};

const Ext_POINT ed25519_BasePoint = {   // y = 4/5 mod P
  { 0x8F25D51A,0xC9562D60,0x9525A7B2,0x692CC760,
    0xFDD6DC5C,0xC0A4E231,0xCD6E53FE,0x216936D3 },
  { 0x66666658,0x66666666,0x66666666,0x66666666,
    0x66666666,0x66666666,0x66666666,0x66666666 },
  { 1,0,0,0,0,0,0,0 },
  { 0xA5B7DDA3,0x6DDE8AB3,0x775152F5,0x20F09F80,
    0x64ABE37D,0x66EA4E8E,0xD78B7665,0x67875F0F }
};
#endif

/*
    Reference: http://eprint.iacr.org/2008/522
    Cost: 7M + 7add
    Return: R = P + BasePoint
*/
void ed25519_AddBasePoint(Ext_POINT *r, const Ext_POINT *p)
{
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];

    ecp_SubReduce(a, p->y, p->x);           /* A = (Y1-X1)*(Y2-X2) */
    ecp_MulReduce(a, a, _w_edbase_YmX);
    ecp_AddReduce(b, p->y, p->x);           /* B = (Y1+X1)*(Y2+X2) */
    ecp_MulReduce(b, b, _w_edbase_YpX);
    ecp_MulReduce(c, p->t, _w_edbase_2dT);  /* C = T1*2d*T2 */
    ecp_AddReduce(d, p->z, p->z);           /* D = 2*Z1 */
    ecp_SubReduce(e, b, a);                 /* E = B-A */
    ecp_AddReduce(b, b, a);                 /* H = B+A */
    ecp_SubReduce(a, d, c);                 /* F = D-C */
    ecp_AddReduce(d, d, c);                 /* G = D+C */

    ecp_MulReduce(r->x, e, a);              /* E*F */
    ecp_MulReduce(r->y, b, d);              /* H*G */
    ecp_MulReduce(r->t, e, b);              /* E*H */
    ecp_MulReduce(r->z, d, a);              /* G*F */
}

/*
    Reference: http://eprint.iacr.org/2008/522
    Cost: 4M + 4S + 7add
    Return: P = 2*P
*/
void ed25519_DoublePoint(Ext_POINT *p)
{
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];

    ecp_SqrReduce(a, p->x);         /* A = X1^2 */
    ecp_SqrReduce(b, p->y);         /* B = Y1^2 */
    ecp_SqrReduce(c, p->z);         /* C = 2*Z1^2 */
    ecp_AddReduce(c, c, c);
    ecp_SubReduce(d, _w_maxP, a);   /* D = -A */

    ecp_SubReduce(a, d, b);         /* H = D-B */
    ecp_AddReduce(d, d, b);         /* G = D+B */
    ecp_SubReduce(b, d, c);         /* F = G-C */
    ecp_AddReduce(e, p->x, p->y);   /* E = (X1+Y1)^2-A-B = (X1+Y1)^2+H */
    ecp_SqrReduce(e, e);
    ecp_AddReduce(e, e, a);

    ecp_MulReduce(p->x, e, b);      /* E*F */
    ecp_MulReduce(p->y, a, d);      /* H*G */
    ecp_MulReduce(p->z, d, b);      /* G*F */
    ecp_MulReduce(p->t, e, a);      /* E*H */
}

#ifdef ECP_CONSTANT_TIME
#define ECP_MONT_C(n) ed25519_DoublePoint(&P); ed25519_AddBasePoint(PP[(k>>n)&1], &P)

// --------------------------------------------------------------------------
// Return Q = k*B where B is ed25519 base point
// This is constant time implementation
void ed25519_BasePointMultiply(OUT Affine_POINT *Q, IN const U8 *sk)
{
    int k, len = 32;
    Ext_POINT P, T, *PP[2];

    ecp_SetValue(P.x, 0);
    ecp_SetValue(P.y, 1);
    ecp_SetValue(P.t, 0);
    ecp_SetValue(P.z, 1);

    PP[0] = &T;
    PP[1] = &P;

    do
    {
        k = sk[--len];
        ECP_MONT_C(7);
        ECP_MONT_C(6);
        ECP_MONT_C(5);
        ECP_MONT_C(4);
        ECP_MONT_C(3);
        ECP_MONT_C(2);
        ECP_MONT_C(1);
        ECP_MONT_C(0);
    } while (len > 0);

    ecp_Inverse(P.z, P.z);
    ecp_MulMod(Q->x, P.x, P.z);
    ecp_MulMod(Q->y, P.y, P.z);
}
#else
#define ECP_MONT_B(n) ed25519_DoublePoint(&P); if (k&n) ed25519_AddBasePoint(&P, &P)

// --------------------------------------------------------------------------
// Return Q = k*B where B is ed25519 base point
void ed25519_BasePointMultiply(OUT Affine_POINT *Q, IN const U8 *sk)
{
    int i, k, len = 32;

    // Find first non-zero bit
    do
    {
        k = sk[--len];
        for (i = 0; i < 8; i++, k <<= 1)
        {
            if (k & 0x80)
            {
                // We have first non-zero bit
                Ext_POINT P = ed25519_BasePoint;
                while (++i < 8) { k <<= 1; ECP_MONT_B(0x80); }

                while (len > 0)
                {
                    k = sk[--len];
                    ECP_MONT_B(0x80);
                    ECP_MONT_B(0x40);
                    ECP_MONT_B(0x20);
                    ECP_MONT_B(0x10);
                    ECP_MONT_B(0x08);
                    ECP_MONT_B(0x04);
                    ECP_MONT_B(0x02);
                    ECP_MONT_B(0x01);
                }

                ecp_Inverse(P.z, P.z);
                ecp_MulMod(Q->x, P.x, P.z);
                ecp_MulMod(Q->y, P.y, P.z);
                return;
            }
        }
    } while (len > 0);

    // K is 0 ==> (0, 1)
    ecp_SetValue(Q->x, 0);
    ecp_SetValue(Q->y, 1);
}
#endif

// Generate public and private key pair associated with the secret key
void ed25519_CreateKeyPair(
    unsigned char *pubKey,              // OUT: public key
    unsigned char *privKey,             // OUT: private key
    const unsigned char *sk)            // IN: secret key (32 bytes)
{
    U8 md[SHA512_DIGEST_LENGTH];
    SHA512_CTX H;
    Affine_POINT Q;

    // [a:b] = H(sk)
    SHA512_Init(&H);
    SHA512_Update(&H, sk, 32);
    SHA512_Final(md, &H);
    // 
    ecp_TrimSecretKey(md);

    PrintHexBytes("sk", sk, 32);
    PrintHexBytes("a", md, 32);
    PrintHexBytes("b", md+32, 32);
    ed25519_BasePointMultiply(&Q, md);
    ed25519_PackPoint(pubKey, Q.y, Q.x[0]);

    memcpy(privKey, sk, 32);
    memcpy(privKey+32, pubKey, 32);

    PrintHexWords("Q.x", Q.x, K_WORDS);
    PrintHexWords("Q.y", Q.y, K_WORDS);
    PrintHexBytes("pk", pubKey, 32);
    PrintHexBytes("priv", privKey, 64);
}

// Generate message signature
void ed25519_SignMessage(
    unsigned char *signature,           // OUT: [64 bytes] signature (R,S)
    const unsigned char *privKey,       //  IN: [64 bytes] private key (sk,pk)
    const unsigned char *msg,           //  IN: [msg_size bytes] message to sign
    size_t msg_size)
{
    SHA512_CTX H;
    Affine_POINT R;
    U_WORD a[K_WORDS], t[K_WORDS], r[K_WORDS];
    U8 md[SHA512_DIGEST_LENGTH];

    // [a:b] = H(sk)
    SHA512_Init(&H);
    SHA512_Update(&H, privKey, 32);
    SHA512_Final(md, &H);
    ecp_TrimSecretKey(md);              // a = first 32 bytes
    ecp_BytesToWords(a, md);

    PrintHexWords("a", a, K_WORDS);

    // r = H(b + m) mod BPO
    SHA512_Init(&H);
    SHA512_Update(&H, md+32, 32);
    SHA512_Update(&H, msg, msg_size);
    SHA512_Final(md, &H);
    eco_DigestToWords(r, md);
    eco_Mod(r);                         // r mod BPO
    PrintHexWords("r", r, K_WORDS);

    // R = r*P
    ecp_WordsToBytes(md, r);
    ed25519_BasePointMultiply(&R, md);
    PrintHexWords("R.x", R.x, K_WORDS);
    PrintHexWords("R.y", R.y, K_WORDS);

    ed25519_PackPoint(signature, R.y, R.x[0]); // R part of signature
    PrintHexBytes("sig.R", signature, 32);

    // S = r + H(encoded(R) + pk + m) * a  mod BPO
    SHA512_Init(&H);
    SHA512_Update(&H, signature, 32);   // encoded(R)
    SHA512_Update(&H, privKey+32, 32);  // pk
    SHA512_Update(&H, msg, msg_size);   // m
    SHA512_Final(md, &H);
    PrintHexBytes("md(R+pk+m)", md, 64);
    eco_DigestToWords(t, md);
    PrintHexWords("h(R+pk+m)", t, K_WORDS);

    eco_MulReduce(t, t, a);             // h()*a
    eco_AddMod(t, t, r);
    PrintHexWords("r", r, K_WORDS);
    ecp_WordsToBytes(signature+32, t);  // S part of signature
    PrintHexBytes("sig.S", signature+32, 32);

    // Clear sensitive data
    ecp_SetValue(a, 0);
    ecp_SetValue(r, 0);
}

