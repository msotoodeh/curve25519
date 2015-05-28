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

extern const U_WORD _w_maxP[K_WORDS];

const U_WORD _w_2d[K_WORDS] = /* 2*d */
    W256(0x26B2F159,0xEBD69B94,0x8283B156,0x00E0149A,0xEEF3D130,0x198E80F2,0x56DFFCE7,0x2406D9DC);

const PA_POINT pre_BaseMultiples[16] = 
{
  { // 0*P
    W256(0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000),
    W256(0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000),
    W256(0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000)
  },
  { // 1*P
    W256(0xF58C3B85,0x2FBC93C6,0xFB8C0E19,0xCF932DC6,0x643D42C2,0x270B4898,0x33D4BA65,0x07CF9D3A),
    W256(0xD740913E,0x9D103905,0xD140BEB3,0xFD399F05,0x688F8A09,0xA5C18434,0x98F81267,0x44FD2F92),
    W256(0x877AAA68,0xABC91205,0xCCAAC49E,0x26D9E823,0xDD43598C,0x5A1B7DCB,0x9F0C65A8,0x6F117B68)
  },
  { // 2*P
    W256(0x933C71D7,0x9224E7FC,0x7A0FF5B5,0x9F469D96,0xE1D60702,0x5AA69A65,0xA87D2E2E,0x590C063F),
    W256(0x42B4D5A8,0x8A99A560,0x4E60ACF6,0x8F2B810C,0xB16E37AA,0xE09E236B,0x69C92555,0x6BB595A6),
    W256(0xA59B7A5F,0x43FAA8B3,0x5D9ACF78,0x36C16BDD,0x0B3D6A31,0x500FA084,0x3EA50B73,0x701AF5B1)
  },
  { // 3*P
    W256(0x4CEE9730,0xAF25B0A8,0xE8864B8A,0x025A8430,0x9F016732,0xC11B5002,0x9A80F8F4,0x7A164E1B),
    W256(0xA4FCD265,0x56611FE8,0xE5C1BA7D,0x3BD353FD,0x214BD6BD,0x8131F31A,0x555BDA62,0x2AB91587),
    W256(0x0DD0D889,0x14AE933F,0x1C35DA62,0x58942322,0x8CF2DB4C,0xD170E545,0x12B9B4C6,0x5A2826AF)
  },
  { // 4*P
    W256(0x8EFC099F,0x287351B9,0x7DFD2538,0x6765C6F4,0xFB0A9265,0xCA348D3D,0x21E58727,0x680E9103),
    W256(0x056818BF,0x95FE050A,0x5660FAA9,0x327E8971,0x06A05073,0xC3E8E3CD,0x7445A49A,0x27933F4C),
    W256(0xC476FF09,0x5A13FBE9,0x7B5CC172,0x6E9E3945,0x102B4494,0x5DDBDCF9,0x63553E2B,0x7F9D0CBF)
  },
  { // 5*P
    W256(0x08A5BB33,0xA212BC44,0xC75EED02,0x8D5048C3,0x5ABFEC44,0xDD1BEB0C,0x46E206EB,0x2945CCF1),
    W256(0xA447D6BA,0x7F9182C3,0x4B2729B7,0xD50014D1,0xB864A087,0xE33CF11C,0xEB1B55F3,0x154A7E73),
    W256(0x812A8285,0xBCBBDBF1,0xD0BDD1FC,0x270E0807,0x1BBDA72D,0xB41B670B,0x6B3BB69A,0x43AABE69)
  },
  { // 6*P
    W256(0x77157131,0x3A0CEEEB,0x00C8AF88,0x9B271589,0xDA59A736,0x8065B668,0xA2CC38BD,0x51E57BB6),
    W256(0x7B7D8CA4,0x499806B6,0x27D22739,0x575BE284,0x204553B9,0xBB085CE7,0xAE417884,0x38B64C41),
    W256(0x02EA4B71,0x85AC3267,0x41A1BB01,0xBE70E003,0x083BC144,0x53E4A24B,0x9F0D61E3,0x10B8E91A)
  },
  { // 7*P
    W256(0x944EA3BF,0x6B1A5CD0,0xB39DC0D2,0x7470353A,0x28542E49,0x71B25282,0x283C927E,0x461BEA69),
    W256(0xAA3221B1,0xBA6F2C9A,0x3BBA23A7,0x6CA02153,0x92192C3A,0x9DEA764F,0x2E5317E0,0x1D6EDD5D),
    W256(0x01B8B3A2,0xF1836DC8,0x053EA49A,0xB3035F47,0x5877ADF3,0x529C41BA,0x6A0F90A7,0x7A9FBB1C)
  },
  { // 8*P
    W256(0x04DD3E8F,0x59B75966,0xE288702C,0x6CB30377,0x5ED9C323,0xB1339C66,0x61BCE52F,0x0915E760),
    W256(0xF39234D9,0xE2A75DED,0xE1B558F9,0x963D7680,0x6E3C23FB,0x2C2741AC,0x320E01C3,0x3A9024A1),
    W256(0xC9A2911A,0xE7C1F5D9,0x8BCCA7D7,0xB8A37178,0x0EB62A32,0x63641219,0x2ECC4E95,0x26907C5C)
  },
  { // 9*P
    W256(0xA6A8632F,0x9B2E678A,0x51BC46C5,0xA6509E6F,0xC686F5B5,0xCEB233C9,0x8ADD7F59,0x34B9ED33),
    W256(0x039D8064,0xF36E217E,0xF520419B,0x98A081B6,0xE75EB044,0x96CBC608,0xFADC9C8F,0x49C05A51),
    W256(0x9045AF1B,0x06B4E8BF,0xA719D22F,0xE2FF83E8,0x93D4CF16,0xAAF6FC29,0x1B008B06,0x73C17202)
  },
  { // 10*P
    W256(0xB360748E,0xFF1D93D2,0x1617E057,0x45F534D4,0x9B554646,0x0D550363,0xAAE591ED,0x43AC7628),
    W256(0x227081DD,0x75F3558E,0x65A9F02F,0x04F81836,0xF5DC3958,0x84739745,0x4950B702,0x0353832C),
    W256(0x03D0F8D8,0xD03D2AE4,0xD3F06340,0x1D0C1CCB,0x6731B509,0xFF169F0F,0x70BF4CE7,0x0EC62AF4)
  },
  { // 11*P
    W256(0x8A802ADE,0x2FBF0084,0x02302E27,0xE5D9FECF,0x17703406,0x113E8471,0x546D8FAF,0x4275AAE2),
    W256(0x49864348,0x315F5B02,0x77088381,0x3ED6B369,0x6A8DEB95,0xA3A07555,0x29D5C77F,0x18AB5980),
    W256(0xFD6089E9,0xD82B2CC5,0x3282E4A4,0x031EB4A1,0xB51A8622,0x44311199,0xB53DF948,0x3DC65522)
  },
  { // 12*P
    W256(0xA71E7539,0xE2358042,0xD834D1A9,0x88DE3DD7,0x701A6F93,0x45ECDD2E,0x8D3CDD58,0x078AAFDE),
    W256(0xB53D54B9,0x856F8375,0xCCB25B24,0x23B2BF90,0x56D5DBDD,0x884DFB6E,0x8A6022ED,0x7956ECE2),
    W256(0x7F944553,0xEEA594D8,0xA24E180B,0xF66CDA23,0xF4976461,0xFFCB589A,0x1C83D0C6,0x37C6A515)
  },
  { // 13*P
    W256(0xA2007F6D,0xBF70C222,0xB5BCDEDB,0xBF84B39A,0xFB07BA07,0x537A0E12,0xC346F241,0x234FD7EE),
    W256(0x327FBF93,0x506F013B,0x9B776F6B,0xAEFCEBC9,0xAAAD5968,0x9D12B232,0x176024A7,0x0267882D),
    W256(0x732EA378,0x5360A119,0xDF8DD471,0x2437E6B1,0x91A7E533,0xA2EF37F8,0xAA097863,0x497BA6FD)
  },
  { // 14*P
    W256(0x3F213DF2,0x26F870EC,0x57EFA987,0x80277FC0,0x2881BDD5,0x1A474C04,0x464D1630,0x6EAF60B2),
    W256(0xD4171280,0xDFDB8A44,0xDB7CA331,0xCE69B20F,0x6EEC47A9,0x112E56F1,0x5B3C80D2,0x2DF0EA2C),
    W256(0x7A1E1B82,0x96A1C587,0xA2A9BF54,0xF02397ED,0x3ECB1BAA,0x9C1FDF70,0xD8BA9C93,0x24BF7E3C)
  },
  { // 15*P
    W256(0x13CFEAA0,0x24CECC03,0x189C246D,0x8648C28D,0xC1F2D4D0,0x2DBDBDFA,0xF12DE72B,0x61E22917),
    W256(0x468CCF0B,0x040BCD86,0x2A9910D6,0xD3829BA4,0x07B25192,0x75083008,0x18D05EBF,0x43B5CD42),
    W256(0x9BD0B516,0x5D9A762F,0x373FDEEE,0xEB38AF4E,0x93D64270,0x032E5A7D,0x0AE4D842,0x511D6121)
  }
};

/*
    Reference: http://eprint.iacr.org/2008/522
    Cost: 7M + 7add
    Return: R = P + BasePoint
*/
void ed25519_AddBasePoint(Ext_POINT *p)
{
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];

    ecp_SubReduce(a, p->y, p->x);           /* A = (Y1-X1)*(Y2-X2) */
    ecp_MulReduce(a, a, pre_BaseMultiples[1].YmX);
    ecp_AddReduce(b, p->y, p->x);           /* B = (Y1+X1)*(Y2+X2) */
    ecp_MulReduce(b, b, pre_BaseMultiples[1].YpX);
    ecp_MulReduce(c, p->t, pre_BaseMultiples[1].T2d); /* C = T1*2d*T2 */
    ecp_AddReduce(d, p->z, p->z);           /* D = 2*Z1 */
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
    Assumptions: pre-computed q, q->Z=1
    Cost: 7M + 7add
    Return: P = P + Q
*/
void ed25519_AddAffinePoint(Ext_POINT *p, const PA_POINT *q)
{
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];
    ecp_SubReduce(a, p->y, p->x);           /* A = (Y1-X1)*(Y2-X2) */
    ecp_MulReduce(a, a, q->YmX);
    ecp_AddReduce(b, p->y, p->x);           /* B = (Y1+X1)*(Y2+X2) */
    ecp_MulReduce(b, b, q->YpX);
    ecp_MulReduce(c, p->t, q->T2d);         /* C = T1*2d*T2 */
    ecp_AddReduce(d, p->z, p->z);           /* D = Z1*2*Z2 (Z2=1)*/
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

static const U_WORD _w_di[] =   // 1/d mod P
    W256(0xCDC9F843,0x25E0F276,0x4279542E,0x0B5DD698,0xCDB9CF66,0x2B162114,0x14D5CE43,0x40907ED2);

// Constant-time
#define ECP_DBLADD_C(x) ed25519_DoublePoint(&P); ed25519_DoublePoint(&P); \
    ed25519_DoublePoint(&P); ed25519_DoublePoint(&P); \
    ed25519_AddAffinePoint(&P,&pre_BaseMultiples[x])

// --------------------------------------------------------------------------
// Return Q = k*B where B is ed25519 base point
// This is constant time implementation
void ed25519_BasePointMultiply(OUT Affine_POINT *Q, IN const U_WORD *sk)
{
    int len = K_WORDS;
    Ext_POINT P;
    const PA_POINT *p0;
#ifdef WORDSIZE_64
    M64 k;
    k.u64 = sk[--len];
    p0 = &pre_BaseMultiples[k.u8.b7>>4];
#else
    M32 k;
    k.u32 = sk[--len];
    p0 = &pre_BaseMultiples[k.u8.b3>>4];
#endif
    // Convert p0 to extended coordinate
    ecp_SubReduce(P.x, p0->YpX, p0->YmX);   // (y+x)-(y-x) = 2x
    ecp_AddReduce(P.y, p0->YpX, p0->YmX);   // (y+x)+(y-x) = 2y
    ecp_MulReduce(P.t, p0->T2d, _w_di);     // 2dT/d = 2t
    ecp_SetValue(P.z, 2);
    goto next_nibble;

    do
    {
#ifdef WORDSIZE_64
        k.u64 = sk[--len];
        ECP_DBLADD_C(k.u8.b7>>4); 
        next_nibble:
        ECP_DBLADD_C(k.u8.b7&15);
        ECP_DBLADD_C(k.u8.b6>>4); 
        ECP_DBLADD_C(k.u8.b6&15);
        ECP_DBLADD_C(k.u8.b5>>4); 
        ECP_DBLADD_C(k.u8.b5&15);
        ECP_DBLADD_C(k.u8.b4>>4); 
        ECP_DBLADD_C(k.u8.b4&15);
        ECP_DBLADD_C(k.u8.b3>>4); 
#else
        k.u32 = sk[--len];
        ECP_DBLADD_C(k.u8.b3>>4); 
        next_nibble:
#endif
        ECP_DBLADD_C(k.u8.b3&15);
        ECP_DBLADD_C(k.u8.b2>>4); 
        ECP_DBLADD_C(k.u8.b2&15);
        ECP_DBLADD_C(k.u8.b1>>4); 
        ECP_DBLADD_C(k.u8.b1&15);
        ECP_DBLADD_C(k.u8.b0>>4); 
        ECP_DBLADD_C(k.u8.b0&15);

    } while (len > 0);

    ecp_Inverse(P.z, P.z);
    ecp_MulMod(Q->x, P.x, P.z);
    ecp_MulMod(Q->y, P.y, P.z);
}

// Generate public and private key pair associated with the secret key
void ed25519_CreateKeyPair(
    unsigned char *pubKey,              // OUT: public key
    unsigned char *privKey,             // OUT: private key
    const unsigned char *sk)            // IN: secret key (32 bytes)
{
    U8 md[SHA512_DIGEST_LENGTH];
    SHA512_CTX H;
    U_WORD a[K_WORDS];
    Affine_POINT Q;

    // [a:b] = H(sk)
    SHA512_Init(&H);
    SHA512_Update(&H, sk, 32);
    SHA512_Final(md, &H);
    // 
    ecp_TrimSecretKey(md);

    ecp_BytesToWords(a, md);
    ed25519_BasePointMultiply(&Q, a);
    ed25519_PackPoint(pubKey, Q.y, Q.x[0]);

    memcpy(privKey, sk, 32);
    memcpy(privKey+32, pubKey, 32);
}

/*
 * Comment: The design of EdDSA signature scheme is such that it cannot
 *          handle signing of large data and files in a multi-phase fashion 
 *          (init, update(s), finish). This is due to dependecy of 
 *          H(encoded(R) + pk + m) on R which is dependent on m again.
 *          This was not an issue if H(pk + m + encoded(R)) was used instead.
 *          To overcome the limitation of current scheme, following workarounds
 *          can be considered:
 *              a. Sign hash of the file instead of the file itself.
 *              b. Read the file twice
 */
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

    // r = H(b + m) mod BPO
    SHA512_Init(&H);
    SHA512_Update(&H, md+32, 32);
    SHA512_Update(&H, msg, msg_size);
    SHA512_Final(md, &H);
    eco_DigestToWords(r, md);
    eco_Mod(r);                         // r mod BPO

    // R = r*P
    ed25519_BasePointMultiply(&R, r);
    ed25519_PackPoint(signature, R.y, R.x[0]); // R part of signature

    // S = r + H(encoded(R) + pk + m) * a  mod BPO
    SHA512_Init(&H);
    SHA512_Update(&H, signature, 32);   // encoded(R)
    SHA512_Update(&H, privKey+32, 32);  // pk
    SHA512_Update(&H, msg, msg_size);   // m
    SHA512_Final(md, &H);
    eco_DigestToWords(t, md);

    eco_MulReduce(t, t, a);             // h()*a
    eco_AddMod(t, t, r);
    ecp_WordsToBytes(signature+32, t);  // S part of signature

    // Clear sensitive data
    ecp_SetValue(a, 0);
    ecp_SetValue(r, 0);
}
