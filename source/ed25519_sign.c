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
#include <malloc.h>
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
extern const U_WORD _w_BPO[K_WORDS];

/*
// -- custom blind --------------------------------------------------------- 
//
// edp_custom_blinding is defined in source/custom_blind.c
// source/custom_blind is created randomly on every new build
//
// -------------------------------------------------------------------------
*/
extern const EDP_BLINDING_CTX edp_custom_blinding;

const U_WORD _w_2d[K_WORDS] = /* 2*d */
    W256(0x26B2F159,0xEBD69B94,0x8283B156,0x00E0149A,0xEEF3D130,0x198E80F2,0x56DFFCE7,0x2406D9DC);
const U_WORD _w_di[K_WORDS] = /* 1/d */
    W256(0xCDC9F843,0x25E0F276,0x4279542E,0x0B5DD698,0xCDB9CF66,0x2B162114,0x14D5CE43,0x40907ED2);

#include "base_perm_p32.h"

const PA_POINT _w_basepoint_perm64[16] =
{
  { /* P{0} */
    W256(0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000),
    W256(0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000),
    W256(0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000)
  },
  { /* P{1} */
    W256(0xF58C3B85,0x2FBC93C6,0xFB8C0E19,0xCF932DC6,0x643D42C2,0x270B4898,0x33D4BA65,0x07CF9D3A),
    W256(0xD740913E,0x9D103905,0xD140BEB3,0xFD399F05,0x688F8A09,0xA5C18434,0x98F81267,0x44FD2F92),
    W256(0x877AAA68,0xABC91205,0xCCAAC49E,0x26D9E823,0xDD43598C,0x5A1B7DCB,0x9F0C65A8,0x6F117B68)
  },
  { /* P{2} */
    W256(0x77D1F515,0xCD2A65E7,0x8FAA60F1,0x54899187,0xDABC06E5,0xB1B73BBC,0xA97CC9FB,0x654878CB),
    W256(0x8DF6B0FE,0x51138EC7,0xE575F51B,0x5397DA89,0x717AF1B9,0x09207A1D,0x2B20D650,0x2102FDBA),
    W256(0x055CE6A1,0x969EE405,0x1251AD29,0x36BCA768,0xAA7DA415,0x3A1AF517,0x29ECB2BA,0x0AD725DB)
  },
  { /* P{3} */
    W256(0x601E59E8,0x0055C585,0x66480E60,0x8793342B,0xFE45E44C,0x3E14AAD0,0x4813CF2B,0x26EAD8E6),
    W256(0x9C8462A4,0xCB75B8B6,0x67D31CD7,0x2DD86FC5,0x881342F6,0xCD1972EC,0x0FC12F2F,0x0975B597),
    W256(0xDA5BA743,0x63CF2303,0x52F1BA6E,0x04BF9D81,0xAA7367DA,0x333790D0,0x9DF6C5EA,0x53467047)
  },
  { /* P{4} */
    W256(0xACAD8EA2,0x583B04BF,0x148BE884,0x29B743E8,0x0810C5DB,0x2B1E583B,0x8EB3BBAA,0x2B5449E5),
    W256(0xEB3DBE47,0x5F3A7562,0x8EBDA0B8,0xF7EA3854,0x45747299,0x00C3E531,0x1627D551,0x1304E9E7),
    W256(0x6ADC9CFE,0x789814D2,0x8B48DD0B,0x3C1BAB3F,0xF979C60A,0xDA0FE1FF,0x7C2DD693,0x4468DE2D)
  },
  { /* P{5} */
    W256(0xE3BC6748,0x2118278D,0xD0B20EF7,0xE71FFD60,0xC67BB198,0xF551BE51,0xD0543D4D,0x26A13664),
    W256(0x13A339EE,0x29522D3B,0x6CD89529,0x85522550,0xACF4F0F1,0xDFEA3AD4,0x7942742E,0x49D76BBA),
    W256(0x8D56E61D,0x14FA4233,0xC351299A,0x191D3946,0xA7ADB185,0x247D576D,0xA8FCEDC2,0x4E1FAFE3)
  },
  { /* P{6} */
    W256(0x236A044C,0x15E7053D,0x3B8D87E3,0x3CDDBCB1,0xD321A828,0x519960D2,0x0FC5BBA4,0x4E559A0F),
    W256(0x9C12701C,0xFE00E876,0x039C3B5F,0x95DCDC0A,0x0C02EB1B,0xC169454B,0x5F87530C,0x727021D3),
    W256(0x27DF241E,0xA5710407,0xB2900D36,0xDF45EFAA,0x60A69ADE,0xFE6EDB5C,0x07BBC01D,0x64FCB730)
  },
  { /* P{7} */
    W256(0x6FD390CA,0x38EF58CC,0x171A98FC,0xEF786575,0xC442D65F,0x8850B78F,0x6FD086EF,0x6F34C66D),
    W256(0x3898DC04,0x93F3CBB4,0x4307B727,0x0791FFB2,0xCE34981D,0xD7BD8096,0x8B849F6D,0x0B598B8E),
    W256(0x0CC2F689,0x11CFC18A,0xB529CE2A,0x81114607,0xC00B5940,0x0A9BC046,0xB1AC66C8,0x412128B0)
  },
  { /* P{8} */
    W256(0xC80C1AC0,0xA66DCC9D,0x1B38A436,0x97A05CF4,0x95DBD7C6,0xA7EBF3BE,0x8D7E7DAB,0x7DA0B8F6),
    W256(0x385675A6,0xEF782014,0xAAFDA9E8,0xA2649F30,0x5CDFA8CB,0x4CD1EB50,0x1D4DC0B3,0x46115ABA),
    W256(0xC3B5DA76,0xD40F1953,0x21119E9B,0x1DAC6F73,0xFEB25960,0x03CC6021,0x83674B4B,0x5A5F887E)
  },
  { /* P{9} */
    W256(0x0CA2C1F4,0x0A8D6018,0xCC68DF40,0x815EB0DB,0xB82F4E99,0xD7E67A47,0x607F15C0,0x45A02890),
    W256(0xFD41F184,0xFEF366D1,0x01CFE11E,0x8B694A11,0x0150A74D,0x4B39E15E,0x6AD351BA,0x4013F03D),
    W256(0x6EE065CC,0xBD0282DC,0x224AE646,0x36B994FD,0xFEBCE874,0x534E9AD8,0xD9F06E4F,0x482255C1)
  },
  { /* P{10} */
    W256(0x71CEF800,0x3C03EACF,0xCA8AFEBB,0x90367544,0x6A29C477,0x383FEA28,0xBC655462,0x4E8593B0),
    W256(0xA3E5638C,0x12DE114A,0x29C4F20D,0xBA2A4AA9,0x7B8B13A3,0x56B0D29D,0x7B9B7944,0x6BB91A49),
    W256(0xC5E7D206,0x2A49E646,0x9263C445,0xB13EF9CD,0xEDAB529E,0x50AB6CE8,0xB0EBE39B,0x20CF7D79)
  },
  { /* P{11} */
    W256(0x8AE75C48,0xCBD28F4E,0x44000B60,0x3CDE0291,0x98BC2170,0x373BB9C8,0x9F570886,0x7C118853),
    W256(0xF0FE7DCA,0x7DB4939D,0xCBA951CE,0xF50EB90F,0x357E1D1D,0x098BE61C,0x8899469D,0x02356237),
    W256(0xE15A4C03,0x20F6EFFA,0x3C778E05,0x2F470A94,0xFC99DE67,0x79F50A03,0xD1061483,0x38D20188)
  },
  { /* P{12} */
    W256(0x0E6315DF,0x23E811AD,0xE2AEB290,0x0B650D05,0xA75D586C,0xB7BA0F59,0x5E1F4DEE,0x043EEDD4),
    W256(0xC7073217,0xF6C147F2,0xF3AFD20C,0xC651B919,0x7041F802,0x258FDBFD,0x4F45073E,0x173C4FA9),
    W256(0x928DF9C4,0x3D71EA60,0x3373562D,0x5B7E7806,0xA29552B2,0xD9B0514C,0x993CC472,0x1E2A7024)
  },
  { /* P{13} */
    W256(0xD45C811F,0x601A0FBC,0x92EC0803,0x24B7BC7D,0x17D2407F,0xA0CAE62B,0x06225B26,0x5FCB43EE),
    W256(0x3509FBA4,0x310509B9,0x05631B75,0x0D8DB376,0x52401C87,0x97DECCBA,0x11B2E773,0x044649F4),
    W256(0x9598215F,0x0C0D24AD,0xCC36628C,0x1B7F9026,0x7016DCEA,0x338E2F55,0x5CC0E58F,0x0C8A1BFA)
  },
  { /* P{14} */
    W256(0x681D104C,0x8DE703B5,0x1263CB45,0x3D2F7A59,0x1CE56C63,0xAE710C17,0xFCC3E6CA,0x6B857C7E),
    W256(0x8B2801C0,0x79D256B4,0x3C400FC4,0x7E9FBEAC,0x4733BA41,0xA751AB1D,0xDD418ACA,0x09DE2BF5),
    W256(0xEFF0687F,0x3BF10FF3,0xF1E37BA2,0x5EBAEA34,0x1D66034D,0xE49E6126,0xC3B242CA,0x5B466E2A)
  },
  { /* P{15} */
    W256(0x47FBB842,0x137EEB67,0x60811A8B,0x79DF5C75,0x71F8C89A,0x5A2BA76F,0x3BC8FFC2,0x09952A56),
    W256(0xDC7EF83C,0xA2A8CB4B,0x5F93C226,0x96B5C6FA,0x0664E3A5,0xD4EBEB1B,0xE5C6CF2F,0x409B4ADC),
    W256(0x834350C4,0x44D53DB9,0xA5F505B4,0x89299305,0x5949FF2F,0xFB22FAA2,0x04657D64,0x69B968A7)
  }
};

/*
    Reference: http://eprint.iacr.org/2008/522
    Cost: 7M + 7add
    Return: R = P + BasePoint
*/
void edp_AddBasePoint(Ext_POINT *p)
{
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];

    ecp_SubReduce(a, p->y, p->x);           /* A = (Y1-X1)*(Y2-X2) */
    ecp_MulReduce(a, a, _w_basepoint_perm64[1].YmX);
    ecp_AddReduce(b, p->y, p->x);           /* B = (Y1+X1)*(Y2+X2) */
    ecp_MulReduce(b, b, _w_basepoint_perm64[1].YpX);
    ecp_MulReduce(c, p->t, _w_basepoint_perm64[1].T2d); /* C = T1*2d*T2 */
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
void edp_AddAffinePoint(Ext_POINT *p, const PA_POINT *q)
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
void edp_DoublePoint(Ext_POINT *p)
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

/* -- FOLDING ---------------------------------------------------------------
//
//    The performance boost is achieved by a process that I call it FOLDING.
//    Folding can be viewed as an extension of Shamir's trick but it is based
//    on break down of the scalar multiplier of a*P into a polynomial of the
//    form:
//
//        a*P = SUM(a_i*2^(i*w))*P    for i = 0,1,2,...n-1
//
//        a*P = SUM(a_i*P_i)
//
//        where P_i = (2^(i*w))*P
//              n = number of limbs
//              w = bit-length of limbs
//
//    For 64-bit limbs, n will be 4 for 256-bit multipliers. P_0 - P_3 can be 
//    pre-calculated and their 16-different permutations can be cached or 
//    hard-coded (in case of P=base point) directly into the code.
//    This arrangement combined with double-and-add approach reduces the 
//    number of EC point calculations by a factor of 4. We only need 64
//    double & add operations.
//
// --------------------------------------------------------------------------
// Return R = a*P where P is ed25519 base point
*/
void edp_BasePointMult(OUT Ext_POINT *S, IN const U_WORD *sk)
{
    int i = 1;
    U8 cut[32];
    const PA_POINT *p0;

    ecp_8Folds(cut, sk);

    p0 = &_w_basepoint_perm32[cut[0]];

    ecp_SubReduce(S->x, p0->YpX, p0->YmX);  /* 2x */
    ecp_AddReduce(S->y, p0->YpX, p0->YmX);  /* 2y */
    ecp_MulReduce(S->t, p0->T2d, _w_di);    /* 2xy */
    ecp_SetValue(S->z, 2);

    do 
    {
        edp_DoublePoint(S);
        edp_AddAffinePoint(S, &_w_basepoint_perm32[cut[i]]);
    } while (i++ < 31);
}

void edp_BasePointMultiply(
    OUT Affine_POINT *R, 
    IN const U8 *sk, 
    IN const void *blinding)
{
    Ext_POINT S;
    U_WORD t[K_WORDS];

    ecp_BytesToWords(t, sk);

    if (blinding)
    {
        eco_AddReduce(t, t, ((EDP_BLINDING_CTX*)blinding)->bl);
        edp_BasePointMult(&S, t);
        edp_AddPoint(&S, &S, &((EDP_BLINDING_CTX*)blinding)->BP);
    }
    else
    {
        edp_BasePointMult(&S, t);
    }

    ecp_Inverse(S.z, S.z);
    ecp_MulMod(R->x, S.x, S.z);
    ecp_MulMod(R->y, S.y, S.z);
}

void edp_ExtPoint2PE(PE_POINT *r, const Ext_POINT *p)
{
    ecp_AddReduce(r->YpX, p->y, p->x);
    ecp_SubReduce(r->YmX, p->y, p->x);
    ecp_MulReduce(r->T2d, p->t, _w_2d);
    ecp_AddReduce(r->Z2, p->z, p->z);
}

/* -- Blinding -------------------------------------------------------------
//
//  Blinding is a measure to protect against side channel attacks. 
//  Blinding andomizes the scalar multiplier.
//
//  Instead of calculating a*P, calculate (a-b mod BPO)*P followed by adding
//  point B.
//
//  Where b = random blinding and B = b*P
//
// -------------------------------------------------------------------------
*/
void *ed25519_Blinding_Init(
    void *context,                      /* IO: null or ptr blinding context */
    const unsigned char *blinder)       /* IN: [32 bytes] random blind */
{
    Ext_POINT T;
    U_WORD t[K_WORDS];
    EDP_BLINDING_CTX *ctx = (EDP_BLINDING_CTX*)context;

    if (ctx == 0) ctx = (EDP_BLINDING_CTX*)malloc(sizeof(EDP_BLINDING_CTX));

    /* Use edp_custom_blinding to protect generation of the new blinder */

    ecp_BytesToWords(t, blinder);
    eco_AddReduce(t, t, edp_custom_blinding.bl);
    edp_BasePointMult(&T, t);
    edp_AddPoint(&T, &T, &edp_custom_blinding.BP);

    edp_ExtPoint2PE(&ctx->BP, &T);

    ecp_BytesToWords(ctx->bl, blinder);
    eco_Mod(ctx->bl);
    ecp_Sub(ctx->bl, _w_BPO, ctx->bl);

    return ctx;
}

void ed25519_Blinding_Finish(
    void *context)                      /* IN: blinding context */
{
    if (context)
    {
        memset(context, 0, sizeof(EDP_BLINDING_CTX));
        free (context);
    }
}

/* Generate public and private key pair associated with the secret key */
void ed25519_CreateKeyPair(
    unsigned char *pubKey,              /* OUT: public key */
    unsigned char *privKey,             /* OUT: private key */
    const void *blinding,               /* IN: [optional] null or blinding context */
    const unsigned char *sk)            /* IN: secret key (32 bytes) */
{
    U8 md[SHA512_DIGEST_LENGTH];
    SHA512_CTX H;
    Affine_POINT Q;

    /* [a:b] = H(sk) */
    SHA512_Init(&H);
    SHA512_Update(&H, sk, 32);
    SHA512_Final(md, &H);
    ecp_TrimSecretKey(md);

    edp_BasePointMultiply(&Q, md, blinding);
    ed25519_PackPoint(pubKey, Q.y, Q.x[0]);

    memcpy(privKey, sk, 32);
    memcpy(privKey+32, pubKey, 32);
}

/*
 * Generate message signature
 */
void ed25519_SignMessage(
    unsigned char *signature,           /* OUT: [64 bytes] signature (R,S) */
    const unsigned char *privKey,       /*  IN: [64 bytes] private key (sk,pk) */
    const void *blinding,               /*  IN: [optional] null or blinding context */
    const unsigned char *msg,           /*  IN: [msg_size bytes] message to sign */
    size_t msg_size)
{
    SHA512_CTX H;
    Affine_POINT R;
    U_WORD a[K_WORDS], t[K_WORDS], r[K_WORDS];
    U8 md[SHA512_DIGEST_LENGTH];

    /* [a:b] = H(sk) */
    SHA512_Init(&H);
    SHA512_Update(&H, privKey, 32);
    SHA512_Final(md, &H);
    ecp_TrimSecretKey(md);              /* a = first 32 bytes */
    ecp_BytesToWords(a, md);

    /* r = H(b + m) mod BPO */
    SHA512_Init(&H);
    SHA512_Update(&H, md+32, 32);
    SHA512_Update(&H, msg, msg_size);
    SHA512_Final(md, &H);
    eco_DigestToWords(r, md);
    eco_Mod(r);                         /* r mod BPO */

    /* R = r*P */
    ecp_WordsToBytes(md, r);
    edp_BasePointMultiply(&R, md, blinding);
    ed25519_PackPoint(signature, R.y, R.x[0]); /* R part of signature */

    /* S = r + H(encoded(R) + pk + m) * a  mod BPO */
    SHA512_Init(&H);
    SHA512_Update(&H, signature, 32);   /* encoded(R) */
    SHA512_Update(&H, privKey+32, 32);  /* pk */
    SHA512_Update(&H, msg, msg_size);   /* m */
    SHA512_Final(md, &H);
    eco_DigestToWords(t, md);

    eco_MulReduce(t, t, a);             /* h()*a */
    eco_AddMod(t, t, r);
    ecp_WordsToBytes(signature+32, t);  /* S part of signature */

    /* Clear sensitive data */
    ecp_SetValue(a, 0);
    ecp_SetValue(r, 0);
}
