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
#include "curve25519_dh.h"
#include "ed25519_signature.h"

extern U64 readTSC();

void ecp_PrintBytes(IN const char *name, IN const U8 *data, IN U32 size)
{
    U32 i;
    printf("\nstatic const U8 %s[%d] =\n  { 0x%02X", name, size, *data++);
    for (i = 1; i < size; i++)
    {
        if ((i & 15) == 0)
            printf(",\n    0x%02X", *data++);
        else
            printf(",0x%02X", *data++);
    }
    printf(" };\n");
}

void ecp_PrintWords(IN const char *name, IN const U64 *data, IN U32 size)
{
    U32 i;
    printf("\nstatic const U64 %s[%d] =\n  { 0x%016llX", name, size, *data++);
    for (i = 1; i < size; i++)
    {
        if ((i & 3) == 0)
            printf(",\n    0x%016llX", *data++);
        else
            printf(",0x%016llX", *data++);
    }
    printf(" };\n");
}

void ecp_PrintHexBytes(IN const char *name, IN const U8 *data, IN U32 size)
{
    printf("%s = 0x", name);
    while (size > 0) printf("%02X", data[--size]);
    printf("\n");
}

void ecp_PrintHexWords(IN const char *name, IN const U64 *data, IN U32 size)
{
    printf("%s = 0x", name);
    while (size > 0) printf("%16llX", data[--size]);
    printf("\n");
}

extern int curve25519_SelfTest(int level);

int speed_test(int loops)
{
    U64 t1, t2, tovr = 0, td = (U64)(-1), tm = (U64)(-1);
    U8 secret_key[32], donna_publickey[32], mehdi_publickey[32];
    unsigned char pubkey[32], privkey[64], sig[64];
    int i;

    // generate key
    memset(secret_key, 0x42, 32);
    ecp_TrimSecretKey(secret_key);

    // Make sure both generate identical public key
    curve25519_donna(donna_publickey, secret_key, ecp_BasePoint);
    curve25519_dh_CalculatePublicKey(mehdi_publickey, secret_key);

    if (memcmp(mehdi_publickey, donna_publickey, 32) != 0)
    {
        ecp_PrintHexBytes("sk", secret_key, 32);
        ecp_PrintHexBytes("mehdi_pk", mehdi_publickey, 32);
        ecp_PrintHexBytes("donna_pk", donna_publickey, 32);
        printf("\n*********** Public keys do not match!! ********************\n");
        return 1;
    }

    // Timing values that we measure includes some random CPU activity overhead
    // We try to get the minimum time as the more accurate time

    t1 = readTSC();
    tovr = readTSC() - t1; // t2-t1 = readTSC() overhead
    for (i = 0; i < 100; i++)
    {
        t1 = readTSC();
        t2 = readTSC() - t1; // t2-t1 = readTSC() overhead
        if (t2 < tovr) tovr = t2;
    }

    // ---------------------------------------------------------------------
    // Go Donna, go 
    // ---------------------------------------------------------------------
    for (i = 0; i < loops; ++i) 
    {
        t1 = readTSC();
        curve25519_donna(donna_publickey, secret_key, ecp_BasePoint);
        t2 = readTSC() - t1;
        if (t2 < td) td = t2;
    }
    td -= tovr;

    // ---------------------------------------------------------------------
    // Ready, set, go 
    // ---------------------------------------------------------------------
    for (i = 0; i < loops; i++)
    {
        t1 = readTSC();
        curve25519_dh_CalculatePublicKey(mehdi_publickey, secret_key);
        t2 = readTSC() - t1;
        if (t2 < tm) tm = t2;
    }
    tm -= tovr;

    printf ("\n-- curve25519-DH --\n"
            "    Donna: %lld cycles = %.3f usec @3.4GHz -- ratio: %.3f\n", 
        td, (double)td/3400.0, (double)td/(double)tm);
    printf ("    Mehdi: %lld cycles = %.3f usec @3.4GHz -- delta: %.2f%%\n", 
        tm, (double)tm/3400.0, (100.0*(td-tm))/(double)td);

    // ---------------------------------------------------------------------
    // Speed measurement for ed25519 keygen, sign and verify
    // ---------------------------------------------------------------------
    tm = (U64)(-1);
    for (i = 0; i < loops; i++)
    {
        t1 = readTSC();
        ed25519_CreateKeyPair(pubkey, privkey, secret_key);
        t2 = readTSC() - t1;
        if (t2 < tm) tm = t2;
    }
    tm -= tovr;

    printf ("\n-- ed25519 --\n"
            "    KeyGen: %lld cycles = %.3f usec @3.4GHz\n", tm, (double)tm/3400.0);

    // ---------------------------------------------------------------------
    tm = (U64)(-1);
    for (i = 0; i < loops; i++)
    {
        t1 = readTSC();
        ed25519_SignMessage(sig, privkey, "abc", 3);
        t2 = readTSC() - t1;
        if (t2 < tm) tm = t2;
    }
    tm -= tovr;

    printf ("      Sign: %lld cycles = %.3f usec @3.4GHz\n", tm, (double)tm/3400.0);

    // ---------------------------------------------------------------------
    tm = (U64)(-1);
    for (i = 0; i < loops; i++)
    {
        t1 = readTSC();
        ed25519_VerifySignature(sig, pubkey, (const unsigned char*)"abc", 3);
        t2 = readTSC() - t1;
        if (t2 < tm) tm = t2;
    }
    tm -= tovr;

    printf ("    Verify: %lld cycles = %.3f usec @3.4GHz\n", tm, (double)tm/3400.0);
    return 0;
}

int signature_test(
    const unsigned char *sk, 
    const unsigned char *expected_pk, 
    const unsigned char *msg, size_t size, 
    const unsigned char *expected_sig)
{
    int rc = 0;
    unsigned char sig[ed25519_signature_size];
    unsigned char pubKey[ed25519_public_key_size];
    unsigned char privKey[ed25519_private_key_size];

    printf("\n-- ed25519 -- sign/verify test ---------------------------------\n");
    printf("\n-- CreateKeyPair --\n");
    ed25519_CreateKeyPair(pubKey, privKey, sk);
    ecp_PrintHexBytes("secret_key", sk, ed25519_secret_key_size);
    ecp_PrintHexBytes("public_key", pubKey, ed25519_public_key_size);
    ecp_PrintBytes("private_key", privKey, ed25519_private_key_size);

    if (expected_pk && memcmp(pubKey, expected_pk, ed25519_public_key_size) != 0)
    {
        rc++;
        printf("ed25519_CreateKeyPair() FAILED!!\n");
        ecp_PrintHexBytes("Expected_pk", expected_pk, ed25519_public_key_size);
    }

    printf("-- Sign/Verify --\n");
    ed25519_SignMessage(sig, privKey, msg, size);
    ecp_PrintBytes("message", msg, (U32)size);
    ecp_PrintBytes("signature", sig, ed25519_signature_size);
    if (expected_sig && memcmp(sig, expected_sig, ed25519_signature_size) != 0)
    {
        rc++;
        printf("Signature generation FAILED!!\n");
        ecp_PrintBytes("Calculated", sig, ed25519_signature_size);
        ecp_PrintBytes("ExpectedSig", expected_sig, ed25519_signature_size);
    }

    if (!ed25519_VerifySignature(sig, pubKey, msg, size))
    {
        rc++;
        printf("Signature verification FAILED!!\n");
        ecp_PrintBytes("sig", sig, ed25519_signature_size);
        ecp_PrintBytes("pk", pubKey, ed25519_public_key_size);
    }
    else
    {
        printf("  ++ Signature Verified Successfully. ++\n");
    }
    return rc;
}

unsigned char sk1[32] = 
  { 0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
    0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb };
unsigned char pk1[ed25519_public_key_size] = 
  { 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
    0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c };
unsigned char msg1[] = { 0x72 };
unsigned char msg1_sig[ed25519_signature_size] = {
    0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
    0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
    0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
    0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
};

int ed25519_selftest();

int dh_test()
{
    int rc = 0;
    unsigned char alice_public_key[32], alice_shared_key[32];
    unsigned char bruce_public_key[32], bruce_shared_key[32];

    unsigned char alice_secret_key[32] = { // #1234
        0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,
        0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
        0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,
        0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4 };

    unsigned char bruce_secret_key[32] = { // #abcd
        0x88,0xd4,0x26,0x6f,0xd4,0xe6,0x33,0x8d,
        0x13,0xb8,0x45,0xfc,0xf2,0x89,0x57,0x9d,
        0x20,0x9c,0x89,0x78,0x23,0xb9,0x21,0x7d,
        0xa3,0xe1,0x61,0x93,0x6f,0x03,0x15,0x89 };

    printf("\n-- curve25519 -- key exchange test -----------------------------\n");
    // Step 1. Alice and Bruce generate their own random secret keys

    ecp_PrintHexBytes("Alice_secret_key", alice_secret_key, 32);
    ecp_PrintHexBytes("Bruce_secret_key", bruce_secret_key, 32);

    // Step 2. Alice and Bruce create public keys associated with their secret keys
    //         and exchange their public keys

    curve25519_dh_CalculatePublicKey(alice_public_key, alice_secret_key);
    curve25519_dh_CalculatePublicKey(bruce_public_key, bruce_secret_key);
    ecp_PrintHexBytes("Alice_public_key", alice_public_key, 32);
    ecp_PrintHexBytes("Bruce_public_key", bruce_public_key, 32);

    // Step 3. Alice and Bruce create their shared key

    curve25519_dh_CreateSharedKey(alice_shared_key, bruce_public_key, alice_secret_key);
    curve25519_dh_CreateSharedKey(bruce_shared_key, alice_public_key, bruce_secret_key);
    ecp_PrintHexBytes("Alice_shared", alice_shared_key, 32);
    ecp_PrintHexBytes("Bruce_shared", alice_shared_key, 32);

    // Alice and Bruce should end up with idetntical keys
    if (memcmp(alice_shared_key, bruce_shared_key, 32) != 0)
    {
        rc++;
        printf("DH key exchange FAILED!!\n");
    }
    return rc;
}

//void pre_compute_base_point();

int main(int argc, char**argv)
{
    int rc = 0;
    //pre_compute_base_point();

    if (curve25519_SelfTest(1) != 0)
    {
        printf("Self-test FAILED!");
        return 1;
    }

    rc += dh_test();

    rc += signature_test(sk1, pk1, msg1, sizeof(msg1), msg1_sig);

    speed_test(1000);

    return rc;
}
