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
#if defined(_MSC_VER)
#include <windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif
#include <memory.h>
#include "sha512.h"

// Customize this with your own random key
static const unsigned char my_secret_key[] =
{
    0x1c,0xf2,0x42,0x5f,0x89,0x0f,0x68,0xd3,0x85,0x99,0xba,0x26,0xbb,0x8e,0x57,0x3f,
    0x4b,0x58,0x51,0x5a,0x04,0x3c,0x3f,0x26,0x94,0xa0,0xee,0x3a,0x8f,0xf9,0xd1,0x9f,
    0x22,0xa1,0x23,0xfc,0xe3,0xef,0x59,0x1f,0xca,0x7e,0x51,0x67,0x24,0x3b,0x06,0xce,
    0x57,0x71,0xca,0xc2,0x19,0xdb,0x07,0xc2,0x82,0xaf,0x41,0x9f,0x57,0xb5,0x7b,0x21
};

void GetRandomBytes(unsigned char *buffer, int size)
{
#if defined(_MSC_VER)
    HCRYPTPROV hcp;
    CryptAcquireContext(&hcp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(hcp, size, buffer);
    CryptReleaseContext(hcp, 0);
#else
    FILE *fp = fopen("/dev/urandom", "r");
    fread(buffer, sizeof(unsigned char), size, fp);
    fclose(fp);
#endif

    // -- paranoia ----------------------------------------------------------
    //
    // System level RNG's could be compromized, monitored, hacked, hooked,...
    // 
    // We are putting a custom layer of transformation on top which includes 
    // a secret key
    //
    // ----------------------------------------------------------------------

    while (size > 0)
    {
        SHA512_CTX hash;

        SHA512_Init(&hash);
        SHA512_Update(&hash, my_secret_key, sizeof(my_secret_key));
        SHA512_Update(&hash, buffer, size);

        if (size <= SHA512_DIGEST_LENGTH)
        {
            unsigned char digest[SHA512_DIGEST_LENGTH];
            SHA512_Final(digest, &hash);
            memcpy(buffer, digest, size);
            break;
        }

        SHA512_Final(buffer, &hash);
        buffer += SHA512_DIGEST_LENGTH;
        size -= SHA512_DIGEST_LENGTH;
    }
}

