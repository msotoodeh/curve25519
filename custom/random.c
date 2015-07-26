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

#if defined(_MSC_VER)
#include <windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif
#include <memory.h>
#include "../source/sha512.h"

/* Customize this with your own random key */
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

    /* -- paranoia ----------------------------------------------------------
    //
    // System level RNG's could be compromized, monitored, hacked, hooked,...
    // 
    // We are putting a custom layer of transformation on top which includes 
    // a secret key
    //
    // ----------------------------------------------------------------------
    */
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

