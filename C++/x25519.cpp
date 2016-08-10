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
#include "x25519.h"
#include "custom/random.h"
#include "source/sha512.h"
#include "include/curve25519_dh.h"

X25519Private::X25519Private()
{
    GetRandomBytes (m_PrivateKey, PrivateKeySize);
    curve25519_dh_CalculatePublicKey_fast(m_PublicKey, m_PrivateKey);
}

X25519Private::X25519Private(const unsigned char* PrivateKey)
{
    memcpy (m_PrivateKey, PrivateKey, PrivateKeySize);
    curve25519_dh_CalculatePublicKey_fast(m_PublicKey, m_PrivateKey);
}

X25519Private::~X25519Private(void)
{
    memset (m_PrivateKey, 0, PrivateKeySize);
}

const unsigned char* X25519Private::GetPrivateKey(unsigned char* privateKey) const
{
    if (privateKey)
    {
        memcpy (privateKey, m_PrivateKey, sizeof(m_PrivateKey));
        return privateKey;
    }
    return &m_PrivateKey[0];
}

const unsigned char* X25519Private::GetPublicKey(unsigned char* publicKey) const
{
    if (publicKey)
    {
        memcpy (publicKey, m_PublicKey, sizeof(m_PublicKey));
        return publicKey;
    }

    return &m_PublicKey[0];
}

void X25519Private::CreateShare(
    const unsigned char* peerPublicKey, 
    unsigned char* sharedSecret)
{
    curve25519_dh_CreateSharedKey(sharedSecret, peerPublicKey, m_PrivateKey);
}

void X25519Private::CreateSharedKey(
    const unsigned char* peerPublicKey, 
    unsigned char*       sharedKey,
    unsigned int         sharedKeySize)
{
    unsigned char shared_secret[SharedKeyBytes], digest[SHA512_DIGEST_LENGTH];
    curve25519_dh_CreateSharedKey(shared_secret, peerPublicKey, m_PrivateKey);
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, (const void*)&shared_secret[0], sizeof(shared_secret));
    SHA512_Final(digest, &ctx);

    if (sharedKeySize > SHA512_DIGEST_LENGTH)
        sharedKeySize = SHA512_DIGEST_LENGTH;

    memcpy (sharedKey, digest, sharedKeySize);

    // clear sensitive data
    memset (shared_secret, 0, sizeof(shared_secret));
    memset (digest, 0, sizeof(digest));
}
