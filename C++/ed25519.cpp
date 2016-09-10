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
#include "ed25519.h"
#include "custom/random.h"
#include "include/ed25519_signature.h"
#include "source/curve25519_mehdi.h"

extern "C" 
{
// Refresh blinds using custom_tool project
#include "custom_blinds.h"
}


///////////////////////////////////////////////////////////////////////////////////////////////////

ED25519Public::ED25519Public(const unsigned char* publicKey)
{
    memcpy(m_Key, publicKey, sizeof(m_Key));
}

ED25519Public::~ED25519Public()
{
}

const unsigned char* ED25519Public::GetKeyBytes(
    unsigned char* publicKey) const
{
    if (publicKey)
    {
        memcpy(publicKey, m_Key, sizeof(m_Key));
        return publicKey;
    }

    return &m_Key[0];
}

bool ED25519Public::VeifySignature(
    const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
    unsigned int msg_size,              /* IN: size of message */
    const unsigned char* signature)     /* IN: [64 bytes] signature (R,S) */
{
    return ed25519_VerifySignature (signature, m_Key, msg, msg_size) == 1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Load private key or generate randomly
//
ED25519Private::ED25519Private(const unsigned char* key, unsigned int size)
{
    if (size == PrivateKeySize)
    {
        // construct from raw key bytes
        memcpy(m_Key, key, PrivateKeySize);
    }
    else
    {
        unsigned char sk[SecretBytes], Kpub[ED25519Public::PublicKeySize];
        if (size == SecretBytes)
            memcpy(sk, key, SecretBytes);
        else
            GetRandomBytes (sk, sizeof(sk));

        ed25519_CreateKeyPair (Kpub, m_Key, &edp_genkey_blinding, sk);
        memset (sk, 0, sizeof(sk));
    }
}
 
ED25519Private::~ED25519Private(void)
{
    memset (m_Key, 0, sizeof(m_Key));
}

const unsigned char* ED25519Private::GetPrivateKey(unsigned char* privateKey) const
{
    if (privateKey)
    {
        memcpy (privateKey, m_Key, sizeof(m_Key));
        return privateKey;
    }

    return &m_Key[0];
}

const unsigned char* ED25519Private::GetPublicKey(unsigned char* publicKey) const
{
    if (publicKey)
    {
        memcpy (publicKey, &m_Key[32], 32);
        return publicKey;
    }

    return &m_Key[32];
}

void ED25519Private::SignMessage(
    const unsigned char* msg,   /* IN: [msg_size bytes] message to sign */
    unsigned int msg_size,      /* IN: size of message */
    unsigned char*signature)    /* OUT: [64 bytes] signature (R,S) */
{
    ed25519_SignMessage (signature, m_Key, &edp_signature_blinding, msg, msg_size);
}
