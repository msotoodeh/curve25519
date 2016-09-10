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
#ifndef __ed25519_h__
#define __ed25519_h__

class ED25519Public
{
public:
    enum { PublicKeySize = 32, SignatureBytes = 64 };

    ED25519Public(const unsigned char* PublicKey);
    ~ED25519Public();

    const unsigned char* GetKeyBytes(unsigned char* publicKey) const;

    bool VeifySignature(
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,              /* IN: size of message */
        const unsigned char* signature);    /* IN: [64 bytes] signature (R,S) */

private:
    unsigned char m_Key[PublicKeySize];
};

class ED25519Private
{
public:
    /* Constructor/Destructor */

    /*
     *   Load existing key or generate a random key. 
     *       key     Secret or private key blob
     *       size    Size (in bytes) of the key argument
     *               Expected values:
     *                   32      key is the 'secret key'. 
     *                           Public and private keys are claculated from secret key.
     *                   64      key is 'private key'.
     *                           Load an existing key.
     *                   0       Generate key pair randomly
     */
    ED25519Private(const unsigned char* key, unsigned int size);
    ~ED25519Private();
    
    enum { SecretBytes = 32, PrivateKeySize = 64, SignatureBytes = 64 };

    const unsigned char* GetPrivateKey(unsigned char* privateKey = 0) const;
    const unsigned char* GetPublicKey(unsigned char* publicKey = 0) const;

    void SignMessage(
        const unsigned char* msg,   /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,      /* IN: size of message */
        unsigned char* signature);  /* OUT: [64 bytes] signature (R,S) */

private:
    unsigned char m_Key[PrivateKeySize];
};

#endif // __ed25519_h__
