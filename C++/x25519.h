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
#ifndef __x25519_h__
#define __x25519_h__

class X25519Private
{
public:
    // Generate random key pair
    X25519Private();
    // Load an existing private key
    X25519Private(const unsigned char* PrivateKey);

    ~X25519Private();
    
    enum { PrivateKeySize = 32, PublicKeySize = 32, SharedKeyBytes = 32 };

    const unsigned char* GetPrivateKey(unsigned char* privateKey) const;
    const unsigned char* GetPublicKey(unsigned char* publicKey) const;

    void CreateShare(
        const unsigned char* peerPublicKey, 
        unsigned char* sharedSecret);

    // Calls CalculateDHShare(...) then SHA512 hash of shared_secret
    void CreateSharedKey(
        const unsigned char* peerPublicKey, 
        unsigned char*       sharedKey,
        unsigned int         sharedKeySize);
    
private:
    unsigned char m_PrivateKey[32];
    unsigned char m_PublicKey[32];
};

#endif  // __x25519_h__
