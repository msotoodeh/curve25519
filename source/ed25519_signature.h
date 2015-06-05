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
#ifndef __ed25519_signature_h__
#define __ed25519_signature_h__

#ifdef __cplusplus
extern "C" {
#endif

// -- ed25519-sign -------------------------------------------------------------

#define ed25519_public_key_size     32
#define ed25519_secret_key_size     32
#define ed25519_private_key_size    64
#define ed25519_signature_size      64

// Generate public key associated with the secret key
void ed25519_CreateKeyPair(
    unsigned char *pubKey,              // OUT: public key
    unsigned char *privKey,             // OUT: private key
    const void *blinding,               // IN: [optional] null or blinding context
    const unsigned char *sk);           // IN: secret key (32 bytes)

// Generate message signature
void ed25519_SignMessage(
    unsigned char *signature,           // OUT:[64 bytes] signature (R,S)
    const unsigned char *privKey,       // IN: [64 bytes] private key (sk,pk)
    const void *blinding,               // IN: [optional] null or blinding context
    const unsigned char *msg,           // IN: [msg_size bytes] message to sign
    size_t msg_size);                   // IN: size of message

void *ed25519_Blinding_Init(
    void *context,                      // IO: null or ptr blinding context
    const unsigned char *blinder);      // IN: [32 bytes] random blind

void ed25519_Blinding_Finish(
    void *context);                     // IN: blinding context

// -- ed25519-verify -----------------------------------------------------------

int ed25519_VerifySignature(
    const unsigned char *signature,     // IN: [64 bytes] signature (R,S)
    const unsigned char *publicKey,     // IN: [32 bytes] public key
    const unsigned char *msg,           // IN: [msg_size bytes] message to sign
    size_t msg_size);                   // IN: size of message

void * ed25519_Verify_Init(
    void *context,                      // IO: null or verify context to use
    const unsigned char *publicKey);    // IN: [32 bytes] public key

int ed25519_Verify_Check(
    const void          *context,               // IN: created by ed25519_Verify_Init
    const unsigned char *signature,             // IN: signature (R,S)
    const unsigned char *msg, size_t msg_size); // IN: message to sign

void ed25519_Verify_Finish(void *ctx);

#ifdef __cplusplus
}
#endif
#endif  // __ed25519_signature_h__