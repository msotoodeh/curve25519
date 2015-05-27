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
#ifndef __curve25519_dh_key_exchange_h__
#define __curve25519_dh_key_exchange_h__

#ifdef __cplusplus
extern "C" {
#endif

// Return public key associated with sk
// sk will be trimmed on return
void curve25519_dh_CalculatePublicKey(
    unsigned char *pk,          // [32-bytes] OUT: Public key
    unsigned char *sk);         // [32-bytes] IN/OUT: Your secret key

// sk will be trimmed on return
void curve25519_dh_CreateSharedKey(
    unsigned char *shared,      // [32-bytes] OUT: Created shared key
    const unsigned char *pk,    // [32-bytes] IN: Other side's public key
    unsigned char *sk);         // [32-bytes] IN/OUT: Your secret key

#ifdef __cplusplus
}
#endif
#endif  // __curve25519_dh_key_exchange_h__