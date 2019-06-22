#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>

#include "external_calls.h"
#include "curve25519_dh.h"
#include "ed25519_signature.h"

uint64_t readTSC();

void print_hex(uint8_t *data, size_t length) {
  printf("  ");
  for (size_t i = 0; i < length; i++) printf("%02X", data[i]);
  printf("\n");
}

#define X25519_SECRET 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

int openssl_CreateKeyPair(uint8_t *private, int print_flag) {
  int status;
  uint8_t secret[32] = { X25519_SECRET };

  EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret, 32);

  size_t private_size = 32;

  status = EVP_PKEY_get_raw_private_key(key, private, &private_size);
  assert(status == 1);
  assert(private_size == 32);

  status = EVP_PKEY_get_raw_public_key(key, &private[32], &private_size);
  assert(status == 1);
  assert(private_size == 32);

  uint8_t public[32] = { 0 };
  size_t public_size = 32;
  status = EVP_PKEY_get_raw_public_key(key, public, &public_size);
  assert(status == 1);
  assert(public_size == 32);

  if (print_flag)
  {
    printf("OpenSSL CreateKeyPair:\n");
    print_hex(private, 64);
    print_hex(public, 32);
  }
  return 64;
}

int curve25519_CreateKeyPair(uint8_t *private, int print_flag) {
  uint8_t secret[32] = { X25519_SECRET };
  uint8_t public[64] = { 0 };
  ed25519_CreateKeyPair(public, private, NULL, secret);

  if (print_flag)
  {
    printf("Curve25519 CreateKeyPair:\n");
    print_hex(private, 64);
    print_hex(public, 32);
  }
  return 64;
}

int openssl_CalculatePublicKey(uint8_t *public, int print_flag) {
  int status;
  uint8_t secret[32] = { X25519_SECRET };

  EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret, 32);

  size_t public_size = 32;
  status = EVP_PKEY_get_raw_public_key(key, public, &public_size);
  assert(status == 1);
  assert(public_size == 32);

  if (print_flag)
  {
    printf("OpenSSL CalculatePublicKey:\n");
    print_hex(public, 32);
  }
  return 32;
}

int curve25519_CalculatePublicKey(uint8_t *public, int print_flag) {
  uint8_t secret[32] = { X25519_SECRET };
  curve25519_dh_CalculatePublicKey(public, secret);

  if (print_flag)
  {
    printf("Curve25519 CalculatePublicKey:\n");
    print_hex(public, 32);
  }
  return 32;
}

static const uint8_t peer_public[32] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F };

int openssl_CreateSharedKey(uint8_t *result, int print_flag) {
  int status;
  uint8_t secret[32] = { X25519_SECRET };
  EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret, 32);
  EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, 32);

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);

  status = EVP_PKEY_derive_init(ctx);
  assert(status == 1);

  status = EVP_PKEY_derive_set_peer(ctx, peer_key);
  assert(status == 1);

  size_t size = 32;
  status = EVP_PKEY_derive(ctx, result, &size);
  assert(status == 1);
  assert(size == 32);

  if (print_flag)
  {
    printf("OpenSSL CreateSharedKey:\n");
    print_hex(result, 32);
  }
  return 32;
}

int curve25519_CreateSharedKey(uint8_t *result, int print_flag) {
  uint8_t secret[32] = { X25519_SECRET };
  curve25519_dh_CreateSharedKey(result, peer_public, secret);

  if (print_flag)
  {
    printf("Curve25519 CreateSharedKey:\n");
    print_hex(result, 32);
  }
  return 32;
}

static const uint8_t msg[32] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F };

int openssl_SignMessage(uint8_t *signature, int print_flag) {
  int status;
  uint8_t secret[32] = { X25519_SECRET };
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  assert(ctx != NULL);
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret, 32);
  assert(pkey != NULL);

  status = EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
  assert(status == 1);

  size_t signature_length = 64;

  status = EVP_DigestSign(ctx, signature, &signature_length, msg, 32);
  assert(status == 1);
  assert(signature_length == 64);

  if (print_flag)
  {
    printf("OpenSSL SignMessage:\n");
    print_hex(signature, 64);
  }
  return 64;
}

int curve25519_SignMessage(uint8_t *signature, int print_flag) {
  uint8_t key[64] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x03, 0xA1, 0x07, 0xBF, 0xF3, 0xCE, 0x10, 0xBE, 0x1D, 0x70, 0xDD, 0x18, 0xE7, 0x4B, 0xC0, 0x99, 0x67, 0xE4, 0xD6, 0x30, 0x9B, 0xA5, 0x0D, 0x5F, 0x1D, 0xDC, 0x86, 0x64, 0x12, 0x55, 0x31, 0xB8 };

  ed25519_SignMessage(signature, key, NULL, msg, 32);

  if (print_flag)
  {
    printf("Curve25519 SignMessage:\n");
    print_hex(signature, 64);
  }
  return 64;
}

#define LOOPS       100
uint64_t tovr = 0;

int compare_timing(
    const char *op,
    int (*openssl_op)(uint8_t *, int),
    int (*x25519_op)(uint8_t *, int))
{
    int i, len;
    uint64_t t1, t2, t_opnssl = (uint64_t)(-1), t_x25519 = (uint64_t)(-1);
    double d1, d2;
    uint8_t buf1[64], buf2[64];

    for (i = 0; i < LOOPS; ++i)
    {
        t1 = readTSC(); 
        openssl_op(buf1, 0); 
        t2 = readTSC() - t1;
        if (t2 < t_opnssl) t_opnssl = t2;
    }
    t_opnssl -= tovr;

    for (i = 0; i < LOOPS; ++i)
    {
        t1 = readTSC(); 
        x25519_op(buf2, 0); 
        t2 = readTSC() - t1;
        if (t2 < t_x25519) t_x25519 = t2;
    }
    t_x25519 -= tovr;
    
    d1 = (double)t_opnssl;
    d2 = (double)t_x25519;

    printf ("\n-- %s --\n"
            "  OpenSSL: %lld cycles = %.3f usec @3.4GHz -- ratio: %.3f\n", 
        op, t_opnssl, d1/3400.0, d1/d2);
    printf ("    Mehdi: %lld cycles = %.3f usec @3.4GHz -- delta: %.2f%%\n", 
        t_x25519, d2/3400.0, (100.0*(d1-d2))/d1);

    // Print and compare returned values
    len = openssl_op(buf1, 1); 
    x25519_op(buf2, 1); 

    if (memcmp (buf1, buf2, len) != 0)
    {
        printf ("  *** Mismatched results ***\n");
        return 1;
    }
    return 0;
}

int main() {
    int i, diff_cnt = 0;
    uint64_t t1, t2;

    t1 = readTSC();
    tovr = readTSC() - t1;
    for (i = 0; i < 100; i++)
    {
        t1 = readTSC();
        t2 = readTSC() - t1; /* t2-t1 = readTSC() overhead */
        if (t2 < tovr) tovr = t2;
    }

    /* --------------------------------------------------------------------- */
    diff_cnt += compare_timing(
                    "CreateKeyPair", 
                    openssl_CreateKeyPair,
                    curve25519_CreateKeyPair);
    diff_cnt += compare_timing(
                    "CalculatePublicKey", 
                    openssl_CalculatePublicKey,
                    curve25519_CalculatePublicKey);
    diff_cnt += compare_timing(
                    "CreateSharedKey",
                    openssl_CreateSharedKey,
                    curve25519_CreateSharedKey);
    diff_cnt += compare_timing(
                    "SignMessage",
                    openssl_SignMessage,
                    curve25519_SignMessage);
    return diff_cnt;
}
