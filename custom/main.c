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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "random.h"
#include "../source/curve25519_mehdi.h"
#include "../include/ed25519_signature.h"
#include "../source/sha512.h"

/* Linker expects this */
EDP_BLINDING_CTX edp_custom_blinding =
{
  W256(0xD1DFA242,0xAB91A857,0xE9F62749,0xE314C485,0x48FE8FD3,0xF00E7295,0xD29CF9EF,0x06A83629),
  W256(0xC724BEF6,0x59D19EB7,0x1A7ECF15,0x5C439216,0xFCBB0F20,0xA02E4E62,0xA41D8396,0x2D8FD635),
  {
    W256(0xDA38075E,0x33285265,0x7C4AF98A,0x1329C8E1,0xA1D64651,0x05761C7A,0x22D98600,0x0028E8FE),
    W256(0x333BA706,0x842E7E42,0x50F16F1D,0x11FC488E,0x28BCF020,0x078534D6,0x1A0870D7,0xB9CD265C),
    W256(0x1D6F86C0,0xA6D7476F,0xC3BD3FF6,0xF18C0B79,0x512BF0EA,0x6823C74C,0xEA0B036A,0x26708E65),
    W256(0x860B528A,0x5C7CD5E5,0xBFBDA927,0x9834D9F4,0xF696EA66,0xED15167A,0x375453BC,0x5DA1B958)
  }
};

void PrintWords(IN const char *txt, IN const U32 *data, IN int size)
{
    int i;
    printf("%s0x%08X", txt, *data++);
    for (i = 1; i < size; i++) printf(",0x%08X", *data++);
}

void PrintBytes(IN const char *name, IN const unsigned char *data, IN int size)
{
    int i;
    printf("const unsigned char %s[%d] =\n  { 0x%02X", name, size, *data++);
    for (i = 1; i < size; i++)
    {
        if ((i & 15) == 0)
            printf(",\n    0x%02X", *data++);
        else
            printf(",0x%02X", *data++);
    }
    printf(" };\n");
}


int CreateBlindingContext(IN const char *name)
{
    /* Create a random blind */
    unsigned char seed[64];
    EDP_BLINDING_CTX B;
    
    GetRandomBytes(seed, (int)sizeof(seed));
    ed25519_Blinding_Init((void *)&B, seed, sizeof(seed));
    
    printf(
        //"#include \"curve25519_mehdi.h\"\n\n"
        "EDP_BLINDING_CTX %s = \n", name);
    PrintWords("{\n  W256(",B.bl, K_WORDS);
    PrintWords("),\n  W256(",B.zr, K_WORDS);
    PrintWords("),\n  {\n    W256(",B.BP.YpX, K_WORDS);
    PrintWords("),\n    W256(",B.BP.YmX, K_WORDS);
    PrintWords("),\n    W256(",B.BP.T2d, K_WORDS);
    PrintWords("),\n    W256(",B.BP.Z2, K_WORDS);
    printf(")\n  }\n};\n");
    return 0;
}

int CreateRandomBytes(const char *name, int size)
{
    unsigned char *buff = (unsigned char*)malloc(size);
    if (buff)
    {
        GetRandomBytes(buff, size);
        PrintBytes(name, buff, size);
        free(buff);
        return 0;
    }

    fprintf(stderr, "Insufficient memory error.\n");
    return 1;
}

int CreateSignTestVector(const char *seed, const char *msg)
{
    unsigned char md[SHA512_DIGEST_LENGTH];
    unsigned char Kpub[ed25519_public_key_size];
    unsigned char Kprv[ed25519_private_key_size];
    unsigned char sig[ed25519_signature_size];
    int len = (int)strlen(msg);

    if (seed)
    {
        SHA512_CTX H;
        SHA512_Init(&H);
        SHA512_Update(&H, seed, strlen(seed));
        SHA512_Final(md, &H);
    }
    else
    {
        GetRandomBytes(md, 32);
    }

    PrintBytes("sk", md, 32);
    ed25519_CreateKeyPair(Kpub, Kprv, 0, md);

    PrintBytes("Kpub", Kpub, ed25519_public_key_size);
    PrintBytes("Kprv", Kprv, ed25519_private_key_size);

    PrintBytes("m", (const unsigned char*)msg, len);
    ed25519_SignMessage(sig, Kprv, 0, (const unsigned char*)msg, len);
    PrintBytes("sig", sig, ed25519_signature_size);

    if (ed25519_VerifySignature(sig, Kpub, (const unsigned char*)msg, len))
        return 0;

    fprintf(stderr, "Signature verification failed.\n");
    return 1;
}

int main(int argc, char**argv)
{
    if (argc == 3 && argv[1][0] == 'b') 
        return CreateBlindingContext(argv[2]);
    if (argc == 3 && argv[1][0] == 'r') 
        return CreateRandomBytes(argv[2], 32);
    if (argc == 4 && argv[1][0] == 'r') 
        return CreateRandomBytes(argv[2], atol(argv[3]));
    if (argc == 3 && argv[1][0] == 't') 
        return CreateSignTestVector(0, argv[2]);
    if (argc == 4 && argv[1][0] == 't') 
        return CreateSignTestVector(argv[2], argv[3]);

    fprintf(stderr, 
        "Custom tool version " ECP_VERSION_STR ".\n"
        "\nCommand line error.\n"
        "\nCommand line arguments are:"
        "\n  b <name>            Create a random blinding context"
        "\n  r <name> [<size>]   Create random bytes"
        "\n  t [<seed>] <msg>    Create key(seed) and sign(msg) with it"
        "\n");
    return 1;
}
