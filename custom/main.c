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
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "random.h"
#include "curve25519_mehdi.h"
#include "ed25519_signature.h"

EDP_BLINDING_CTX edp_custom_blinding =
{
  W256(0x8869B072,0x58B262BC,0xE32D3A61,0x39608B4F,0x9D89ECB9,0xC9CE3304,0x48F0B76F,0x0871ADF4),
  {
    W256(0x0AA28C78,0x7E925BF0,0xEA304262,0xC5BCA23A,0xD0AE1AD1,0xA5B282D3,0x0B63B8F7,0x12D645C5),
    W256(0x036F96C2,0xB4C60821,0x11AA73FC,0x54D922F1,0x01CB7AD7,0x944898BB,0xC1B70616,0xF3CB170F),
    W256(0x6ED30222,0x5BBA27EC,0x1012744C,0xE8828782,0xB1224A21,0x762F4EB9,0xC0A604F9,0x3798991C),
    W256(0x189C6DA2,0xCBC9AE70,0xED9B1B36,0x7270BB46,0x620CA91F,0x8BB3E371,0xDC5E859A,0x67DA9D45)
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
    printf("static const unsigned char %s[%d] =\n  { 0x%02X", name, size, *data++);
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
    // Create a random blind
    unsigned char blind[32];
    EDP_BLINDING_CTX B;
    
    GetRandomBytes(blind, 32);
    ed25519_Blinding_Init((void *)&B, blind);
    
    printf(
        "#include \"curve25519_mehdi.h\"\n\n"
        "const EDP_BLINDING_CTX %s = \n", name);
    PrintWords("{\n  W256(",B.bl, K_WORDS);
    PrintWords("),\n  {\n    W256(",B.BP.YpX, K_WORDS);
    PrintWords("),\n    W256(",B.BP.YmX, K_WORDS);
    PrintWords("),\n    W256(",B.BP.T2d, K_WORDS);
    PrintWords("),\n    W256(",B.BP.Z2, K_WORDS);
    printf(")\n  }\n};\n");
    return 0;
}

int CreateRandomBytes(char *name, int size)
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

int main(int argc, char**argv)
{
    if (argc == 3 && argv[1][0] == 'b') return CreateBlindingContext(argv[2]);
    if (argc == 3 && argv[1][0] == 'r') return CreateRandomBytes(argv[2], 32);
    if (argc == 4 && argv[1][0] == 'r') return CreateRandomBytes(argv[2], atol(argv[3]));

    fprintf(stderr, "Command line error.\n"
        "\nUsage:"
        "\n   b <name>            Create a random blinding context"
        "\n   r <name> [<size>]   Create random bytes"
        "\n");
    return 1;
}
