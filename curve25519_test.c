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
#include <memory.h>
#include "curve25519_mehdi.h"
#include "curve25519_donna.h"
#include "curve25519_SelfTest.h"

#ifdef ECP_NO_TSC
#include <sys/time.h>

U64 TimeNow()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}
#else
#if defined(_MSC_VER)
#include <intrin.h>
//#pragma intrinsic(__rdtsc)
U64 TimeNow() 
{ 
    return __rdtsc();
}
#else
U64 TimeNow()
{
    U64 tsc;
    __asm__ volatile(".byte 0x0f,0x31" : "=A" (tsc));
    return tsc;
}
#endif
#endif

void ecp_PrintBytes(IN const char *name, IN const U8 *data, IN U32 size)
{
    U32 i;
    printf("\nstatic const U8 %s[%d] = {\n    0x%02X", name, size, *data++);
    for (i = 1; i < size; i++)
    {
        if ((i & 15) == 0)
            printf(",\n    0x%02X", *data++);
        else
            printf(",0x%02X", *data++);
    }
    printf(" };\n");
}

void ecp_PrintWords(IN const char *name, IN const U32 *data, IN U32 size)
{
    U32 i;
    printf("\nstatic const U32 %s[%d] = {\n    0x%08X", name, size, *data++);
    for (i = 1; i < size; i++)
    {
        if ((i & 3) == 0)
            printf(",\n    0x%08X", *data++);
        else
            printf(",0x%08X", *data++);
    }
    printf(" };\n");
}

int main(int argc, char**argv)
{
    U64 t1, t2, tovr = 0, td = (U64)(-1), tm = (U64)(-1);
    U8 secret_key[32], donna_publickey[32], mehdi_publickey[32];
    int i;

#ifdef ECP_SELF_TEST
    if (curve25519_SelfTest(0))
    {
        printf("\n*********** Selftest FAILED!! ********************\n");
        return 1;
    }
#endif
    // generate key
    memset(secret_key, 0x42, 32);
    ecp_TrimSecretKey(secret_key);
    ecp_PrintBytes("secret_key", secret_key, 32);

    // Make sure both generate identical public key
    curve25519_donna(donna_publickey, secret_key, ecp_BasePoint);
    ecp_PointMultiply(mehdi_publickey, ecp_BasePoint, secret_key, 32);

    ecp_PrintBytes("mehdi_public_key", mehdi_publickey, 32);

    if (memcmp(mehdi_publickey, donna_publickey, 32) != 0)
    {
        ecp_PrintBytes("donna_public_key", donna_publickey, 32);
        printf("\n*********** Public keys do not match!! ********************\n");
        return 1;
    }

#ifdef ECP_NO_TSC
    // ---------------------------------------------------------------------
    // Go Donna, go 
    // ---------------------------------------------------------------------
    // To take into account timer update resolution, we measure time for 100
    // calls
    for (i = 0; i < 10; ++i) 
    {
        int j;
        t1 = TimeNow();
        for (j = 0; j < 100; j++)
            curve25519_donna(donna_publickey, secret_key, ecp_BasePoint);
        t2 = TimeNow() - t1;
        if (t2 < td) td = t2;
    }

    // ---------------------------------------------------------------------
    // Ready, set, go 
    // ---------------------------------------------------------------------
    for (i = 0; i < 10; i++)
    {
        int j;
        t1 = TimeNow();
        for (j = 0; j < 100; j++)
            ecp_PointMultiply(mehdi_publickey, ecp_BasePoint, secret_key, 32);
        t2 = TimeNow() - t1;
        if (t2 < tm) tm = t2;
    }
    printf ("\n    Donna: %lld usec -- ratio: %.3f\n", 
        td/100, (double)td/(double)tm);
    printf ("    Mehdi: %lld usec -- delta: %.2f%%\n", 
        tm/100, (100.0*(td-tm))/(double)td);
#else
    // Timing values that we measure includes some random CPU activity overhead
    // We try to get the minimum time as the more accurate time

    t1 = TimeNow();
    tovr = TimeNow() - t1; // t2-t1 = TimeNow() overhead
    for (i = 0; i < 100; i++)
    {
        t1 = TimeNow();
        t2 = TimeNow() - t1; // t2-t1 = TimeNow() overhead
        if (t2 < tovr) tovr = t2;
    }

    // ---------------------------------------------------------------------
    // Go Donna, go 
    // ---------------------------------------------------------------------
    for (i = 0; i < 1000; ++i) 
    {
        t1 = TimeNow();
        curve25519_donna(donna_publickey, secret_key, ecp_BasePoint);
        t2 = TimeNow() - t1;
        if (t2 < td) td = t2;
    }
    td -= tovr;

    // ---------------------------------------------------------------------
    // Ready, set, go 
    // ---------------------------------------------------------------------
    for (i = 0; i < 1000; i++)
    {
        t1 = TimeNow();
        ecp_PointMultiply(mehdi_publickey, ecp_BasePoint, secret_key, 32);
        t2 = TimeNow() - t1;
        if (t2 < tm) tm = t2;
    }
    tm -= tovr;

    printf ("\n    Donna: %lld cycles = %.3f usec @3.4GHz -- ratio: %.3f\n", 
        td, (double)td/3400.0, (double)td/(double)tm);
    printf ("    Mehdi: %lld cycles = %.3f usec @3.4GHz -- delta: %.2f%%\n", 
        tm, (double)tm/3400.0, (100.0*(td-tm))/(double)td);
#endif
    return 0;
}
