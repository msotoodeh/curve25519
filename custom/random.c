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

/* ---------------------------------------------------------------------
    A high resolution timer/counter accumulates all sort of system 
    entropies because of time shift due to interrupts, exceptions, task 
    switching, cache hit/miss and other event processing.
    Using TSC (Time Stamp Counter) in an accumulative fashion is used 
    here. Accumulation is achieved by using SHA512 hash of the state 
    information and storing it back in to the state again (cascaded 
    hash).
    No need for seeding. Applications normally do a poor job for 
    providing seed. With this RNG, every call to get new random number, 
    adds more entropy. However, it is a good practice to call the 
    RNG_AddEntropy() interface in places that physical or external 
    events are handled like network and user activities and other 
    similar events.
    It is a good practice to save/restore the RNG context across power 
    cycles
 */

#if defined(_MSC_VER)
#include <windows.h>
#if _MSC_VER > 1400
#include <intrin.h>
#endif
#pragma intrinsic(__rdtsc)
#else
#include <sys/time.h>
#endif
#include "sha512.h"


static struct
{
    U64     _tsc;
    U64     _entropy;
#if defined(_MSC_VER)
    SYSTEMTIME _SystemTime;
    LARGE_INTEGER _PerfCounter;
#else
    struct timeval _TimeVal;
    time_t  _SystemTime;
#endif
    U8      _digest[SHA512_DIGEST_LENGTH];

} g_RNG_Context;

void RNG_Reset ()
{
    // Force collection of additional entropy
    g_RNG_Context._entropy = 0;
}

void RNG_AddEntropy (const void *entropy, SZ size)
{
    SHA512_CTX hash;
    SHA512_Init (&hash);

#if defined(_MSC_VER)
    g_RNG_Context._tsc += __rdtsc();
    GetSystemTime( &g_RNG_Context._SystemTime);
    QueryPerformanceCounter( &g_RNG_Context._PerfCounter );
#else
    __asm__ volatile("rdtsc" : "=A" (g_RNG_Context._tsc));
    time( &g_RNG_Context._SystemTime);
    gettimeofday(&g_RNG_Context._TimeVal, 0);
#endif
    g_RNG_Context._entropy += size + 8;

    if (size) SHA512_Update (&hash, entropy, size);

    SHA512_Update (&hash, &g_RNG_Context, sizeof(g_RNG_Context));
    SHA512_Final (g_RNG_Context._digest, &hash);
}

void RNG_Bytes (void *data, SZ size)
{
    int i;
    U8 *p = (U8*)data;

    // Add more entropy for every call
    RNG_AddEntropy (data, size);    // TSC and uninitialized memory

    // Make sure enough entropy collected
    while (g_RNG_Context._entropy < 500) RNG_AddEntropy (0, 0);

    while (size > 0)
    {
        RNG_AddEntropy (&p, sizeof(data)); // heap memory fragmentation

        // Expose only helf of the digest
        for (i = 0; i < (SHA512_DIGEST_LENGTH/2); i++)
        {
            *p++ = g_RNG_Context._digest[i];
            if (--size == 0)
                break;
        }
    }
}

U32 RNG_Int32 ()
{
    U32 r;
    RNG_Bytes (&r, sizeof(r));
    return r;
}