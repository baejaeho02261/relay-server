/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
#ifndef GAME_IMGUI_GUARD_H
#define GAME_IMGUI_GUARD_H

/* The classic Win64 C++ compiler emits the Itanium one-time-init ABI for
   function-local statics, including ImGui's ImFontLoader. Delphi does not
   supply that C++ runtime. Keep the implementation in this object.

   Byte 0 is the ABI completion flag; byte 1 is our per-object lock. Do not
   publish completion until the constructor has finished. No OS calls, TLS,
   allocation or initialization sections are required. Same-static recursive
   initialization is undefined by C++; this is not a recursive lock. */
static_assert(sizeof(long long) == 8 && sizeof(void*) == 8,
              COZY_TEXT_GAME_IMGUI_GUARD_IMGUI_GUARD_RUNTIME_REQUIRES_THE_WIN64_SIZED_ABI_80D3BB7F);
static_assert(__atomic_always_lock_free(1, 0),
              COZY_TEXT_GAME_IMGUI_GUARD_IMGUI_GUARD_RUNTIME_REQUIRES_INLINE_BYTE_ATOMICS_24BB84DC);

extern "C" int __cxa_guard_acquire(long long* guard)
{
    unsigned char* bytes = reinterpret_cast<unsigned char*>(guard);
    for (;;)
    {
        if (__atomic_load_n(bytes, __ATOMIC_ACQUIRE) != 0)
            return 0;
        unsigned char expected = 0;
        if (__atomic_compare_exchange_n(bytes + 1, &expected, 1, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        {
            /* Another initializer may have completed before we took the lock. */
            if (__atomic_load_n(bytes, __ATOMIC_ACQUIRE) != 0)
            {
                __atomic_store_n(bytes + 1, 0, __ATOMIC_RELEASE);
                return 0;
            }
            return 1;
        }
        __builtin_ia32_pause();
    }
}

extern "C" void __cxa_guard_release(long long* guard)
{
    unsigned char* bytes = reinterpret_cast<unsigned char*>(guard);
    __atomic_store_n(bytes, 1, __ATOMIC_RELEASE);
    __atomic_store_n(bytes + 1, 0, __ATOMIC_RELEASE);
}

extern "C" void __cxa_guard_abort(long long* guard)
{
    unsigned char* bytes = reinterpret_cast<unsigned char*>(guard);
    /* Leave completion zero so a subsequent caller retries initialization. */
    __atomic_store_n(bytes + 1, 0, __ATOMIC_RELEASE);
}

#endif
