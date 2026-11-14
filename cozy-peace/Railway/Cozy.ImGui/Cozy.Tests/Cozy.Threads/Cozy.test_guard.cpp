/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Tests.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
/* Portable runtime test, not linked into O. Compile with normal local-static
   guards enabled and link this test with Cozy.game_imgui_bridge's portable object. */
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int __cxa_guard_acquire(long long*);
extern "C" void __cxa_guard_release(long long*);
extern "C" void __cxa_guard_abort(long long*);

static void check(bool ok, const char* message)
{
    if (!ok) { fprintf(stderr, COZY_TEXT_TEST_GUARD_FAIL_S_N_F80BB318, message); exit(1); }
}

static int constructors = 0, start = 0, ready = 0, errors = 0;
struct OnceValue
{
    int values[64];
    OnceValue()
    {
        __atomic_add_fetch(&constructors, 1, __ATOMIC_RELAXED);
        for (int i = 0; i < 64; ++i)
        {
            values[i] = 700 + i;
            sched_yield();
        }
    }
};
static const OnceValue& actual_static()
{
    static OnceValue value;
    return value;
}
static void* race_static(void*)
{
    __atomic_add_fetch(&ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&start, __ATOMIC_ACQUIRE)) sched_yield();
    const OnceValue& value = actual_static();
    for (int i = 0; i < 64; ++i)
        if (value.values[i] != 700 + i)
            __atomic_add_fetch(&errors, 1, __ATOMIC_RELAXED);
    return 0;
}

static long long abort_guard = 0;
static int waiter_started = 0, waiter_entered = 0;
static void* retry_after_abort(void*)
{
    __atomic_store_n(&waiter_started, 1, __ATOMIC_RELEASE);
    if (__cxa_guard_acquire(&abort_guard))
    {
        __atomic_store_n(&waiter_entered, 1, __ATOMIC_RELEASE);
        __cxa_guard_release(&abort_guard);
    }
    return 0;
}

int main()
{
    long long guard = 0;
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&guard);
    check(__cxa_guard_acquire(&guard) == 1, COZY_TEXT_TEST_GUARD_FIRST_CALLER_OWNS_INITIALIZATION_54D6D5CF);
    check(bytes[0] == 0, COZY_TEXT_TEST_GUARD_ACQUIRE_MUST_NOT_PUBLISH_COMPLETION_42F6D72D);
    __cxa_guard_abort(&guard);
    check(bytes[0] == 0, COZY_TEXT_TEST_GUARD_ABORT_KEEPS_INITIALIZATION_INCOMPLETE_B464BC53);
    check(__cxa_guard_acquire(&guard) == 1, COZY_TEXT_TEST_GUARD_ABORTED_INITIALIZATION_CAN_RETRY_9871F568);
    __cxa_guard_release(&guard);
    check(bytes[0] == 1, COZY_TEXT_TEST_GUARD_RELEASE_PUBLISHES_ABI_COMPLETION_BYTE_80D315C4);
    check(__cxa_guard_acquire(&guard) == 0, COZY_TEXT_TEST_GUARD_COMPLETED_INITIALIZATION_IS_SKIPPED_8B599CE5);

    // Per-object locks allow one initializer to use a different local static.
    long long outer = 0, inner = 0;
    check(__cxa_guard_acquire(&outer) == 1, COZY_TEXT_TEST_GUARD_OUTER_INITIALIZATION_ACQUIRED_40357D73);
    check(__cxa_guard_acquire(&inner) == 1, COZY_TEXT_TEST_GUARD_DIFFERENT_NESTED_GUARD_ACQUIRED_97BEA20E);
    __cxa_guard_release(&inner);
    __cxa_guard_release(&outer);

    const int count = 16;
    pthread_t threads[count];
    for (int i = 0; i < count; ++i)
        check(pthread_create(&threads[i], 0, race_static, 0) == 0, COZY_TEXT_TEST_GUARD_CREATE_RACE_THREAD_170BAA32);
    while (__atomic_load_n(&ready, __ATOMIC_ACQUIRE) != count) sched_yield();
    __atomic_store_n(&start, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < count; ++i)
        check(pthread_join(threads[i], 0) == 0, COZY_TEXT_TEST_GUARD_JOIN_RACE_THREAD_4DB7BA80);
    check(constructors == 1, COZY_TEXT_TEST_GUARD_COMPILER_GENERATED_GUARD_CONSTRUCTS_EXACTLY_ONCE_75B402F7);
    check(errors == 0, COZY_TEXT_TEST_GUARD_ALL_THREADS_SEE_FULLY_INITIALIZED_PAYLOAD_5A435556);

    check(__cxa_guard_acquire(&abort_guard) == 1, COZY_TEXT_TEST_GUARD_HOLD_GUARD_BEFORE_ABORT_13FEFC83);
    pthread_t waiter;
    check(pthread_create(&waiter, 0, retry_after_abort, 0) == 0, COZY_TEXT_TEST_GUARD_CREATE_ABORT_WAITER_9821B3CD);
    while (!__atomic_load_n(&waiter_started, __ATOMIC_ACQUIRE)) sched_yield();
    for (int i = 0; i < 1000; ++i) sched_yield();
    check(__atomic_load_n(&waiter_entered, __ATOMIC_ACQUIRE) == 0,
          COZY_TEXT_TEST_GUARD_SECOND_CALLER_CANNOT_ENTER_AN_UNFINISHED_INITIAL_214B08F9);
    __cxa_guard_abort(&abort_guard);
    check(pthread_join(waiter, 0) == 0, COZY_TEXT_TEST_GUARD_JOIN_ABORT_WAITER_0972C39C);
    check(waiter_entered == 1, COZY_TEXT_TEST_GUARD_WAITING_CALLER_RETRIES_AFTER_ABORT_758D7F3A);
    check(__cxa_guard_acquire(&abort_guard) == 0, COZY_TEXT_TEST_GUARD_RETRY_PUBLISHES_COMPLETION_5CE91705);
    puts(COZY_TEXT_TEST_GUARD_PASS_GUARD_ABI_BYTES_ABORT_RETRY_NESTED_GUARDS_1_ED29E6FD);
}
