/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Tests.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
// Exercises actual allocation/split/coalesce implementation independently.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include "../../Cozy.Bridge/Cozy.Memory/Cozy.game_imgui_arena.h"
static unsigned checks=0;
static void check(bool ok){++checks;if(!ok){fprintf(stderr,COZY_TEXT_TEST_ARENA_FAIL_ARENA_AT_CHECK_U_N_7CF88629,checks);exit(1);}}
static unsigned fault_cases=0;
static void fragmentation(uint32_t seed,unsigned pattern){
    void* reservation=malloc(GameArenaBytes);check(reservation!=0);game_arena_init(reservation);
    struct Slot{void* p;size_t n;unsigned char value;} slots[1024]={};uint32_t state=seed;
    for(unsigned step=0;step<30000;++step){
        state^=state<<13;state^=state>>17;state^=state<<5;Slot& slot=slots[state%1024];
        if(slot.p){
            const unsigned char* p=static_cast<const unsigned char*>(slot.p);
            for(size_t j=0;j<slot.n;++j)if(p[j]!=slot.value)check(false);
            check(true);game_arena_free(slot.p);slot.p=0;
        }else{
            slot.n=16+((state>>10)%65536);
            if(pattern==1)slot.n=1+((state>>10)%4096);
            if(pattern==2)slot.n=(state&1)?16:65536;
            slot.value=static_cast<unsigned char>(state);
            slot.p=game_arena_alloc(slot.n);check(slot.p!=0);check((reinterpret_cast<uintptr_t>(slot.p)&15)==0);
            memset(slot.p,slot.value,slot.n);
        }
    }
    for(unsigned i=0;i<1024;++i)if(slots[i].p)game_arena_free(slots[i].p);
    check(game_arena.live_bytes==0);check(game_arena_largest()==GameArenaBytes-sizeof(GameArenaBlock));
    check(game_arena.first->previous==0&&game_arena.first->next==0);
    check(!game_arena_alloc(SIZE_MAX));check(!game_arena_alloc(GameArenaBytes));
    check(!game_arena_alloc(GameArenaBytes-1));
    void* zero=game_arena_alloc(0);check(zero!=0);check(game_arena.live_bytes==16);game_arena_free(zero);
    game_arena_free(0);check(game_arena.live_bytes==0);
    void* all=game_arena_alloc(game_arena_largest());check(all!=0);check(!game_arena_alloc(1));
    game_arena_free(all);check(game_arena.live_bytes==0);free(reservation);
    game_arena={};
}

// Fault children must terminate at the allocator's explicit trap, never by a
// guessed-pointer read/write fault. Core files and Windows crash dialogs are
// disabled only in these test children; production code has no test hook.
static int fault_child(const char* name){
#if defined(_WIN32)
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
#else
    const rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core)!=0)return 65;
#endif
    if(!strcmp(name,COZY_TEXT_TEST_ARENA_UNINITIALIZED_50E37E06)){game_arena_free(reinterpret_cast<void*>(uintptr_t(16)));return 66;}
    if(!strcmp(name,COZY_TEXT_TEST_ARENA_INIT_NULL_9005F6AE)){game_arena_init(0);return 66;}
    if(!strcmp(name,COZY_TEXT_TEST_ARENA_INIT_OVERFLOW_8EAA6D2E)){game_arena_init(reinterpret_cast<void*>(UINTPTR_MAX&~uintptr_t(15)));return 66;}
    void* reservation=malloc(GameArenaBytes);if(!reservation)return 65;
    if(!strcmp(name,COZY_TEXT_TEST_ARENA_INIT_MISALIGNED_C58DB539)){game_arena_init(static_cast<unsigned char*>(reservation)+1);return 66;}
    game_arena_init(reservation);
    void* a=game_arena_alloc(256);void* b=game_arena_alloc(256);void* c=game_arena_alloc(256);
    if(!a||!b||!c)return 65;
    if(!strcmp(name,COZY_TEXT_TEST_ARENA_LOW_ADDRESS_05841FFB))game_arena_free(reinterpret_cast<void*>(uintptr_t(1)));
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_ARENA_HEADER_02B17FA3))game_arena_free(reservation);
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_ONE_PAST_END_869EEBED))game_arena_free(reinterpret_cast<void*>(game_arena.end));
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_BEFORE_START_FC63736C))game_arena_free(reinterpret_cast<void*>(game_arena.begin-16));
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_STACK_CC3C3B88)){alignas(16) unsigned char other[64]={};game_arena_free(other);}
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_FOREIGN_RESERVATION_8F5FC6E7)){void* other=malloc(GameArenaBytes);if(!other)return 65;game_arena_free(static_cast<unsigned char*>(other)+sizeof(GameArenaBlock));}
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_MISALIGNED_C61DA259))game_arena_free(static_cast<unsigned char*>(b)+1);
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_ALIGNED_INTERIOR_197162C4))game_arena_free(static_cast<unsigned char*>(b)+16);
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_FORGED_INTERIOR_HEADER_E21BD749)){
        GameArenaBlock* fake=static_cast<GameArenaBlock*>(b);
        fake->bytes=16;fake->previous=0;fake->next=0;fake->used=1;fake->magic=0x47494152u;
        game_arena_free(fake+1);
    }
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_DOUBLE_FREE_CD454A59)){game_arena_free(b);game_arena_free(b);}
    else if(!strcmp(name,COZY_TEXT_TEST_ARENA_COALESCED_DOUBLE_FREE_F7556026)){game_arena_free(a);game_arena_free(b);game_arena_free(b);}
    else {
        GameArenaBlock* header=static_cast<GameArenaBlock*>(b)-1;
        if(!strcmp(name,COZY_TEXT_TEST_ARENA_CORRUPT_MAGIC_3EDFE67D))header->magic=0;
        else if(!strcmp(name,COZY_TEXT_TEST_ARENA_CORRUPT_SIZE_FF300D0C))header->bytes=SIZE_MAX;
        else if(!strcmp(name,COZY_TEXT_TEST_ARENA_CORRUPT_ALIGNED_SIZE_CF138F6D))header->bytes=GameArenaBytes;
        else if(!strcmp(name,COZY_TEXT_TEST_ARENA_CORRUPT_NEXT_92F60CC2))header->next=reinterpret_cast<GameArenaBlock*>(uintptr_t(1));
        else if(!strcmp(name,COZY_TEXT_TEST_ARENA_CORRUPT_PREVIOUS_7E769F90))header->previous=reinterpret_cast<GameArenaBlock*>(uintptr_t(1));
        else if(!strcmp(name,COZY_TEXT_TEST_ARENA_CORRUPT_USED_E9932EE6))header->used=2;
        else if(!strcmp(name,COZY_TEXT_TEST_ARENA_CORRUPT_ACCOUNTING_0E491762))game_arena.live_bytes=0;
        else return 64;
        game_arena_free(b);
    }
    return 66; // Reaching here means an invalid input was incorrectly accepted.
}
static void expect_trap(const char* executable,const char* name){
#if defined(_WIN32)
    const char* args[]={executable,COZY_TEXT_TEST_ARENA_FAULT_A019442F,name,0};
    const intptr_t status=_spawnv(_P_WAIT,executable,args);
    check(status!=-1&&static_cast<uint32_t>(status)==0xC000001Du);
#else
    const pid_t child=fork();check(child>=0);
    if(child==0){execl(executable,executable,COZY_TEXT_TEST_ARENA_FAULT_A019442F,name,static_cast<char*>(0));_exit(64);}
    int status=0;pid_t waited;
    do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    check(waited==child);check(WIFSIGNALED(status)&&WTERMSIG(status)==SIGILL);
#endif
    ++fault_cases;
}
int main(int argc,char** argv){
    if(argc==3&&!strcmp(argv[1],COZY_TEXT_TEST_ARENA_FAULT_A019442F))return fault_child(argv[2]);
    const bool benchmark=argc==2&&!strcmp(argv[1],COZY_TEXT_TEST_ARENA_BENCHMARK_D4ABEC4F);
    if(argc!=1&&!benchmark)return 64;
    fragmentation(0x581CA76Du,0); // Preserve the original 30,000-step trace.
    if(!benchmark){
        fragmentation(0xA5C39E17u,0);fragmentation(0x13579BDFu,1);fragmentation(0xC001D00Du,2);
        const char* cases[]={COZY_TEXT_TEST_ARENA_UNINITIALIZED_50E37E06,COZY_TEXT_TEST_ARENA_INIT_NULL_9005F6AE,COZY_TEXT_TEST_ARENA_INIT_OVERFLOW_8EAA6D2E,COZY_TEXT_TEST_ARENA_INIT_MISALIGNED_C58DB539,
            COZY_TEXT_TEST_ARENA_LOW_ADDRESS_05841FFB,COZY_TEXT_TEST_ARENA_ARENA_HEADER_02B17FA3,COZY_TEXT_TEST_ARENA_ONE_PAST_END_869EEBED,COZY_TEXT_TEST_ARENA_BEFORE_START_FC63736C,COZY_TEXT_TEST_ARENA_STACK_CC3C3B88,COZY_TEXT_TEST_ARENA_FOREIGN_RESERVATION_8F5FC6E7,
            COZY_TEXT_TEST_ARENA_MISALIGNED_C61DA259,COZY_TEXT_TEST_ARENA_ALIGNED_INTERIOR_197162C4,COZY_TEXT_TEST_ARENA_FORGED_INTERIOR_HEADER_E21BD749,COZY_TEXT_TEST_ARENA_DOUBLE_FREE_CD454A59,COZY_TEXT_TEST_ARENA_COALESCED_DOUBLE_FREE_F7556026,
            COZY_TEXT_TEST_ARENA_CORRUPT_MAGIC_3EDFE67D,COZY_TEXT_TEST_ARENA_CORRUPT_SIZE_FF300D0C,COZY_TEXT_TEST_ARENA_CORRUPT_ALIGNED_SIZE_CF138F6D,COZY_TEXT_TEST_ARENA_CORRUPT_NEXT_92F60CC2,COZY_TEXT_TEST_ARENA_CORRUPT_PREVIOUS_7E769F90,
            COZY_TEXT_TEST_ARENA_CORRUPT_USED_E9932EE6,COZY_TEXT_TEST_ARENA_CORRUPT_ACCOUNTING_0E491762};
        for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i)expect_trap(argv[0],cases[i]);
    }
    printf(COZY_TEXT_TEST_ARENA_PASS_ARENA_U_ALLOCATION_FRAGMENTATION_OWNERSHIP__B342EAE1,checks,fault_cases);
}
