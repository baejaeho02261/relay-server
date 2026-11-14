#ifndef GAME_IMGUI_ARENA_H
#define GAME_IMGUI_ARENA_H
#include <stddef.h>
#include <stdint.h>
/* One context, one committed reservation. No OS/CRT allocation is attempted
   from an ImGui stack frame. Admission bounds live in the C bridge. */
struct alignas(16) GameArenaBlock {
    size_t bytes;
    GameArenaBlock* previous;
    GameArenaBlock* next;
    uint32_t used;
    uint32_t magic;
};
struct GameArena {
    GameArenaBlock* first;
    uintptr_t begin, end;
    size_t live_bytes, peak_bytes, largest_request;
};
static const size_t GameArenaBytes = 64u * 1024u * 1024u;
static const size_t GameFrameReserve = 32u * 1024u * 1024u;
static GameArena game_arena = {};
static void game_arena_init(void* memory) {
    // The caller owns one writable GameArenaBytes reservation for its lifetime.
    // Validate arithmetic/alignment before writing the first block header.
    const uintptr_t begin=reinterpret_cast<uintptr_t>(memory);
    if(!begin||(begin&15u)||begin>UINTPTR_MAX-GameArenaBytes)__builtin_trap();
    game_arena.begin=begin;game_arena.end=begin+GameArenaBytes;
    game_arena.first=static_cast<GameArenaBlock*>(memory);
    game_arena.first->bytes=GameArenaBytes-sizeof(GameArenaBlock);
    game_arena.first->previous=0;game_arena.first->next=0;
    game_arena.first->used=0;game_arena.first->magic=0x47494152u;
    game_arena.live_bytes=0;game_arena.peak_bytes=0;game_arena.largest_request=0;
}
static size_t game_arena_largest() {
    size_t largest=0;
    for(GameArenaBlock* b=game_arena.first;b;b=b->next)
        if(!b->used&&b->bytes>largest)largest=b->bytes;
    return largest;
}
static void* game_arena_alloc(size_t bytes) {
    if(!bytes)bytes=1;
    if(bytes>GameArenaBytes-16)return 0;
    bytes=(bytes+15)&~static_cast<size_t>(15);
    for(GameArenaBlock* b=game_arena.first;b;b=b->next) {
        if(b->used||b->bytes<bytes)continue;
        if(b->bytes-bytes>=sizeof(GameArenaBlock)+16) {
            GameArenaBlock* tail=reinterpret_cast<GameArenaBlock*>(reinterpret_cast<unsigned char*>(b+1)+bytes);
            tail->bytes=b->bytes-bytes-sizeof(GameArenaBlock);tail->previous=b;
            tail->next=b->next;tail->used=0;tail->magic=0x47494152u;
            if(tail->next)tail->next->previous=tail;
            b->next=tail;b->bytes=bytes;
        }
        b->used=1;game_arena.live_bytes+=b->bytes;
        if(game_arena.live_bytes>game_arena.peak_bytes)game_arena.peak_bytes=game_arena.live_bytes;
        if(bytes>game_arena.largest_request)game_arena.largest_request=bytes;
        return b+1;
    }
    return 0;
}
static void game_arena_free(void* memory) {
    if(!memory)return;
    // Never read a header derived from the supplied address. An aligned
    // interior pointer may point after a forged header inside a live payload.
    // Walk the physical partition instead, validating each header before its
    // links can be followed or used for coalescing. No allocation is performed.
    const uintptr_t address=reinterpret_cast<uintptr_t>(memory);
    if(!game_arena.first||!game_arena.begin||(game_arena.begin&15u)||
       game_arena.begin>UINTPTR_MAX-GameArenaBytes||
       game_arena.end!=game_arena.begin+GameArenaBytes||
       reinterpret_cast<uintptr_t>(game_arena.first)!=game_arena.begin||
       (address&15u)||address<game_arena.begin+sizeof(GameArenaBlock)||
       address>=game_arena.end)__builtin_trap();
    GameArenaBlock* b=0;
    GameArenaBlock* previous=0;
    size_t live=0;
    uintptr_t cursor=game_arena.begin;
    while(cursor<game_arena.end) {
        // cursor comes only from the fixed start or a checked block extent.
        if((cursor&15u)||game_arena.end-cursor<sizeof(GameArenaBlock)+16)__builtin_trap();
        GameArenaBlock* current=reinterpret_cast<GameArenaBlock*>(cursor);
        const size_t available=game_arena.end-cursor-sizeof(GameArenaBlock);
        if(current->magic!=0x47494152u||current->used>1||
           current->previous!=previous||!current->bytes||(current->bytes&15u)||
           current->bytes>available)__builtin_trap();
        const uintptr_t next=cursor+sizeof(GameArenaBlock)+current->bytes;
        if((next==game_arena.end&&current->next)||
           (next!=game_arena.end&&reinterpret_cast<uintptr_t>(current->next)!=next))__builtin_trap();
        if(current->used) {
            if(current->bytes>GameArenaBytes-live)__builtin_trap();
            live+=current->bytes;
        }
        if(cursor+sizeof(GameArenaBlock)==address)b=current;
        previous=current;cursor=next;
    }
    if(cursor!=game_arena.end||live!=game_arena.live_bytes||!b||!b->used)__builtin_trap();
    game_arena.live_bytes-=b->bytes;b->used=0;
    if(b->next&&!b->next->used){GameArenaBlock* next=b->next;b->bytes+=sizeof(GameArenaBlock)+next->bytes;b->next=next->next;if(b->next)b->next->previous=b;}
    if(b->previous&&!b->previous->used){GameArenaBlock* previous=b->previous;previous->bytes+=sizeof(GameArenaBlock)+b->bytes;previous->next=b->next;if(previous->next)previous->next->previous=previous;}
}
#endif
