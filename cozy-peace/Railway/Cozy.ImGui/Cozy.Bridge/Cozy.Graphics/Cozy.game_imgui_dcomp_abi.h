/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
/* DirectComposition's flat Win64 COM ABI, independent of C++ overload layout.
   Classic bcc64 uses Itanium C++ vtables, while the Windows SDK declarations
   assume MSVC's reversed overloaded-method slots. Never invoke the SDK's
   overloaded clip methods directly: float and object overloads otherwise
   dispatch to animation and rectangle methods with incompatible arguments.

   ABI reference: Microsoft windows-rs 0.58.0, DirectComposition/mod.rs,
   IDCompositionRectangleClip_Vtbl and IDCompositionVisual_Vtbl.
   https://github.com/microsoft/windows-rs/blob/0.58.0/crates/libs/windows/src/Windows/Win32/Graphics/DirectComposition/mod.rs
   Git blob: 9e0f070ac30e3c4ad0f72ce81fab7719a9af288b.
   No new API lookup, export, runtime allocation or external dependency. */
#ifndef COZY_GAME_IMGUI_DCOMP_ABI_H
#define COZY_GAME_IMGUI_DCOMP_ABI_H
#include <stddef.h>
#include <stdint.h>
#if defined(_WIN32)
#define GAME_DCOMP_CALL __stdcall
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
/* Portable fixtures deliberately exercise the actual Windows register ABI. */
#define GAME_DCOMP_CALL __attribute__((ms_abi))
#else
#error DirectComposition ABI fixtures require x86-64
#endif

typedef int32_t (GAME_DCOMP_CALL *GameDCompQuery)(void*,const void*,void**);
typedef uint32_t (GAME_DCOMP_CALL *GameDCompReference)(void*);
typedef int32_t (GAME_DCOMP_CALL *GameDCompObject)(void*,void*);
typedef int32_t (GAME_DCOMP_CALL *GameDCompFloat)(void*,float);
typedef int32_t (GAME_DCOMP_CALL *GameDCompData)(void*,const void*);
typedef int32_t (GAME_DCOMP_CALL *GameDCompEnum)(void*,int32_t);
typedef int32_t (GAME_DCOMP_CALL *GameDCompNoArguments)(void*);
typedef int32_t (GAME_DCOMP_CALL *GameDCompAddVisual)(void*,void*,int32_t,void*);

struct GameDCompRectangleClipVTable {
    GameDCompQuery query_interface;
    GameDCompReference add_ref,release;
    GameDCompObject left_animation;
    GameDCompFloat left;
    GameDCompObject top_animation;
    GameDCompFloat top;
    GameDCompObject right_animation;
    GameDCompFloat right;
    GameDCompObject bottom_animation;
    GameDCompFloat bottom;
    GameDCompObject top_left_radius_x_animation;
    GameDCompFloat top_left_radius_x;
    GameDCompObject top_left_radius_y_animation;
    GameDCompFloat top_left_radius_y;
    GameDCompObject top_right_radius_x_animation;
    GameDCompFloat top_right_radius_x;
    GameDCompObject top_right_radius_y_animation;
    GameDCompFloat top_right_radius_y;
    GameDCompObject bottom_left_radius_x_animation;
    GameDCompFloat bottom_left_radius_x;
    GameDCompObject bottom_left_radius_y_animation;
    GameDCompFloat bottom_left_radius_y;
    GameDCompObject bottom_right_radius_x_animation;
    GameDCompFloat bottom_right_radius_x;
    GameDCompObject bottom_right_radius_y_animation;
    GameDCompFloat bottom_right_radius_y;
};
struct GameDCompVisualVTable {
    GameDCompQuery query_interface;
    GameDCompReference add_ref,release;
    GameDCompObject offset_x_animation;
    GameDCompFloat offset_x;
    GameDCompObject offset_y_animation;
    GameDCompFloat offset_y;
    GameDCompObject transform_object;
    GameDCompData transform_matrix;
    GameDCompObject transform_parent,effect;
    GameDCompEnum bitmap_interpolation_mode,border_mode;
    GameDCompObject clip_object;
    GameDCompData clip_rectangle;
    GameDCompObject content;
    GameDCompAddVisual add_visual;
    GameDCompObject remove_visual;
    GameDCompNoArguments remove_all_visuals;
    GameDCompEnum composite_mode;
};
static_assert(sizeof(void*)==8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_ABI_REQUIRES_WIN64_POINTERS_C75097FE);
static_assert(sizeof(GameDCompRectangleClipVTable)==27*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_ABI_SIZE_AD6B2309);
static_assert(sizeof(GameDCompVisualVTable)==20*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_VISUAL_ABI_SIZE_8AE826CA);
static_assert(offsetof(GameDCompRectangleClipVTable,left)==4*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,top)==6*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,right)==8*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,bottom)==10*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,top_left_radius_x)==12*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,top_left_radius_y)==14*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,top_right_radius_x)==16*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,top_right_radius_y)==18*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,bottom_left_radius_x)==20*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,bottom_left_radius_y)==22*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,bottom_right_radius_x)==24*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompRectangleClipVTable,bottom_right_radius_y)==26*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_FLOAT_ABI_SLOT_09D3C9D7);
static_assert(offsetof(GameDCompVisualVTable,clip_object)==13*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_OBJECT_ABI_SLOT_D0D25CA9);
static_assert(offsetof(GameDCompVisualVTable,clip_rectangle)==14*8,COZY_TEXT_GAME_IMGUI_DCOMP_ABI_DIRECTCOMPOSITION_CLIP_RECTANGLE_ABI_SLOT_DFCC145A);

/* Read the COM object's first pointer as bytes to avoid C++ aliasing assumptions
   about a vendor SDK interface and this independently declared flat ABI. */
template<class Table> static const Table* game_dcomp_table(const void* object) noexcept {
    if(!object)return 0;
    const Table* table=0;
    const unsigned char* source=static_cast<const unsigned char*>(object);
    unsigned char* destination=reinterpret_cast<unsigned char*>(&table);
    for(size_t i=0;i<sizeof(table);++i)destination[i]=source[i];
    return table;
}
static int32_t game_dcomp_clip_left(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->left?table->left(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_top(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->top?table->top(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_right(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->right?table->right(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_bottom(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->bottom?table->bottom(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_top_left_radius_x(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->top_left_radius_x?table->top_left_radius_x(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_top_left_radius_y(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->top_left_radius_y?table->top_left_radius_y(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_top_right_radius_x(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->top_right_radius_x?table->top_right_radius_x(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_top_right_radius_y(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->top_right_radius_y?table->top_right_radius_y(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_bottom_left_radius_x(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->bottom_left_radius_x?table->bottom_left_radius_x(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_bottom_left_radius_y(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->bottom_left_radius_y?table->bottom_left_radius_y(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_bottom_right_radius_x(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->bottom_right_radius_x?table->bottom_right_radius_x(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_clip_bottom_right_radius_y(void* object,float value) noexcept {
    const GameDCompRectangleClipVTable* table=game_dcomp_table<GameDCompRectangleClipVTable>(object);
    return table&&table->bottom_right_radius_y?table->bottom_right_radius_y(object,value):static_cast<int32_t>(0x80004003u);
}
static int32_t game_dcomp_visual_clip(void* object,void* clip) noexcept {
    const GameDCompVisualVTable* table=game_dcomp_table<GameDCompVisualVTable>(object);
    return table&&table->clip_object?table->clip_object(object,clip):static_cast<int32_t>(0x80004003u);
}
#endif
