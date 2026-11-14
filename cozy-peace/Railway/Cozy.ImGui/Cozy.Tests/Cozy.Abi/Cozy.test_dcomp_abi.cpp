/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Tests.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
/* Flat COM tables follow Microsoft's Windows metadata, not C++ overload order. */
#include <cassert>
#include <cstdio>
#include <cstdint>
#include "../../Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h"

static void* expected_object=0;
static void* expected_clip=0;
static float expected_value=0;
static unsigned called_slot=0,animation_calls=0,rectangle_calls=0;
struct FakeObject {const uintptr_t* table;};
static int32_t GAME_DCOMP_CALL animation(void* object,void*) {
    assert(object==expected_object);++animation_calls;return -30;
}
template<unsigned Slot> static int32_t GAME_DCOMP_CALL scalar(void* object,float value) {
    assert(object==expected_object);assert(value==expected_value);called_slot=Slot;
    return static_cast<int32_t>(0x80040000u+Slot);
}
static int32_t GAME_DCOMP_CALL clip_object(void* object,void* clip) {
    assert(object==expected_object);assert(clip==expected_clip);called_slot=13;return -130;
}
static int32_t GAME_DCOMP_CALL clip_rectangle(void* object,const void*) {
    assert(object==expected_object);++rectangle_calls;return -140;
}
static int32_t GAME_DCOMP_CALL unrelated(void*) {assert(false);return -1;}

// Independent ABI fixture: IUnknown0..2; animation3,5,...25; scalar4,6,...26.
// These slots come from Microsoft Windows-rs IDCompositionRectangleClip_Vtbl.
static uintptr_t clip_table[27];
static uintptr_t visual_table[20];
#define FLOAT_ENTRY(slot) reinterpret_cast<uintptr_t>(&scalar<slot>)
static const uintptr_t scalar_functions[]={FLOAT_ENTRY(4),FLOAT_ENTRY(6),FLOAT_ENTRY(8),FLOAT_ENTRY(10),FLOAT_ENTRY(12),FLOAT_ENTRY(14),FLOAT_ENTRY(16),FLOAT_ENTRY(18),FLOAT_ENTRY(20),FLOAT_ENTRY(22),FLOAT_ENTRY(24),FLOAT_ENTRY(26)};
typedef int32_t (*FloatWrapper)(void*,float);
static const FloatWrapper wrappers[]={game_dcomp_clip_left,game_dcomp_clip_top,game_dcomp_clip_right,game_dcomp_clip_bottom,game_dcomp_clip_top_left_radius_x,game_dcomp_clip_top_left_radius_y,game_dcomp_clip_top_right_radius_x,game_dcomp_clip_top_right_radius_y,game_dcomp_clip_bottom_left_radius_x,game_dcomp_clip_bottom_left_radius_y,game_dcomp_clip_bottom_right_radius_x,game_dcomp_clip_bottom_right_radius_y};

// Negative control reproduces the SDK's MSVC-oriented overload declarations
// under an Itanium-layout C++ compiler, as in the uploaded classic bcc64 ELF.
struct LegacyClip {
    virtual int32_t GAME_DCOMP_CALL Query()=0;
    virtual int32_t GAME_DCOMP_CALL AddRef()=0;
    virtual int32_t GAME_DCOMP_CALL Release()=0;
    virtual int32_t GAME_DCOMP_CALL SetLeft(float)=0;
    virtual int32_t GAME_DCOMP_CALL SetLeft(void*)=0;
};
struct Rect {float left,top,right,bottom;};
struct LegacyVisual {
    virtual int32_t GAME_DCOMP_CALL Query()=0;
    virtual int32_t GAME_DCOMP_CALL AddRef()=0;
    virtual int32_t GAME_DCOMP_CALL Release()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix3()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix4()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix5()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix6()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix7()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix8()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix9()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix10()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix11()=0;
    virtual int32_t GAME_DCOMP_CALL Prefix12()=0;
    virtual int32_t GAME_DCOMP_CALL SetClip(const Rect&)=0;
    virtual int32_t GAME_DCOMP_CALL SetClip(void*)=0;
};
static __attribute__((noinline)) int32_t legacy_left(void* object) {return reinterpret_cast<LegacyClip*>(object)->SetLeft(680.0f);}
static __attribute__((noinline)) int32_t legacy_clip(void* object,void* clip) {return reinterpret_cast<LegacyVisual*>(object)->SetClip(clip);}
int main() {
    for(unsigned n=0;n<27;++n)clip_table[n]=reinterpret_cast<uintptr_t>(&unrelated);
    for(unsigned n=0;n<12;++n){clip_table[3+n*2]=reinterpret_cast<uintptr_t>(&animation);clip_table[4+n*2]=scalar_functions[n];}
    for(unsigned n=0;n<20;++n)visual_table[n]=reinterpret_cast<uintptr_t>(&unrelated);
    visual_table[13]=reinterpret_cast<uintptr_t>(&clip_object);
    visual_table[14]=reinterpret_cast<uintptr_t>(&clip_rectangle);
    FakeObject clip={clip_table},visual={visual_table};
    expected_object=&clip;
    for(unsigned n=0;n<12;++n){
        expected_value=static_cast<float>(n)*0.5f+0.25f;called_slot=0;
        assert(wrappers[n](&clip,expected_value)==static_cast<int32_t>(0x80040000u+4+n*2));
        assert(called_slot==4+n*2);assert(animation_calls==0);
    }
    expected_object=&visual;expected_clip=&clip;
    assert(game_dcomp_visual_clip(&visual,&clip)==-130);assert(called_slot==13);assert(rectangle_calls==0);
    expected_clip=0;assert(game_dcomp_visual_clip(&visual,0)==-130);assert(called_slot==13);
    FakeObject missing={0};
    for(unsigned n=0;n<12;++n){assert(wrappers[n](0,1)==static_cast<int32_t>(0x80004003u));assert(wrappers[n](&missing,1)==static_cast<int32_t>(0x80004003u));}
    assert(game_dcomp_visual_clip(0,&clip)==static_cast<int32_t>(0x80004003u));
    assert(game_dcomp_visual_clip(&missing,&clip)==static_cast<int32_t>(0x80004003u));
#if !defined(_MSC_VER)
    expected_object=&clip;
    assert(legacy_left(&clip)==-30);assert(animation_calls==1);
    expected_object=&visual;
    assert(legacy_clip(&visual,&clip)==-140);assert(rectangle_calls==1);
#endif
    for(unsigned n=0;n<12;++n){clip_table[4+n*2]=0;assert(wrappers[n](&clip,1)==static_cast<int32_t>(0x80004003u));}
    visual_table[13]=0;assert(game_dcomp_visual_clip(&visual,&clip)==static_cast<int32_t>(0x80004003u));
    std::puts(COZY_TEXT_TEST_DCOMP_ABI_DCOMP_ABI_PASS_12_FLOAT_SLOTS_OBJECT_CLIP_SLOT_W_BFE1E5E0);
}
