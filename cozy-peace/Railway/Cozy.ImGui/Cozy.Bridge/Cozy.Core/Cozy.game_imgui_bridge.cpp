/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
/* Delphi host for the attached Dear ImGui 1.93 core.  This translation unit is
   linked into Cozy.Overlay.exe, never loaded as a separate DLL. */
#include "Cozy.game_imgui_bridge.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <stdint.h>
#include "../Cozy.Memory/Cozy.game_imgui_guard.h"
#include "../Cozy.Memory/Cozy.game_imgui_arena.h"
#include "../Cozy.Memory/Cozy.game_imgui_fp.h"
#include "../Cozy.Graphics/Cozy.game_imgui_texture.h"
#ifndef GAME_IMGUI_PORTABLE_TEST
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi1_2.h>
#include <dcomp.h>
#include "../Cozy.Graphics/Cozy.game_imgui_dcomp_abi.h"
#endif

static_assert(sizeof(GameImGuiHost)==32, COZY_TEXT_GAME_IMGUI_BRIDGE_THIS_BRIDGE_IS_FOR_64_BIT_HOSTS_ONLY_DF287FCF);
static GameImGuiHost game_imgui_host = {};
static bool game_imgui_runtime_failed = false;
static bool game_imgui_dx11_failed = false;
/* Preserve the first failed HRESULT across backend cleanup, so a device-loss
   or GPU allocation failure is not reduced to an undifferentiated Boolean. */
static int32_t game_imgui_dx11_error = 0;
#ifdef GAME_IMGUI_FAULT_TESTS
static int game_test_fault_stage=0;
static int32_t game_test_fault_hresult=0;
extern "C" void game_imgui_test_fault(int stage,int32_t error){game_test_fault_stage=stage;game_test_fault_hresult=error;}
static int32_t game_fault_result(int stage,int32_t actual){return game_test_fault_stage==stage?game_test_fault_hresult:actual;}
#else
static int32_t game_fault_result(int,int32_t actual){return actual;}
#endif
static int32_t game_dx11_result(int32_t result) {
    if (result < 0) {
        if (game_imgui_dx11_error == 0) game_imgui_dx11_error = result;
        game_imgui_dx11_failed = true;
    }
    return result;
}
static __attribute__((noreturn)) void game_imgui_assert_failed() { __builtin_trap(); }
/* Preserve compiler canary checks while providing their terminal failure path
   without a C runtime import. This never returns and never accepts a mismatch. */
extern "C" __attribute__((noreturn)) void __stack_chk_fail(void) { game_imgui_assert_failed(); }
template<class T> static T game_proc(int32_t id) {
    void* value = game_imgui_host.get_proc ? game_imgui_host.get_proc(id) : 0;
    if (!value) game_imgui_runtime_failed = true;
    return reinterpret_cast<T>(value);
}
/* A function pointer is decoded for this call only; no decoded API address is
   retained in native globals, ImGui IO or the renderer context. */
static void* game_memcpy(void* dst, const void* src, size_t n) {
    volatile unsigned char* d = static_cast<volatile unsigned char*>(dst);
    const volatile unsigned char* s = static_cast<const volatile unsigned char*>(src);
    for (size_t i=0; i<n; ++i) d[i]=s[i]; return dst;
}
static void* game_memmove(void* dst, const void* src, size_t n) {
    volatile unsigned char* d = static_cast<volatile unsigned char*>(dst);
    const volatile unsigned char* s = static_cast<const volatile unsigned char*>(src);
    if (reinterpret_cast<uintptr_t>(d) < reinterpret_cast<uintptr_t>(s))
        for(size_t i=0;i<n;++i) d[i]=s[i];
    else if(d!=s) for(size_t i=n;i>0;--i) d[i-1]=s[i-1]; return dst;
}
static void* game_memset(void* dst, int value, size_t n) {
    volatile unsigned char* d = static_cast<volatile unsigned char*>(dst);
    for(size_t i=0;i<n;++i) d[i]=static_cast<unsigned char>(value); return dst;
}
static int game_memcmp(const void* a,const void* b,size_t n) {
    const unsigned char* x=static_cast<const unsigned char*>(a); const unsigned char* y=static_cast<const unsigned char*>(b);
    for(size_t i=0;i<n;++i) if(x[i]!=y[i]) return x[i]<y[i]?-1:1; return 0;
}
static void* game_memchr(const void* s,int value,size_t n) {
    const unsigned char* p=static_cast<const unsigned char*>(s);
    for(size_t i=0;i<n;++i) if(p[i]==static_cast<unsigned char>(value)) return const_cast<unsigned char*>(p+i); return 0;
}
static size_t game_strlen(const char* s) { size_t n=0; while(s[n])++n;return n; }
static int game_strcmp(const char* a,const char* b) { while(*a && *a==*b){++a;++b;}return static_cast<unsigned char>(*a)-static_cast<unsigned char>(*b); }
static int game_strncmp(const char* a,const char* b,size_t n) { for(size_t i=0;i<n;++i){unsigned char x=a[i],y=b[i];if(x!=y)return x-y;if(!x)return 0;}return 0; }
static char* game_strncpy(char* d,const char* s,size_t n) {size_t i=0;for(;i<n && s[i];++i)d[i]=s[i];for(;i<n;++i)d[i]=0;return d;}
static char* game_strcpy(char* d,const char* s) {size_t i=0;do{d[i]=s[i];}while(s[i++]);return d;}
static const char* game_strchr(const char* s,int c) {do{if(*s==static_cast<char>(c))return s;}while(*s++);return 0;}
static char* game_strchr(char* s,int c){return const_cast<char*>(game_strchr(static_cast<const char*>(s),c));}
/* In-place heapsort: bounded O(n log n), no allocation or C runtime dependency. */
typedef int (GAME_IMGUI_CALL *GameCompare)(const void*,const void*);
static void game_swap(unsigned char* a,unsigned char* b,size_t n){for(size_t i=0;i<n;++i){unsigned char v=a[i];a[i]=b[i];b[i]=v;}}
static void game_sift(unsigned char* base,size_t root,size_t count,size_t stride,GameCompare compare){
    while(root<count/2){size_t child=root*2+1;if(child+1<count && compare(base+child*stride,base+(child+1)*stride)<0)++child;
    if(compare(base+root*stride,base+child*stride)>=0)return;game_swap(base+root*stride,base+child*stride,stride);root=child;}
}
static void game_qsort(void* base,size_t count,size_t stride,GameCompare compare){
    if(count<2 || !stride)return;unsigned char* p=static_cast<unsigned char*>(base);
    for(size_t i=count/2;i>0;--i)game_sift(p,i-1,count,stride,compare);
    for(size_t end=count;end>1;--end){game_swap(p,p+(end-1)*stride,stride);game_sift(p,0,end-1,stride,compare);}
}
typedef double (GAME_IMGUI_CALL *GameUnary)(double);
typedef double (GAME_IMGUI_CALL *GameBinary)(double,double);
static double game_unary(int id,double a){GameUnary p=game_proc<GameUnary>(id);return p?p(a):0.0;}
static double game_binary(int id,double a,double b){GameBinary p=game_proc<GameBinary>(id);return p?p(a,b):0.0;}
#define GAME_UNARY(name,id) static double game_##name(double x){return game_unary(id,x);} static float game_##name##f(float x){return static_cast<float>(game_unary(id,x));}
#define GAME_BINARY(name,id) static double game_##name(double x,double y){return game_binary(id,x,y);} static float game_##name##f(float x,float y){return static_cast<float>(game_binary(id,x,y));}
GAME_UNARY(acos,GI_PROC_ACOS)
GAME_UNARY(ceil,GI_PROC_CEIL)
GAME_UNARY(cos,GI_PROC_COS)
GAME_UNARY(fabs,GI_PROC_FABS)
GAME_UNARY(floor,GI_PROC_FLOOR)
GAME_UNARY(log,GI_PROC_LOG)
GAME_UNARY(sin,GI_PROC_SIN)
GAME_UNARY(sqrt,GI_PROC_SQRT)
GAME_BINARY(atan2,GI_PROC_ATAN2)
GAME_BINARY(fmod,GI_PROC_FMOD)
GAME_BINARY(pow,GI_PROC_POW)
static double game_strtod(const char* s,char** end){typedef double(GAME_IMGUI_CALL* F)(const char*,char**);F p=game_proc<F>(GI_PROC_STRTOD);return p?p(s,end):0.0;}
static double game_atof(const char* s){return game_strtod(s,0);}
static int game_atoi(const char* s){
    bool negative=false;uint32_t value=0;
    while(*s==' ' || (*s>='\t' && *s<='\r'))++s;
    if(*s=='-' || *s=='+'){negative=*s=='-';++s;}
    const uint32_t limit=negative?2147483648u:2147483647u;
    while(*s>='0' && *s<='9'){
        const uint32_t digit=static_cast<uint32_t>(*s++-'0');
        if(value>(limit-digit)/10u)return negative?INT_MIN:INT_MAX;
        value=value*10u+digit;
    }
    if(negative && value==2147483648u)return INT_MIN;
    return negative?-static_cast<int>(value):static_cast<int>(value);
}
/* UCRT common entry points accept the native Win64 va_list. Options=2 gives
   standard snprintf length/termination semantics, including (NULL,0) queries. */
static int game_vsnprintf(char* buffer,size_t size,const char* format,va_list args){
    typedef int(GAME_IMGUI_CALL* F)(uint64_t,char*,size_t,const char*,void*,va_list);
    F p=game_proc<F>(GI_PROC_CRT_VSPRINTF);if(!p){if(buffer && size)buffer[0]=0;return -1;}return p(2,buffer,size,format,0,args);
}
static int game_sscanf(const char* buffer,const char* format,...){
    typedef int(GAME_IMGUI_CALL* F)(uint64_t,const char*,size_t,const char*,void*,va_list);
    F p=game_proc<F>(GI_PROC_CRT_VSSCANF);if(!p)return 0;
    va_list args;va_start(args,format);int result=p(0,buffer,static_cast<size_t>(-1),format,0,args);va_end(args);return result;
}
#ifndef GAME_IMGUI_PORTABLE_TEST
static HRESULT WINAPI game_d3d_compile(LPCVOID source,SIZE_T size,LPCSTR source_name,
 const D3D_SHADER_MACRO* defines,ID3DInclude* include,LPCSTR entry,LPCSTR target,
 UINT flags1,UINT flags2,ID3DBlob** code,ID3DBlob** errors){
    typedef HRESULT(WINAPI* F)(LPCVOID,SIZE_T,LPCSTR,const D3D_SHADER_MACRO*,ID3DInclude*,LPCSTR,LPCSTR,UINT,UINT,ID3DBlob**,ID3DBlob**);
    F p=game_proc<F>(GI_PROC_D3D_COMPILE);return p?p(source,size,source_name,defines,include,entry,target,flags1,flags2,code,errors):E_FAIL;
}
#endif
/* Redirect calls only. Embarcadero math.h re-emits namespace using-declarations
   on a repeated include, outside its declaration guard. Object-like aliases
   rewrite `using std::acos;` to the nonexistent `std::game_acos`.
   Function-like aliases leave bare names intact while preserving callback calls.
   Standard/system declarations must still be parsed before these aliases. */
#define memcpy(...) game_memcpy(__VA_ARGS__)
#define memmove(...) game_memmove(__VA_ARGS__)
#define memset(...) game_memset(__VA_ARGS__)
#define memcmp(...) game_memcmp(__VA_ARGS__)
#define memchr(...) game_memchr(__VA_ARGS__)
#define strlen(...) game_strlen(__VA_ARGS__)
#define strcmp(...) game_strcmp(__VA_ARGS__)
#define strncmp(...) game_strncmp(__VA_ARGS__)
#define strncpy(...) game_strncpy(__VA_ARGS__)
#define strcpy(...) game_strcpy(__VA_ARGS__)
#define strchr(...) game_strchr(__VA_ARGS__)
#define qsort(...) game_qsort(__VA_ARGS__)
#define acos(...) game_acos(__VA_ARGS__)
#define acosf(...) game_acosf(__VA_ARGS__)
#define atan2(...) game_atan2(__VA_ARGS__)
#define atan2f(...) game_atan2f(__VA_ARGS__)
#define ceil(...) game_ceil(__VA_ARGS__)
#define ceilf(...) game_ceilf(__VA_ARGS__)
#define cos(...) game_cos(__VA_ARGS__)
#define cosf(...) game_cosf(__VA_ARGS__)
#define fabs(...) game_fabs(__VA_ARGS__)
#define fabsf(...) game_fabsf(__VA_ARGS__)
#define floor(...) game_floor(__VA_ARGS__)
#define floorf(...) game_floorf(__VA_ARGS__)
#define fmod(...) game_fmod(__VA_ARGS__)
#define fmodf(...) game_fmodf(__VA_ARGS__)
#define log(...) game_log(__VA_ARGS__)
#define logf(...) game_logf(__VA_ARGS__)
#define pow(...) game_pow(__VA_ARGS__)
#define powf(...) game_powf(__VA_ARGS__)
#define sin(...) game_sin(__VA_ARGS__)
#define sinf(...) game_sinf(__VA_ARGS__)
#define sqrt(...) game_sqrt(__VA_ARGS__)
#define sqrtf(...) game_sqrtf(__VA_ARGS__)
#define strtod(...) game_strtod(__VA_ARGS__)
#define atof(...) game_atof(__VA_ARGS__)
#define atoi(...) game_atoi(__VA_ARGS__)
#define vsnprintf(...) game_vsnprintf(__VA_ARGS__)
#define sscanf(...) game_sscanf(__VA_ARGS__)
#define IMGUI_USER_CONFIG "../../Cozy.Bridge/Cozy.Core/Cozy.game_imgui_config.h"
#include "../../Cozy.Vendor/Cozy.Core/Cozy.imgui.cpp"
#include "../../Cozy.Vendor/Cozy.Drawing/Cozy.imgui_draw.cpp"
#include "../../Cozy.Vendor/Cozy.Tables/Cozy.imgui_tables.cpp"
#include "../../Cozy.Vendor/Cozy.Widgets/Cozy.imgui_widgets.cpp"
#ifndef GAME_IMGUI_PORTABLE_TEST
#define D3DCompile(...) game_d3d_compile(__VA_ARGS__)
#include "../Cozy.Graphics/Cozy.game_imgui_dx11.cpp"
#undef D3DCompile
#endif

#include "Cozy.game_imgui_text_input.h"
#include "Cozy.game_imgui_scene_assets.h"
#include "Cozy.game_imgui_scene_qoi.h"
#ifndef GAME_IMGUI_PORTABLE_TEST
#include "../Cozy.Graphics/Cozy.game_imgui_blur.h"
#endif

struct GameImGuiContext {
    ImGuiContext* imgui;
    void* arena_memory;
    uint32_t input_events, widgets, text_bytes;
    GameImGuiHandle handle;
    uint32_t owner_thread;
    int32_t last_error;
    bool frame_started;
    bool scene_drawn;
    int32_t scene_phase;
    float scene_entry, scene_motion_time, scene_reveal_seconds;
    float scene_hovers[10];
    bool license_only, scene_blur_active;
    bool license_focus_ready, license_field_focused;
    float scene_run_progress, license_caret_x;
    bool license_hint_visible;
    ImDrawList* scene_wave_draw;
    int scene_wave_first_vertex, scene_wave_last_vertex, scene_wave_percent;
    float scene_wave_x, scene_wave_y, scene_wave_radius;
    int license_mask_count;
    ImDrawList* scene_foreground;
    float scene_position, scene_drag_origin, scene_drag_last, scene_velocity, scene_tab_position;
    int scene_tab;
    float scene_detail_mix, scene_accent[3];
    int scene_detail_index, scene_host_selected;
    bool scene_detail_open, scene_accent_ready;
    bool scene_position_ready, scene_drag_pending, scene_dragging, scene_drag_moved;
    unsigned scene_control_index;
    bool scene_reduced;
    bool canvas_begun;
    bool canvas_started;
    bool focus_requested;
    bool input_focused;
    CozyTextInput* text_input; // allocated only by explicit application opt-in
    ImFont* bounded_font;
    uint32_t extra_glyph_count;
    unsigned short extra_glyphs[128];
#ifndef GAME_IMGUI_PORTABLE_TEST
    HWND window;
    ID3D11Device* device;
    ID3D11DeviceContext* device_context;
    IDXGISwapChain* swap_chain;
    IDCompositionDevice* composition;
    IDCompositionTarget* composition_target;
    IDCompositionVisual* composition_visual;
    IDCompositionRectangleClip* composition_clip;
    ID3D11RenderTargetView* render_target;
    GameSceneBlurGpu scene_blur;
    ID3D11ShaderResourceView* scene_images[GameSceneImageCount];
    ID3D11ShaderResourceView* scene_blurs[GameSceneImageCount];
    bool backend_started;
#endif
};
static GameImGuiContext* game_imgui_active = 0;
static uintptr_t game_imgui_generation = 0;
static int32_t game_imgui_call_busy = 0;
/* Inline 32-bit atomics: no C++ RTL locks, exceptions, static constructors or
   imported synchronization helpers. Refuse reentry instead of blocking a UI
   callback on itself. The gate also prevents destroy/read data races. */
struct GameApiCall {
    GameFloatingPointScope floating_point;
    bool held;
    GameApiCall() noexcept : held(false) {
        int32_t expected=0;
        held=__atomic_compare_exchange_n(&game_imgui_call_busy,&expected,1,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
    }
    ~GameApiCall() noexcept {if(held)__atomic_store_n(&game_imgui_call_busy,0,__ATOMIC_RELEASE);}
    explicit operator bool() const noexcept {return held;}
    GameApiCall(const GameApiCall&)=delete;
    GameApiCall& operator=(const GameApiCall&)=delete;
};
#ifdef GAME_IMGUI_PORTABLE_TEST
typedef uint32_t (*GameThreadFn)(void);
#else
typedef DWORD (WINAPI* GameThreadFn)(void);
#endif
static GameImGuiContext* game_context(GameImGuiHandle handle){
    GameImGuiContext* c=game_imgui_active;
    if(!c || !handle || handle!=c->handle || !c->imgui)return 0;
    GameThreadFn current=game_proc<GameThreadFn>(GI_PROC_THREAD_ID);
    if(!current || current()!=c->owner_thread)return 0;
    ImGui::SetCurrentContext(c->imgui);return c;
}
/* Allocation failure at this point is a violated internal fixed-canvas bound,
   not a host heap failure: the complete arena was committed before entering
   ImGui. Ordinary OOM is returned at context creation/admission. */
static void* game_alloc(size_t size,void*){void* p=game_arena_alloc(size);if(!p)game_imgui_assert_failed();return p;}
static void game_free(void* p,void*){game_arena_free(p);}
/* Legacy surface bounds: one canvas, <=8 items, <=512 reviewed UTF-8 bytes/frame,
   <=256 queued input events, eleven locked baked font sizes. One 64MiB arena
   retains a 32MiB contiguous frame admission reserve, exceeding bounded
   draw/input transient storage (1MiB) and 256KiB font-upload strips. Alpha8
   coverage keeps every reviewed font size without full RGBA CPU copies. The
   exclusive scene extension is a fixed three-image/eight-control draw surface,
   not additional arbitrary text admission. Its real-core sweep shares this arena. */
static_assert(sizeof(ImGuiContext)<1024u*1024u,COZY_TEXT_GAME_IMGUI_BRIDGE_REVIEW_FIXED_CANVAS_MEMORY_BOUNDS_E8434B16);
static bool game_memory_ready(GameImGuiContext* c){
    if(game_arena_largest()>=GameFrameReserve)return true;
    c->last_error=GI_ERROR_FRAME_RESERVE;game_imgui_runtime_failed=true;return false;
}
static bool game_input_ready(GameImGuiContext* c){
    if(!c||game_imgui_runtime_failed)return false;
    if(++c->input_events<=256 && GImGui->InputEventsQueue.Size<256)return true;
    ImGui::GetIO().ClearEventsQueue();ImGui::GetIO().ClearInputKeys();ImGui::GetIO().ClearInputMouse();
    if(c->text_input)cozy_text_reset(c->text_input,c->input_focused);
    c->input_events=0;return false;
}
/* This is a fixed product canvas, not an arbitrary text editor. Admit only
   printable ASCII and the reviewed Korean UI vocabulary. Strict decoding rejects
   overlong forms, surrogates, controls and truncated sequences before ImGui. */
static const unsigned short GameKoreanCodepoints[]={0x00B7u,0xAC00u,0xAC04u,0xAC8Cu,0xACB0u,0xACBDu,0xACE0u,0xAE30u,0xAEBCu,0xB098u,0xB294u,0xB2C8u,0xB2E4u,0xB3CCu,0xB418u,0xB41Cu,0xB428u,0xB530u,0xB73Bu,0xB85Cu,0xB8CCu,0xB974u,0xB97Cu,0xB9ACu,0xB9CCu,0xBA74u,0xBAA8u,0xBABBu,0xBBF8u,0xBC18u,0xBC84u,0xBC88u,0xBCCDu,0xBCF4u,0xBD88u,0xBE5Bu,0xC0ACu,0xC0C8u,0xC0D8u,0xC11Cu,0xC120u,0xC124u,0xC138u,0xC158u,0xC18Du,0xC21Cu,0xC2B5u,0xC2DCu,0xC2E4u,0xC544u,0xC54Au,0xC558u,0xC5B4u,0xC5C5u,0xC5ECu,0xC5F0u,0xC678u,0xC694u,0xC6A9u,0xC6B4u,0xC6CCu,0xC73Cu,0xC744u,0xC758u,0xC774u,0xC778u,0xC77Cu,0xC791u,0xC7A5u,0xC7ACu,0xC804u,0xC815u,0xC81Cu,0xC885u,0xC99Du,0xC9C0u,0xC9D0u,0xCC98u,0xCCADu,0xCE58u,0xCEA1u,0xD0DDu,0xD130u,0xD48Du,0xD50Cu,0xD558u,0xD55Cu,0xD569u,0xD588u,0xD589u,0xD5D8u,0xD604u,0xD638u,0xD654u,0xD655u,0xD6C4u,0xD750u};
static bool game_codepoint_allowed(unsigned cp){
    if(cp>=32 && cp<=126)return true;
    for(unsigned i=0;i<sizeof(GameKoreanCodepoints)/sizeof(GameKoreanCodepoints[0]);++i)
        if(cp==GameKoreanCodepoints[i])return true;
    return false;
}
static bool game_utf8_text(const char* text,size_t* bytes){
    if(!text)return false;
    size_t n=0;
    while(n<128 && text[n]){
        unsigned first=static_cast<unsigned char>(text[n]),cp=0,need=0;
        if(first<0x80){cp=first;need=1;}
        else if(first>=0xC2 && first<=0xDF){cp=first&31;need=2;}
        else if(first>=0xE0 && first<=0xEF){cp=first&15;need=3;}
        else return false;
        if(n+need>=128)return false;
        for(unsigned j=1;j<need;++j){unsigned b=static_cast<unsigned char>(text[n+j]);if((b&0xC0)!=0x80)return false;cp=(cp<<6)|(b&63);}
        if((need==2 && cp<0x80)||(need==3 && cp<0x800)||(cp>=0xD800 && cp<=0xDFFF)||!game_codepoint_allowed(cp))return false;
        n+=need;
    }
    if(n==128)return false;
    if(bytes)*bytes=n;
    return true;
}
static bool game_text_ready(GameImGuiContext* c,const char* text){
    if(!c||game_imgui_runtime_failed||c->widgets>=8)return false;
    size_t n=0;if(!game_utf8_text(text,&n)||c->text_bytes+n>512)return false;
    ++c->widgets;c->text_bytes+=static_cast<uint32_t>(n);return true;
}
static uint32_t game_font_u32(const unsigned char* p){return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
static bool game_font_container(const void* data,uint32_t bytes){
    if(!data||bytes<256||bytes>16u*1024u*1024u)return false;
    const unsigned char* p=static_cast<const unsigned char*>(data);
    if(game_font_u32(p)!=0x00010000u)return false; // trusted Windows TrueType only
    unsigned tables=(unsigned(p[4])<<8)|p[5];
    if(!tables||tables>64||12u+16u*tables>bytes)return false;
    for(unsigned i=0;i<tables;++i){const unsigned char* t=p+12+16*i;uint32_t off=game_font_u32(t+8),len=game_font_u32(t+12);if(off>bytes||len>bytes-off)return false;}
    return true;
}
#ifndef GAME_IMGUI_PORTABLE_TEST
static bool game_make_render_target(GameImGuiContext* c){
    ID3D11Texture2D* buffer=0;
    HRESULT hr=c->swap_chain->GetBuffer(0,__uuidof(ID3D11Texture2D),reinterpret_cast<void**>(&buffer));
    if(SUCCEEDED(hr))hr=c->device->CreateRenderTargetView(buffer,0,&c->render_target);
    if(buffer)buffer->Release();c->last_error=hr;return SUCCEEDED(hr)&&c->render_target;
}
#endif
#ifndef GAME_IMGUI_PORTABLE_TEST
static bool game_scene_create_images(GameImGuiContext* c) {
    const unsigned char* const images[]={GameSceneImage0,GameSceneImage1,GameSceneImage2,GameSceneImage3,GameSceneImage4,GameSceneImage5,GameSceneImage6,GameSceneImage7,GameSceneImage8,GameSceneImage9,GameSceneImage10,GameSceneImage11,GameSceneImage12,GameSceneImage13,GameSceneImage14,GameSceneImage15,GameSceneImage16,GameSceneImage17};
    const unsigned char* const blurs[]={GameSceneBlur0,GameSceneBlur1,GameSceneBlur2,GameSceneBlur3,GameSceneBlur4,GameSceneBlur5,GameSceneBlur6,GameSceneBlur7,GameSceneBlur8,GameSceneBlur9,GameSceneBlur10,GameSceneBlur11,GameSceneBlur12,GameSceneBlur13,GameSceneBlur14,GameSceneBlur15,GameSceneBlur16,GameSceneBlur17};
    const size_t image_bytes[]={sizeof(GameSceneImage0),sizeof(GameSceneImage1),sizeof(GameSceneImage2),sizeof(GameSceneImage3),sizeof(GameSceneImage4),sizeof(GameSceneImage5),sizeof(GameSceneImage6),sizeof(GameSceneImage7),sizeof(GameSceneImage8),sizeof(GameSceneImage9),sizeof(GameSceneImage10),sizeof(GameSceneImage11),sizeof(GameSceneImage12),sizeof(GameSceneImage13),sizeof(GameSceneImage14),sizeof(GameSceneImage15),sizeof(GameSceneImage16),sizeof(GameSceneImage17)};
    const size_t blur_bytes[]={sizeof(GameSceneBlur0),sizeof(GameSceneBlur1),sizeof(GameSceneBlur2),sizeof(GameSceneBlur3),sizeof(GameSceneBlur4),sizeof(GameSceneBlur5),sizeof(GameSceneBlur6),sizeof(GameSceneBlur7),sizeof(GameSceneBlur8),sizeof(GameSceneBlur9),sizeof(GameSceneBlur10),sizeof(GameSceneBlur11),sizeof(GameSceneBlur12),sizeof(GameSceneBlur13),sizeof(GameSceneBlur14),sizeof(GameSceneBlur15),sizeof(GameSceneBlur16),sizeof(GameSceneBlur17)};
    const size_t scratch_bytes=size_t(GameSceneImageWidth)*GameSceneImageHeight*4;
    unsigned char* scratch=static_cast<unsigned char*>(game_arena_alloc(scratch_bytes));
    if(!scratch){c->last_error=static_cast<HRESULT>(0x8007000Eu);return false;}
    bool ready=true;
    for(unsigned image=0;image<GameSceneImageCount&&ready;++image)for(unsigned kind=0;kind<2&&ready;++kind){
        D3D11_TEXTURE2D_DESC desc={};desc.Width=kind?GameSceneBlurWidth:GameSceneImageWidth;desc.Height=kind?GameSceneBlurHeight:GameSceneImageHeight;
        if(!game_scene_decode_qoi(kind?blurs[image]:images[image],kind?blur_bytes[image]:image_bytes[image],
                                  scratch,size_t(desc.Width)*desc.Height*4,desc.Width,desc.Height)){
            c->last_error=static_cast<HRESULT>(0x8007000Du);ready=false;break;
        }
        desc.MipLevels=1;desc.ArraySize=1;desc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count=1;desc.Usage=D3D11_USAGE_IMMUTABLE;desc.BindFlags=D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA data={};data.pSysMem=scratch;data.SysMemPitch=desc.Width*4;
        ID3D11ShaderResourceView** view=kind?&c->scene_blurs[image]:&c->scene_images[image];
        ID3D11Texture2D* texture=0;HRESULT hr=c->device->CreateTexture2D(&desc,&data,&texture);
        if(SUCCEEDED(hr)&&texture)hr=c->device->CreateShaderResourceView(texture,0,view);
        if(texture)texture->Release();
        if(SUCCEEDED(hr)&&!*view)hr=static_cast<HRESULT>(0x80004005u);
        c->last_error=hr;ready=SUCCEEDED(hr)&&*view;
    }
    game_memset(scratch,0,scratch_bytes);game_arena_free(scratch);
    return ready;
}
static bool game_composition_clip(GameImGuiContext* c,unsigned width,unsigned height) {
    const float scale=ImMin(width/(c->license_only?340.0f:680.0f),height/(c->license_only?380.0f:440.0f)),radius=6.0f*scale;
    IDCompositionRectangleClip* clip=c->composition_clip;
    HRESULT hr=game_dcomp_clip_left(clip,0.0f);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_top(clip,0.0f);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_right(clip,static_cast<float>(width));
    if(SUCCEEDED(hr))hr=game_dcomp_clip_bottom(clip,static_cast<float>(height));
    if(SUCCEEDED(hr))hr=game_dcomp_clip_top_left_radius_x(clip,radius);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_top_left_radius_y(clip,radius);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_top_right_radius_x(clip,radius);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_top_right_radius_y(clip,radius);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_bottom_left_radius_x(clip,radius);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_bottom_left_radius_y(clip,radius);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_bottom_right_radius_x(clip,radius);
    if(SUCCEEDED(hr))hr=game_dcomp_clip_bottom_right_radius_y(clip,radius);
    if(SUCCEEDED(hr))hr=c->composition->Commit();
    c->last_error=hr;return SUCCEEDED(hr);
}
static bool game_create_composition(GameImGuiContext* c) {
    IDXGIDevice1* dxgi=0;IDXGIAdapter* adapter=0;IDXGIFactory2* factory=0;IDXGISwapChain1* chain=0;
    HRESULT hr=c->device->QueryInterface(__uuidof(IDXGIDevice1),reinterpret_cast<void**>(&dxgi));
    // One queued frame: Present(1) supplies monitor pacing, without a second
    // coarse 16ms Windows timer or a busy wait before each display interval.
    if(SUCCEEDED(hr))hr=dxgi->SetMaximumFrameLatency(1);
    if(SUCCEEDED(hr))hr=dxgi->GetAdapter(&adapter);
    if(SUCCEEDED(hr))hr=adapter->GetParent(__uuidof(IDXGIFactory2),reinterpret_cast<void**>(&factory));
    DXGI_SWAP_CHAIN_DESC1 desc={};desc.Width=c->license_only?340:680;desc.Height=c->license_only?380:440;desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count=1;desc.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;desc.BufferCount=2;
    desc.Scaling=DXGI_SCALING_STRETCH;desc.SwapEffect=DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    desc.AlphaMode=DXGI_ALPHA_MODE_PREMULTIPLIED;
    if(SUCCEEDED(hr))hr=factory->CreateSwapChainForComposition(c->device,&desc,0,&chain);
    if(SUCCEEDED(hr)){c->swap_chain=chain;chain=0;}
    typedef HRESULT(WINAPI* ComposeFn)(IDXGIDevice*,REFIID,void**);
    ComposeFn compose=game_proc<ComposeFn>(GI_PROC_DCOMP_CREATE);
    if(SUCCEEDED(hr))hr=compose?compose(dxgi,__uuidof(IDCompositionDevice),reinterpret_cast<void**>(&c->composition)):E_FAIL;
    if(SUCCEEDED(hr))hr=c->composition->CreateTargetForHwnd(c->window,TRUE,&c->composition_target);
    if(SUCCEEDED(hr))hr=c->composition->CreateVisual(&c->composition_visual);
    if(SUCCEEDED(hr))hr=c->composition->CreateRectangleClip(&c->composition_clip);
    if(SUCCEEDED(hr))hr=c->composition_visual->SetBorderMode(DCOMPOSITION_BORDER_MODE_SOFT);
    if(SUCCEEDED(hr))hr=c->composition_visual->SetContent(c->swap_chain);
    if(SUCCEEDED(hr))hr=game_dcomp_visual_clip(c->composition_visual,c->composition_clip);
    if(SUCCEEDED(hr))hr=c->composition_target->SetRoot(c->composition_visual);
    if(chain)chain->Release();if(factory)factory->Release();if(adapter)adapter->Release();if(dxgi)dxgi->Release();
    c->last_error=hr;if(FAILED(hr))return false;
    return game_composition_clip(c,desc.Width,desc.Height);
}
#endif
extern "C" uint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT {return 3;}
static void game_destroy_context(GameImGuiContext* c){
    if(c->text_input){cozy_text_wipe(c->text_input,sizeof(*c->text_input));game_arena_free(c->text_input);c->text_input=0;}
    if(c->canvas_started){ImGui::End();c->canvas_started=false;}
    if(c->frame_started){ImGui::EndFrame();c->frame_started=false;}
#ifndef GAME_IMGUI_PORTABLE_TEST
    for(unsigned i=0;i<GameSceneImageCount;++i){if(c->scene_images[i])c->scene_images[i]->Release();if(c->scene_blurs[i])c->scene_blurs[i]->Release();}
    game_blur_release(c->scene_blur);
    // Detach our visual tree before releasing its referenced swap chain.
    if(c->composition_target)c->composition_target->SetRoot(0);
    if(c->composition)c->composition->Commit();
    if(c->composition_clip)c->composition_clip->Release();
    if(c->composition_visual)c->composition_visual->Release();
    if(c->composition_target)c->composition_target->Release();
    if(c->composition)c->composition->Release();
    if(c->backend_started)ImGui_ImplDX11_Shutdown();
    if(c->render_target)c->render_target->Release();
    if(c->swap_chain)c->swap_chain->Release();
    if(c->device_context){c->device_context->ClearState();c->device_context->Release();}
    if(c->device)c->device->Release();
#endif
    ImGui::DestroyContext(c->imgui);c->imgui=0;game_imgui_active=0;
    game_imgui_host.free(c->arena_memory);game_arena.first=0;game_arena.begin=0;game_arena.end=0;
    game_imgui_host.free(c);game_memset(&game_imgui_host,0,sizeof(game_imgui_host));
}
static int32_t game_create_failure(GameImGuiContext* c, int32_t fallback) {
    const int32_t error=game_imgui_dx11_error<0 ? game_imgui_dx11_error :
        (fallback<0 ? fallback : static_cast<int32_t>(0x80004005u));
    game_destroy_context(c);return error;
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_destroy(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;
    GameImGuiContext* c=game_context(handle);if(!c)return 0;
    game_destroy_context(c);return 1;
}
static int32_t game_create(void* window,const GameImGuiHost* host,const void* font_data,uint32_t font_bytes,GameImGuiHandle* result,bool license_only=false) {
    if(result)*result=0;
    GameApiCall call;if(!call)return 0;
    if((font_data||font_bytes)&&!game_font_container(font_data,font_bytes))return static_cast<int32_t>(0x8007000Du);
    if(!result || !window || !host || host->abi_version!=3 || host->struct_size!=sizeof(GameImGuiHost) || !host->get_proc || !host->alloc || !host->free || game_imgui_active)return 0;
    if(game_imgui_generation==UINTPTR_MAX)return 0;
    for(int id=1;id<=GI_PROC_LAST;++id)if(!host->get_proc(id))return 0;
    game_imgui_host=*host;game_imgui_runtime_failed=false;game_imgui_dx11_failed=false;game_imgui_dx11_error=0;
    GameThreadFn current=game_proc<GameThreadFn>(GI_PROC_THREAD_ID);
    const uint32_t owner=current?current():0;
    if(!owner){game_memset(&game_imgui_host,0,sizeof(game_imgui_host));return 0;}
    GameImGuiContext* c=static_cast<GameImGuiContext*>(host->alloc(sizeof(GameImGuiContext)));
    if(!c){game_memset(&game_imgui_host,0,sizeof(game_imgui_host));return GI_ERROR_HOST_CONTEXT;}
    game_memset(c,0,sizeof(*c));c->license_only=license_only;
    c->arena_memory=host->alloc(GameArenaBytes+15);
    if(!c->arena_memory){host->free(c);game_memset(&game_imgui_host,0,sizeof(game_imgui_host));return GI_ERROR_HOST_ARENA;}
    /* Touch every page while still outside ImGui; the host allocation owns
       the entire fixed reservation, not a lazily growing allocator. */
    game_memset(c->arena_memory,0,GameArenaBytes+15);
    const uintptr_t arena_base=(reinterpret_cast<uintptr_t>(c->arena_memory)+15)&~static_cast<uintptr_t>(15);
    game_arena_init(reinterpret_cast<void*>(arena_base));
    ImGui::SetAllocatorFunctions(game_alloc,game_free,0);
    c->handle=reinterpret_cast<GameImGuiHandle>(++game_imgui_generation);c->owner_thread=owner;
    c->imgui=ImGui::CreateContext();c->focus_requested=!license_only;game_imgui_active=c;
    ImGuiIO& io=ImGui::GetIO();io.IniFilename=0;io.LogFilename=0;
    io.Fonts->TexDesiredFormat=ImTextureFormat_Alpha8;
    io.ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard|ImGuiConfigFlags_NoMouseCursorChange;
    io.BackendPlatformName=COZY_TEXT_GAME_IMGUI_BRIDGE_GAME_DELPHI_WIN64_85A712A8;
    io.ConfigInputTrickleEventQueue=true;
    /* Font bytes are copied into the fixed arena and owned by the atlas. No
       caller buffer, filename, file handle or persistent font cache survives.
       Bake only the reviewed UI vocabulary at eleven fixed sizes, then lock the cache. */
    ImFont* bounded_font=0;
    if(font_data){
        void* owned=game_arena_alloc(font_bytes);
        if(!owned)return game_create_failure(c,GI_ERROR_FONT_COPY);
        game_memcpy(owned,font_data,font_bytes);
        ImFontConfig config;config.FontDataOwnedByAtlas=true;
        bounded_font=io.Fonts->AddFontFromMemoryTTF(owned,static_cast<int>(font_bytes),13.0f,&config);
        if(!bounded_font){game_arena_free(owned);return game_create_failure(c,static_cast<int32_t>(0x8007000Du));}
    }else bounded_font=io.Fonts->AddFontDefaultVector();
    const float baked_sizes[]={10.0f,13.0f,16.25f,19.5f,22.75f,26.0f,32.5f,39.0f,52.0f,78.0f,104.0f};
    for(unsigned i=0;i<sizeof(baked_sizes)/sizeof(baked_sizes[0]);++i){
        ImFontBaked* baked=bounded_font->GetFontBaked(baked_sizes[i]);
        for(unsigned ch=32;ch<127;++ch)baked->FindGlyph(static_cast<ImWchar>(ch));
        if(font_data)for(unsigned j=0;j<sizeof(GameKoreanCodepoints)/sizeof(GameKoreanCodepoints[0]);++j)
            if(!baked->FindGlyphNoFallback(static_cast<ImWchar>(GameKoreanCodepoints[j])))
                return game_create_failure(c,static_cast<int32_t>(0x8007000Du));
    }
    c->bounded_font=bounded_font;
    bounded_font->Flags|=ImFontFlags_LockBakedSizes|ImFontFlags_NoLoadGlyphs;
    ImGui::StyleColorsDark();ImGuiStyle& style=ImGui::GetStyle();
    style.AntiAliasedLines=true;style.AntiAliasedFill=true;style.CircleTessellationMaxError=0.20f;style.CurveTessellationTol=0.8f;
    style.WindowBorderSize=0;style.WindowRounding=0;style.FrameBorderSize=0;style.FrameRounding=3;
    style.WindowPadding=ImVec2(0,0);style.Colors[ImGuiCol_WindowBg]=ImVec4(0,0,0,1);
    style.Colors[ImGuiCol_Button]=ImVec4(0.13f,0.13f,0.13f,1);
    style.Colors[ImGuiCol_ButtonHovered]=ImVec4(0.23f,0.23f,0.23f,1);
    style.Colors[ImGuiCol_ButtonActive]=ImVec4(0.30f,0.30f,0.30f,1);
#ifndef GAME_IMGUI_PORTABLE_TEST
    c->window=static_cast<HWND>(window);
    // Create the D3D device only. The transparent flip chain belongs to DComp.
    const D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_0};D3D_FEATURE_LEVEL obtained;
    typedef HRESULT(WINAPI* CreateFn)(IDXGIAdapter*,D3D_DRIVER_TYPE,HMODULE,UINT,const D3D_FEATURE_LEVEL*,UINT,UINT,ID3D11Device**,D3D_FEATURE_LEVEL*,ID3D11DeviceContext**);
    CreateFn create=game_proc<CreateFn>(GI_PROC_D3D11_CREATE);
    HRESULT hr=create?create(0,D3D_DRIVER_TYPE_HARDWARE,0,D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,2,D3D11_SDK_VERSION,&c->device,&obtained,&c->device_context):E_FAIL;
    hr=game_fault_result(1,hr);
    if(FAILED(hr) && !game_imgui_runtime_failed){
        if(c->swap_chain){c->swap_chain->Release();c->swap_chain=0;}if(c->device_context){c->device_context->Release();c->device_context=0;}if(c->device){c->device->Release();c->device=0;}
        create=game_proc<CreateFn>(GI_PROC_D3D11_CREATE);
        hr=create?create(0,D3D_DRIVER_TYPE_WARP,0,D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,2,D3D11_SDK_VERSION,&c->device,&obtained,&c->device_context):E_FAIL;
    }
    hr=game_fault_result(1,hr);c->last_error=hr;
    if(FAILED(hr)||!c->device||!c->device_context||!game_create_composition(c)||!game_make_render_target(c))return game_create_failure(c,c->last_error);
    if(!c->license_only&&!game_scene_create_images(c))return game_create_failure(c,c->last_error);
    if(!ImGui_ImplDX11_Init(c->device,c->device_context))return game_create_failure(c,0);c->backend_started=true;
    if(!ImGui_ImplDX11_CreateDeviceObjects()||game_imgui_runtime_failed||game_imgui_dx11_failed)return game_create_failure(c,0);
    // B prepares its authentication blur with its initial GPU resources,
    // before the host freezes the module baseline. Submitting a license must
    // not be the first time this shader pipeline is compiled or allocated.
    if(c->license_only){hr=game_blur_prepare(c->scene_blur,c->device,340,380);c->last_error=hr;
        if(FAILED(hr))return game_create_failure(c,hr);}
#else
    /* Test harness only: build atlas to exercise actual core draw generation;
       this compile mode deliberately cannot return a successful Present. */
    unsigned char* pixels=0;int w=0,h=0;io.Fonts->GetTexDataAsAlpha8(&pixels,&w,&h);io.Fonts->SetTexID(1);
#endif
    if(game_imgui_runtime_failed||!game_memory_ready(c))return game_create_failure(c,c->last_error);*result=c->handle;return 1;
}
/* Existing ABI v2 remains available for portable/core and fault fixtures.
   Versioned font entry point copies the exact trusted font bytes synchronously. */
extern "C" int32_t GAME_IMGUI_CALL game_imgui_create(void* window,const GameImGuiHost* host,GameImGuiHandle* result) GAME_IMGUI_NOEXCEPT {
    return game_create(window,host,0,0,result);
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_create_korean_v1(void* window,const GameImGuiHost* host,const void* font_data,uint32_t font_bytes,GameImGuiHandle* result) GAME_IMGUI_NOEXCEPT {
    if(!font_data||!font_bytes){if(result)*result=0;return static_cast<int32_t>(0x8007000Du);}
    return game_create(window,host,font_data,font_bytes,result);
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_create_license_korean_v1(void* window,const GameImGuiHost* host,const void* font_data,uint32_t font_bytes,GameImGuiHandle* result) GAME_IMGUI_NOEXCEPT {
    if(!font_data||!font_bytes){if(result)*result=0;return static_cast<int32_t>(0x8007000Du);}
    return game_create(window,host,font_data,font_bytes,result,true);
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_resize(GameImGuiHandle handle,int32_t width,int32_t height) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;
    GameImGuiContext* c=game_context(handle);if(!c||width<=0||height<=0||width>16384||height>16384||c->frame_started||game_imgui_runtime_failed||game_imgui_dx11_failed)return 0;
#ifndef GAME_IMGUI_PORTABLE_TEST
    c->device_context->OMSetRenderTargets(0,0,0);
    if(c->render_target){c->render_target->Release();c->render_target=0;}
    HRESULT hr=c->swap_chain->ResizeBuffers(0,width,height,DXGI_FORMAT_UNKNOWN,0);hr=game_fault_result(2,hr);c->last_error=hr;
    if(FAILED(hr))return 0;
    if(!game_make_render_target(c)||!game_composition_clip(c,width,height))return 0;
    // DPI/SSAA changes replace only the bounded half-resolution targets.
    // The prepared shaders/states persist until normal context destruction.
    if(c->license_only){hr=game_blur_prepare(c->scene_blur,c->device,static_cast<unsigned>(width),static_cast<unsigned>(height));c->last_error=hr;
        if(FAILED(hr))return 0;}
    return 1;
#else
    return 1;
#endif
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_set_dpi(GameImGuiHandle handle,float scale) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;
    GameImGuiContext* c=game_context(handle);if(!c||c->frame_started||!(scale>=0.5f&&scale<=8.0f))return 0;
    ImGui::GetStyle().FontScaleDpi=scale;return 1;
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_new_frame(GameImGuiHandle handle,int32_t width,int32_t height,float delta) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;
    GameImGuiContext* c=game_context(handle);if(!c||c->frame_started||width<=0||height<=0||width>16384||height>16384||!(delta>0)||delta>1.0f||game_imgui_runtime_failed||game_imgui_dx11_failed)return 0;
    if(!game_memory_ready(c))return 0;
#ifndef GAME_IMGUI_PORTABLE_TEST
    ImGui_ImplDX11_NewFrame();
    if(game_imgui_runtime_failed||game_imgui_dx11_failed)return 0;
#endif
    c->input_events=0;c->widgets=0;c->text_bytes=0;c->canvas_begun=false;c->scene_drawn=false;c->scene_blur_active=false;c->scene_foreground=0;c->scene_wave_draw=0;
    ImGuiIO& io=ImGui::GetIO();io.DisplaySize=ImVec2(static_cast<float>(width),static_cast<float>(height));io.DeltaTime=delta;
    ImGui::NewFrame();c->frame_started=true;return (game_imgui_runtime_failed||game_imgui_dx11_failed)?0:1;
}
extern "C" void GAME_IMGUI_CALL game_imgui_mouse_pos(GameImGuiHandle handle,float x,float y) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;
    // ImGui floors ordinary coordinates through a float-to-int conversion.
    // Admit actual signed Win32 coordinates, and normalize the existing host's
    // mouse-leave pair before that conversion. NaN/mixed/oversized values must
    // not reach the queue or consume its admission budget.
    if((x==-1.0e30f&&y==-1.0e30f)||(x==-FLT_MAX&&y==-FLT_MAX)){x=-FLT_MAX;y=-FLT_MAX;}
    else if(!(x>=-32768.0f&&x<=32767.0f&&y>=-32768.0f&&y<=32767.0f))return;
    if(game_input_ready(game_context(handle)))ImGui::GetIO().AddMousePosEvent(x,y);}
extern "C" void GAME_IMGUI_CALL game_imgui_mouse_button(GameImGuiHandle handle,int32_t button,int32_t down) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;if(game_input_ready(game_context(handle))&&button>=0&&button<5)ImGui::GetIO().AddMouseButtonEvent(button,down!=0);}
extern "C" void GAME_IMGUI_CALL game_imgui_mouse_wheel(GameImGuiHandle handle,float h,float v) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;
    if(!(h>=-16384.0f&&h<=16384.0f&&v>=-16384.0f&&v<=16384.0f))return;
    if(game_input_ready(game_context(handle)))ImGui::GetIO().AddMouseWheelEvent(h,v);}
static ImGuiKey game_key(int32_t key){
    switch(key){case 0x09:return ImGuiKey_Tab;case 0x25:return ImGuiKey_LeftArrow;case 0x27:return ImGuiKey_RightArrow;case 0x26:return ImGuiKey_UpArrow;case 0x28:return ImGuiKey_DownArrow;
    case 0x21:return ImGuiKey_PageUp;case 0x22:return ImGuiKey_PageDown;case 0x24:return ImGuiKey_Home;case 0x23:return ImGuiKey_End;case 0x2D:return ImGuiKey_Insert;case 0x2E:return ImGuiKey_Delete;
    case 0x08:return ImGuiKey_Backspace;case 0x20:return ImGuiKey_Space;case 0x0D:return ImGuiKey_Enter;case 0x1B:return ImGuiKey_Escape;
    case 0x10:return ImGuiMod_Shift;case 0x11:return ImGuiMod_Ctrl;case 0x12:return ImGuiMod_Alt;case 0x5B:case 0x5C:return ImGuiMod_Super;
    case 0xA0:return ImGuiKey_LeftShift;case 0xA1:return ImGuiKey_RightShift;case 0xA2:return ImGuiKey_LeftCtrl;case 0xA3:return ImGuiKey_RightCtrl;case 0xA4:return ImGuiKey_LeftAlt;case 0xA5:return ImGuiKey_RightAlt;
    default:if(key>=0x30&&key<=0x39)return static_cast<ImGuiKey>(ImGuiKey_0+key-0x30);if(key>=0x41&&key<=0x5A)return static_cast<ImGuiKey>(ImGuiKey_A+key-0x41);if(key>=0x70&&key<=0x7B)return static_cast<ImGuiKey>(ImGuiKey_F1+key-0x70);return ImGuiKey_None;}
}
extern "C" void GAME_IMGUI_CALL game_imgui_key(GameImGuiHandle handle,int32_t key,int32_t down) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;if(!game_input_ready(game_context(handle)))return;ImGuiKey k=game_key(key);if(k!=ImGuiKey_None){if(down&&(key==0x0D||key==0x20))ImGui::SetNavCursorVisible(true);ImGui::GetIO().AddKeyEvent(k,down!=0);}}
static void game_license_clear_focus(GameImGuiContext* c) {
    if(!c||!c->license_only)return;
    // Native navigation focus must match the host after lost capture/focus.
    // Keeping NavID would hide the hint/caret while the host ignores typing.
    ImGui::ClearActiveID();ImGuiContext& g=*GImGui;
    if(g.NavWindow)ImGui::SetNavID(0,g.NavLayer,g.NavWindow->NavRootFocusScopeId,ImRect());
    g.NavInitRequest=false;g.NavInitResult.Clear();ImGui::NavUpdateAnyRequestFlag();
    c->focus_requested=false;c->license_field_focused=false;
}
extern "C" void GAME_IMGUI_CALL game_imgui_focus(GameImGuiHandle handle,int32_t focused) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;GameImGuiContext* c=game_context(handle);if(c){c->input_focused=(focused!=0);if(!focused){game_license_clear_focus(c);c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;}if(c->text_input)cozy_text_reset(c->text_input,c->input_focused);}if(game_input_ready(c)){ImGui::GetIO().AddFocusEvent(focused!=0);if(focused&&!c->license_only)c->focus_requested=true;}}
extern "C" void GAME_IMGUI_CALL game_imgui_clear_input(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;GameImGuiContext* c=game_context(handle);if(c){c->scene_drag_pending=false;c->scene_dragging=false;c->scene_drag_moved=false;c->scene_velocity=0;if(c->text_input)cozy_text_reset(c->text_input,c->input_focused);ImGuiIO& io=ImGui::GetIO();io.ClearEventsQueue();io.ClearInputKeys();io.ClearInputMouse();c->focus_requested=!c->license_only;game_license_clear_focus(c);}}
extern "C" uint32_t GAME_IMGUI_CALL game_imgui_text_input_version(void) GAME_IMGUI_NOEXCEPT {return 1;}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_text_input_enable_v1(GameImGuiHandle handle,int32_t enabled) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);if(!c || (enabled!=0 && enabled!=1))return 0;
    if(!enabled){if(c->text_input){cozy_text_wipe(c->text_input,sizeof(*c->text_input));game_arena_free(c->text_input);c->text_input=0;}return 1;}
    if(c->text_input)return 1;
    if(!game_memory_ready(c))return 0;
    c->text_input=static_cast<CozyTextInput*>(game_arena_alloc(sizeof(CozyTextInput)));
    if(!c->text_input)return 0;cozy_text_reset(c->text_input,c->input_focused);return 1;
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_text_input_utf8_v1(GameImGuiHandle handle,const char* text,uint32_t bytes,int32_t action) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);
    return c && c->text_input && game_input_ready(c) && cozy_text_event(c->text_input,action,text,bytes)?1:0;
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_text_input_utf16_v1(GameImGuiHandle handle,uint32_t unit) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);
    return c && c->text_input && game_input_ready(c) && cozy_text_utf16(c->text_input,unit)?1:0;
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_text_input_read_v1(GameImGuiHandle handle,void* output,uint32_t bytes,uint32_t kind) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return -1;GameImGuiContext* c=game_context(handle);return c?cozy_text_read(c->text_input,kind,output,bytes):-1;
}
extern "C" uint32_t GAME_IMGUI_CALL game_imgui_text_input_status_v1(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);if(!c || !c->text_input)return 0;
    return 1u|(c->text_input->focused?2u:0u)|(c->text_input->composing?4u:0u)|(c->text_input->high_surrogate?8u:0u);
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_text_input_display_v1(GameImGuiHandle handle,const char* text,uint32_t bytes) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);
    if(!c || !c->text_input || !c->canvas_started || !c->bounded_font || c->widgets>=8 ||
       !cozy_text_utf8(text,bytes) || bytes>512-c->text_bytes || !game_memory_ready(c))return 0;
    // Admission checks precede atlas growth. At most 128 non-product glyphs over
    // this context's lifetime, eleven already locked sizes; overflow fails closed.
    unsigned short pending[128];uint32_t count=0,at=0,cp=0;
    while(at<bytes){if(!cozy_text_decode(text,bytes,at,cp))return 0;if(game_codepoint_allowed(cp))continue;
        bool found=false;for(uint32_t j=0;j<c->extra_glyph_count;++j)if(c->extra_glyphs[j]==cp)found=true;
        for(uint32_t j=0;j<count;++j)if(pending[j]==cp)found=true;
        if(!found){if(count+c->extra_glyph_count>=128)return 0;pending[count++]=static_cast<unsigned short>(cp);}}
    const float sizes[]={10.0f,13.0f,16.25f,19.5f,22.75f,26.0f,32.5f,39.0f,52.0f,78.0f,104.0f};
    c->bounded_font->Flags&=~ImFontFlags_NoLoadGlyphs;
    bool glyphs=true;
    for(uint32_t j=0;j<count && glyphs;++j){
        for(uint32_t k=0;k<sizeof(sizes)/sizeof(sizes[0]);++k)if(!game_memory_ready(c) || !c->bounded_font->GetFontBaked(sizes[k])->FindGlyphNoFallback(pending[j])){glyphs=false;break;}
        if(glyphs)c->extra_glyphs[c->extra_glyph_count++]=pending[j];
    }
    c->bounded_font->Flags|=ImFontFlags_NoLoadGlyphs;
    if(!glyphs || !game_memory_ready(c)){c->last_error=static_cast<int32_t>(0x8007000Du);game_imgui_runtime_failed=true;return 0;}
    ++c->widgets;c->text_bytes+=bytes;
    if(bytes)ImGui::TextUnformatted(text,text+bytes);return 1;
}
extern "C" void GAME_IMGUI_CALL game_imgui_begin_canvas(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;GameImGuiContext* c=game_context(handle);if(!c||!c->frame_started||c->canvas_started||c->canvas_begun)return;
    ImGui::SetNextWindowPos(ImVec2(0,0));ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin(COZY_TEXT_GAME_IMGUI_BRIDGE_GAMEOVERLAYCANVAS_214A44D5,0,ImGuiWindowFlags_NoBackground|ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoSavedSettings|ImGuiWindowFlags_NoScrollWithMouse|ImGuiWindowFlags_NoScrollbar);c->canvas_started=true;c->canvas_begun=true;
}
extern "C" void GAME_IMGUI_CALL game_imgui_set_cursor_pos(GameImGuiHandle handle,float x,float y) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;GameImGuiContext* c=game_context(handle);if(c&&c->canvas_started&&x>=-16384&&x<=16384&&y>=-16384&&y<=16384)ImGui::SetCursorPos(ImVec2(x,y));}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_button(GameImGuiHandle handle,const char* text,float w,float h,int32_t enabled) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);if(!c||!c->canvas_started||!(w>0&&w<=8192&&h>0&&h<=8192)||!game_text_ready(c,text))return 0;
    if(!enabled)c->focus_requested=true;
    if(enabled&&c->focus_requested){ImGui::SetKeyboardFocusHere();c->focus_requested=false;}
    ImGui::BeginDisabled(enabled==0);bool clicked=ImGui::Button(text,ImVec2(w,h));if(enabled)ImGui::SetItemDefaultFocus();ImGui::EndDisabled();return clicked&&enabled&&!game_imgui_runtime_failed?1:0;
}
extern "C" void GAME_IMGUI_CALL game_imgui_text(GameImGuiHandle handle,const char* text) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;GameImGuiContext* c=game_context(handle);if(c&&c->canvas_started&&game_text_ready(c,text))ImGui::TextUnformatted(text);}
extern "C" void GAME_IMGUI_CALL game_imgui_end_canvas(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return;GameImGuiContext* c=game_context(handle);if(c&&c->canvas_started){ImGui::End();c->canvas_started=false;}}
#include "Cozy.game_imgui_scene.h"
#include "Cozy.game_imgui_license.h"

extern "C" int32_t GAME_IMGUI_CALL game_imgui_render_present(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return -1;GameImGuiContext* c=game_context(handle);if(!c||!c->frame_started||c->canvas_started||game_imgui_runtime_failed||game_imgui_dx11_failed)return -1;
    ImGui::Render();c->frame_started=false;if(game_imgui_runtime_failed)return -1;
#ifndef GAME_IMGUI_PORTABLE_TEST
    const float black[]={0,0,0,0};c->device_context->OMSetRenderTargets(1,&c->render_target,0);c->device_context->ClearRenderTargetView(c->render_target,black);
    ImDrawData* source=ImGui::GetDrawData();
    if(c->scene_blur_active){
        if(!source||source->CmdLists.Size>4){c->last_error=E_INVALIDARG;return -1;}
        const unsigned width=static_cast<unsigned>(source->DisplaySize.x),height=static_cast<unsigned>(source->DisplaySize.y);
        HRESULT ready=game_blur_prepare(c->scene_blur,c->device,width,height);
        if(FAILED(ready)){c->last_error=ready;return -1;}
        ImDrawData background,foreground;
        background.Valid=foreground.Valid=true;background.FrameCount=foreground.FrameCount=source->FrameCount;
        background.DisplayPos=foreground.DisplayPos=source->DisplayPos;
        background.DisplaySize=foreground.DisplaySize=source->DisplaySize;
        background.OwnerViewport=foreground.OwnerViewport=source->OwnerViewport;
        background.Textures=foreground.Textures=source->Textures;
        background.FramebufferScale=ImVec2(c->scene_blur.width/source->DisplaySize.x,c->scene_blur.height/source->DisplaySize.y);
        foreground.FramebufferScale=source->FramebufferScale;
        for(int i=0;i<source->CmdLists.Size;++i){ImDrawList* list=source->CmdLists[i];
            if(list==c->scene_foreground)foreground.AddDrawList(list);else background.AddDrawList(list);}
        c->device_context->OMSetRenderTargets(1,&c->scene_blur.targets[0],0);
        c->device_context->ClearRenderTargetView(c->scene_blur.targets[0],black);
        ImGui_ImplDX11_RenderDrawData(&background);
        if(game_imgui_runtime_failed||game_imgui_dx11_failed)return -1;
        const float radius=ImMin(width/(c->license_only?340.0f:680.0f),height/(c->license_only?380.0f:440.0f))*0.70f;
        game_blur_pass(c->scene_blur,c->device_context,c->scene_blur.views[0],c->scene_blur.targets[1],c->scene_blur.width,c->scene_blur.height,radius/c->scene_blur.width,0);
        game_blur_pass(c->scene_blur,c->device_context,c->scene_blur.views[1],c->render_target,width,height,0,radius/c->scene_blur.height);
        if(foreground.CmdLists.Size)ImGui_ImplDX11_RenderDrawData(&foreground);
    }else ImGui_ImplDX11_RenderDrawData(source);
    if(game_imgui_runtime_failed||game_imgui_dx11_failed)return -1;
    HRESULT hr=c->swap_chain->Present(1,0);hr=game_fault_result(3,hr);c->last_error=hr;if(hr==DXGI_STATUS_OCCLUDED)return 0;if(FAILED(hr))return -1;return hr==S_OK?1:0;
#else
    return -1;
#endif
}
struct GameGpuIdentity {
    uint32_t version, bytes, vendor_id, device_id, subsys_id, revision;
    uint64_t driver_version;
};
static_assert(sizeof(GameGpuIdentity)==32,COZY_TEXT_GAME_IMGUI_BRIDGE_GPU_IDENTITY_ABI_MUST_BE_32_BYTES_EE3EB694);
extern "C" int32_t GAME_IMGUI_CALL game_imgui_gpu_identity(GameImGuiHandle handle,void* output,uint32_t bytes) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call||!output||bytes!=sizeof(GameGpuIdentity))return 0;
    game_memset(output,0,bytes);GameImGuiContext* c=game_context(handle);if(!c)return 0;
#ifndef GAME_IMGUI_PORTABLE_TEST
    IDXGIDevice* dxgi=0;IDXGIAdapter* adapter=0;DXGI_ADAPTER_DESC desc={};LARGE_INTEGER version={};
    HRESULT hr=c->device->QueryInterface(__uuidof(IDXGIDevice),reinterpret_cast<void**>(&dxgi));
    if(SUCCEEDED(hr)&&dxgi)hr=dxgi->GetAdapter(&adapter);
    if(SUCCEEDED(hr)&&adapter)hr=adapter->GetDesc(&desc);
    /* IDXGIDevice, not ID3D11Device: this is the documented UMD package
       version query. Failure means unknown, never synthetic compatibility. */
    if(SUCCEEDED(hr)&&adapter)hr=adapter->CheckInterfaceSupport(__uuidof(IDXGIDevice),&version);
    if(adapter)adapter->Release();if(dxgi)dxgi->Release();
    if(FAILED(hr)||version.QuadPart<=0)return 0;
    GameGpuIdentity identity={1,sizeof(GameGpuIdentity),desc.VendorId,desc.DeviceId,desc.SubSysId,desc.Revision,static_cast<uint64_t>(version.QuadPart)};
    game_memcpy(output,&identity,sizeof(identity));return 1;
#else
    return 0;
#endif
}
extern "C" int32_t GAME_IMGUI_CALL game_imgui_last_error(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT {
    GameApiCall call;if(!call)return -1;GameImGuiContext* c=game_context(handle);if(!c)return -1;if(game_imgui_runtime_failed)return c->last_error<0?c->last_error:-2;if(game_imgui_dx11_failed)return game_imgui_dx11_error<0?game_imgui_dx11_error:-3;return c->last_error;}

#ifdef GAME_IMGUI_FAULT_TESTS
extern "C" size_t game_imgui_test_live_arena_bytes(){return game_arena.first?game_arena.live_bytes:0;}
extern "C" void* game_imgui_test_retain_device(GameImGuiHandle handle){
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);
    if(!c||!c->device)return 0;c->device->AddRef();return c->device;
}
#endif

/* Compiler-generated structure copies may call the conventional C symbols
   even with source calls redirected. Define these locally, without a C RTL. */
#undef memcpy
#undef memmove
#undef memset
#if defined(__GNUC__) && !defined(__BORLANDC__)
#define GAME_CRT_NOEXCEPT noexcept
#else
#define GAME_CRT_NOEXCEPT
#endif
extern "C" void* GAME_IMGUI_CALL memcpy(void* d,const void* s,size_t n) GAME_CRT_NOEXCEPT {return game_memcpy(d,s,n);}
extern "C" void* GAME_IMGUI_CALL memmove(void* d,const void* s,size_t n) GAME_CRT_NOEXCEPT {return game_memmove(d,s,n);}
extern "C" void* GAME_IMGUI_CALL memset(void* d,int v,size_t n) GAME_CRT_NOEXCEPT {return game_memset(d,v,n);}
#ifdef GAME_IMGUI_PORTABLE_TEST
extern "C" int game_imgui_test_contract_state(GameImGuiHandle handle,uint32_t* words,uint32_t count){
    GameApiCall call;if(!call||!words||count!=9)return 0;
    GameImGuiContext* c=game_context(handle);if(!c)return 0;
    words[0]=c->frame_started;words[1]=c->canvas_started;words[2]=c->canvas_begun;
    words[3]=c->widgets;words[4]=c->text_bytes;words[5]=GImGui->InputEventsQueue.Size;
    words[6]=game_imgui_runtime_failed||game_imgui_dx11_failed;
    words[7]=c->text_input!=0;words[8]=c->input_focused;return 1;
}
extern "C" unsigned game_imgui_test_scene_focus(GameImGuiHandle handle){GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);return c?c->scene_control_index:0;}
extern "C" int game_imgui_test_scene_state(GameImGuiHandle handle,float* values,uint32_t count){
    GameApiCall call;if(!call||!values||count!=5)return 0;GameImGuiContext* c=game_context(handle);if(!c)return 0;
    values[0]=c->scene_position;values[1]=c->scene_dragging?1.0f:0.0f;values[2]=static_cast<float>(c->scene_tab);
    values[3]=c->scene_velocity;values[4]=c->scene_tab_position;return 1;
}
extern "C" int game_imgui_test_scene_detail(GameImGuiHandle handle,float* values,unsigned count) {
    GameApiCall call;if(!call)return 0;GameImGuiContext* c=game_context(handle);if(!c||!values||count!=7)return 0;
    values[0]=c->scene_detail_open?1.0f:0.0f;values[1]=static_cast<float>(c->scene_detail_index);values[2]=c->scene_detail_mix;
    for(unsigned i=0;i<3;++i)values[3+i]=c->scene_accent[i];
    const int selected=(static_cast<int>(ImFloor(c->scene_position+0.5f))%6+6)%6;
    values[6]=static_cast<float>(cozy_scene_tab_base(c->scene_tab)+selected);return 1;
}

extern "C" float game_imgui_test_scene_gap(float position,int slot) {
    GameApiCall call;if(!call||!(position>=-12&&position<=12)||slot<-12||slot>24)return -1;
    return cozy_scene_card_x(slot+1,position)-cozy_scene_width(slot+1-position)*0.5f-
      (cozy_scene_card_x(slot,position)+cozy_scene_width(slot-position)*0.5f);
}
extern "C" int game_imgui_test_utf8(const char* text){return game_utf8_text(text,0)?1:0;}
extern "C" int game_imgui_test_queue_size(){return GImGui?GImGui->InputEventsQueue.Size:0;}
extern "C" size_t game_imgui_test_arena_peak(){return game_arena.peak_bytes;}
extern "C" size_t game_imgui_test_arena_largest(){return game_arena_largest();}
extern "C" void* game_imgui_test_arena_pressure(size_t bytes){return game_arena_alloc(bytes);}
extern "C" void game_imgui_test_arena_release(void* p){game_arena_free(p);}
extern "C" int game_imgui_test_gpu_error(GameImGuiHandle handle,int32_t value){
    GameApiCall call;if(!call||!game_context(handle))return 0;
    game_dx11_result(value);return 1;
}
extern "C" int game_imgui_test_atoi(const char* value){return game_atoi(value);}
extern "C" int game_imgui_test_draw_vertices(GameImGuiHandle handle){if(!game_context(handle))return 0;ImDrawData* data=ImGui::GetDrawData();return data?data->TotalVtxCount:0;}
extern "C" int game_imgui_test_input_state(GameImGuiHandle handle,int id){if(!game_context(handle))return -1;ImGuiIO& io=ImGui::GetIO();switch(id){case 0:return io.MouseDown[0];case 1:return io.MouseClicked[0];case 2:return io.MouseReleased[0];case 3:return GImGui->ActiveId!=0;case 4:return GImGui->HoveredId!=0;case 5:return static_cast<int>(io.MousePos.x);case 6:return static_cast<int>(io.MousePos.y);case 7:return io.MouseDownOwned[0];case 8:return static_cast<int>(ImGui::GetKeyOwner(ImGuiKey_MouseLeft));case 9:return GImGui->ActiveIdIsAlive!=0;default:return -1;}}
extern "C" int game_imgui_test_no_files(GameImGuiHandle handle){return game_context(handle)&&!ImGui::GetIO().IniFilename&&!ImGui::GetIO().LogFilename;}
#endif
