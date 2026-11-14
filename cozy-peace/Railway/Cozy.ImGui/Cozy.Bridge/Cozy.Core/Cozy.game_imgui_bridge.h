/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
#ifndef GAME_IMGUI_BRIDGE_H
#define GAME_IMGUI_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#if defined(_WIN32)
#define GAME_IMGUI_CALL __cdecl
#else
#define GAME_IMGUI_CALL
#endif
#ifdef __cplusplus
#define GAME_IMGUI_NOEXCEPT noexcept
extern "C" {
#else
#define GAME_IMGUI_NOEXCEPT
#endif
/* Versioned C ABI. Win64 size is 32, default 8-byte packing. No C++ ABI crosses it.
   Cozy.ImGui.Abi.json is the reviewed C/Pascal contract.
   Cozy.Check-ImGui-Abi.js rejects declaration drift and stale compile probes. */
enum GameImGuiProcId {
    GI_PROC_D3D11_CREATE = 1,
    GI_PROC_D3D_COMPILE = 2,
    GI_PROC_CRT_VSPRINTF = 3, /* __stdio_common_vsprintf */
    GI_PROC_CRT_VSSCANF = 4,  /* __stdio_common_vsscanf */
    GI_PROC_STRTOD = 5,
    GI_PROC_ACOS = 6,
    GI_PROC_ATAN2 = 7,
    GI_PROC_CEIL = 8,
    GI_PROC_COS = 9,
    GI_PROC_FABS = 10,
    GI_PROC_FLOOR = 11,
    GI_PROC_FMOD = 12,
    GI_PROC_LOG = 13,
    GI_PROC_POW = 14,
    GI_PROC_SIN = 15,
    GI_PROC_SQRT = 16,
    GI_PROC_THREAD_ID = 17,
    GI_PROC_DCOMP_CREATE = 18,
    GI_PROC_LAST = 18
};
/* Closed FACILITY_ITF failures for the bridge's own CPU admission checks.
   These identify the actual internal gate, not a Windows/GPU allocation.
   Keep actual driver HRESULTs unchanged. Decimal values are signed int32
   in both C and C++; the existing CREATE diagnostic transports them as-is. */
enum GameImGuiAdmissionError {
    GI_ERROR_HOST_CONTEXT = -2147171839, /* 0x8004C201 */
    GI_ERROR_HOST_ARENA = -2147171838,   /* 0x8004C202 */
    GI_ERROR_FONT_COPY = -2147171837,    /* 0x8004C203 */
    GI_ERROR_FRAME_RESERVE = -2147171836 /* 0x8004C204: shared frame/upload CPU reserve */
};
typedef void* (GAME_IMGUI_CALL *GameImGuiGetProc)(int32_t id);
typedef void* (GAME_IMGUI_CALL *GameImGuiAlloc)(size_t bytes);
typedef void (GAME_IMGUI_CALL *GameImGuiFree)(void* memory);
typedef struct GameImGuiHost {
    uint32_t abi_version; /* 3 */
    uint32_t struct_size; /* sizeof(GameImGuiHost) = 32 on Win64 */
    GameImGuiGetProc get_proc;
    GameImGuiAlloc alloc;
    GameImGuiFree free;
} GameImGuiHost;
typedef void* GameImGuiHandle;
/* Resize/NewFrame result: 0 failure, 1 success. Present: -1 failure, 0 occluded, 1 visible.
   Destroy: 0 rejected, 1 destroyed. Handles are opaque generation tokens.
   All operations reject concurrent/reentrant entry and calls from a non-owner
   thread. A failed Destroy leaves the handle owned by its original caller.
   No function throws a C++ exception. Failure closes the authenticated overlay. */
/* The exposed UI is deliberately bounded: one canvas/frame, <=8 reviewed UTF-8 items,
   <=512 text bytes/frame, <=127 bytes/item, <=256 pending input events,
   viewport <=16384 and DPI 0.5..8.0. The complete 64MiB CPU arena is committed
   before entering ImGui. Host OOM returns failure; a frame with insufficient
   contiguous reserve is rejected before core/backend NewFrame. Extending the
   surface/font set requires reviewing these bounds and rerunning the arena tests. */
/* Create returns 1 on success, 0 for invalid arguments/ownership, or a negative
   HRESULT for graphics/initial host-allocation failure. Output stays null on failure. */
int32_t GAME_IMGUI_CALL game_imgui_create(void* window, const GameImGuiHost* host, GameImGuiHandle* result) GAME_IMGUI_NOEXCEPT;
/* Korean v1 requires a bounded Windows TrueType font. Copies bytes immediately;
   required UI glyph absence is a failure, not a silently missing-glyph render. */
int32_t GAME_IMGUI_CALL game_imgui_create_korean_v1(void* window, const GameImGuiHost* host, const void* font_data, uint32_t font_bytes, GameImGuiHandle* result) GAME_IMGUI_NOEXCEPT;
/* B activation context uses the same reviewed font/COM path, without uploading
   gallery card textures. It cannot render a gallery. */
int32_t GAME_IMGUI_CALL game_imgui_create_license_korean_v1(void* window, const GameImGuiHost* host, const void* font_data, uint32_t font_bytes, GameImGuiHandle* result) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_destroy(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_resize(GameImGuiHandle handle, int32_t width, int32_t height) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_set_dpi(GameImGuiHandle handle, float scale) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_new_frame(GameImGuiHandle handle, int32_t width, int32_t height, float delta_seconds) GAME_IMGUI_NOEXCEPT;
/* Positions accept finite signed Win32 coordinates [-32768,32767]. Exact paired
   legacy (-1E30,-1E30) and ImGui (-FLT_MAX,-FLT_MAX) leave markers are normalized.
   Wheels accept finite values in [-16384,16384]. Rejected values enqueue nothing. */
void GAME_IMGUI_CALL game_imgui_mouse_pos(GameImGuiHandle handle, float x, float y) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_mouse_button(GameImGuiHandle handle, int32_t button, int32_t down) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_mouse_wheel(GameImGuiHandle handle, float horizontal, float vertical) GAME_IMGUI_NOEXCEPT;
/* Key numbers are Win32 virtual-key codes (VK_*), mapped privately by bridge. */
void GAME_IMGUI_CALL game_imgui_key(GameImGuiHandle handle, int32_t key, int32_t down) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_focus(GameImGuiHandle handle, int32_t focused) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_clear_input(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;
/* Optional Korean text-input extension v1. Disabled contexts allocate no input
   storage. Focus loss/cancel/disable wipes preedit, queued commits and UTF-16
   pending state. Input is printable ASCII + Hangul/Jamo, at most 512 UTF-8 bytes.
   action: 0 commit, 1 preedit, 2 begin, 3 end, 4 cancel. Only commit is final text.
   read kind 0 consumes committed text; kind 1 reads preedit; output must be 513
   bytes. -1 rejects a read, 0 is empty. Caller owns and wipes copied output.
   The normal window path consumes WM_CHAR only: IME messages go to DefWindowProc.
   display has a per-context budget of 128 extra glyphs; no unbounded font cache. */
uint32_t GAME_IMGUI_CALL game_imgui_text_input_version(void) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_text_input_enable_v1(GameImGuiHandle handle, int32_t enabled) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_text_input_utf8_v1(GameImGuiHandle handle, const char* text, uint32_t bytes, int32_t action) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_text_input_utf16_v1(GameImGuiHandle handle, uint32_t unit) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_text_input_read_v1(GameImGuiHandle handle, void* output, uint32_t bytes, uint32_t kind) GAME_IMGUI_NOEXCEPT;
uint32_t GAME_IMGUI_CALL game_imgui_text_input_status_v1(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_text_input_display_v1(GameImGuiHandle handle, const char* text, uint32_t bytes) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_begin_canvas(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_set_cursor_pos(GameImGuiHandle handle, float x, float y) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_button(GameImGuiHandle handle, const char* label_utf8, float width, float height, int32_t enabled) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_text(GameImGuiHandle handle, const char* text_utf8) GAME_IMGUI_NOEXCEPT;
void GAME_IMGUI_CALL game_imgui_end_canvas(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;
/* Legacy gallery v2. Call once inside Begin/EndCanvas with no other widgets.
   phase: 0/3 idle, 1 pending, 2 presentation. START is denied because this
   compatibility entry point carries no product entitlement.
   selected: 0..5; flags: reserved-dark=1, OS reduced motion=2, enable input=4.
   Time is finite 0..86400; periodic carousel position is finite -1..6 (initial position; native scene owns dragging/easing).
   Returns -1 on rejected call/failure; otherwise prev=2, next=4,
   select0..5 = 128 << index. It does not perform network requests,
   terminate processes or infer success from elapsed time. The host owns work.
   Fixed embedded gallery, six visible periodic cover tiles, three category
   tabs and one START control. Exclusive scene admission; no external text/path. */
int32_t GAME_IMGUI_CALL game_imgui_scene_v2(GameImGuiHandle handle, int32_t phase, int32_t selected, uint32_t flags, float animation_seconds, float carousel_position) GAME_IMGUI_NOEXCEPT;
/* Product gallery v3: category flags bits 4..5 are Cleaner=0, Mobile=1,
   Spoofer=2; low bits retain v2 meanings. licensed_card is -1 (none) or the
   immutable global card index 0..17 (Cleaner0..5, Spoofer6..11, Mobile12..17).
   START is available only for the exact licensed, centered card. This is UI
   gating only: the host must obtain a matching server authorization.
   phase0/3 idle, phase1 authorization pending, phase2 authorized presentation.
   Phases1/2 block every control and moderately blur the UI. run_progress
   is finite0..1, supplied by the host; the local clock animates only the water. Tab actions bits13..15.
   Legacy scene_v2 has no entitlement and cannot emit START. */
int32_t GAME_IMGUI_CALL game_imgui_scene_v3(GameImGuiHandle handle, int32_t phase, int32_t selected, uint32_t flags, float animation_seconds, float carousel_position, int32_t licensed_card, float run_progress) GAME_IMGUI_NOEXCEPT;
/* Activation panel: host owns and erases the key. Only its length0..100 is
   supplied; no plaintext is copied into ImGui or native static buffers.
   phase0 idle,1busy,2silent retry,3closing. run_progress is finite0..1 and
   follows actual host work, never elapsed animation time. Busy/closing show
   animated water and a percentage capped at99 until the host transfers.
   Empty input hint is visible only while unfocused. Initial focus is idle;
   phase2 restores input focus for a silent retry.
   Return submit1, input focus4, input blur8. No custom close action.
   Input hit rectangle is (49,185)..(291,227), scaled from 340x380. */
int32_t GAME_IMGUI_CALL game_imgui_license_scene_v1(GameImGuiHandle handle, int32_t phase, int32_t key_characters, float run_progress) GAME_IMGUI_NOEXCEPT;
int32_t GAME_IMGUI_CALL game_imgui_render_present(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;
/* Writes a versioned 32-byte LE GPU snapshot: version,size,VendorId,DeviceId,
   SubSysId,Revision (six uint32), driverVersion (uint64). No transient LUID.
   Actual created device only; returns0 and zeroes valid-size output if unavailable. */
int32_t GAME_IMGUI_CALL game_imgui_gpu_identity(GameImGuiHandle handle, void* output, uint32_t bytes) GAME_IMGUI_NOEXCEPT;
/* Diagnostic numeric HRESULT/internal status only; no token or server data. */
int32_t GAME_IMGUI_CALL game_imgui_last_error(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;
uint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT;
#ifdef __cplusplus
}
/* Compiler layout evidence complements the source cross-check. No runtime code. */
static_assert(sizeof(void*) == 8, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_HOST_REQUIRES_WIN64_SIZED_POINTERS_F1FF1AF8);
static_assert(sizeof(GameImGuiHost) == 32, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_HOST_ABI_SIZE_61B82DFB);
static_assert(alignof(GameImGuiHost) == 8, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_HOST_ABI_ALIGNMENT_FC6A883E);
static_assert(offsetof(GameImGuiHost, abi_version) == 0, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_VERSION_OFFSET_C4567078);
static_assert(offsetof(GameImGuiHost, struct_size) == 4, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_SIZE_OFFSET_4FACCD47);
static_assert(offsetof(GameImGuiHost, get_proc) == 8, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_GET_PROC_OFFSET_6CFEE93E);
static_assert(offsetof(GameImGuiHost, alloc) == 16, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_ALLOC_OFFSET_2FB22D1A);
static_assert(offsetof(GameImGuiHost, free) == 24, COZY_TEXT_GAME_IMGUI_BRIDGE_IMGUI_ABI_FREE_OFFSET_FA36BF35);
#endif
#endif
