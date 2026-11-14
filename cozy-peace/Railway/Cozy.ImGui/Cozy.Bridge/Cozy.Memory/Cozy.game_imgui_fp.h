/* Cozy central native text imports. */
#include "../../Cozy.Strings/Cozy.Strings.Bridge.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
#ifndef COZY_GAME_IMGUI_FP_H
#define COZY_GAME_IMGUI_FP_H

/* The classic Delphi Win64 caller can enable overflow/divide/invalid traps.
   ImGui font baking and Direct3D expect the C++ IEEE environment: for example
   a font's FLT_MAX maximum advance scaled above 1 intentionally becomes Inf.
   Keep that environment inside each native call, never in the Delphi caller
   or another thread. Only mask exception traps; retain rounding, precision,
   denormal handling and all other caller controls. No OS/CRT imports or TLS.

   x87 is included for math/driver compatibility. Clear native pending x87
   exceptions before restoring its control word, so no delayed native fault
   escapes through a later Delphi instruction. MXCSR is restored exactly,
   dropping temporary native status flags and retaining the caller's flags. */
class GameFloatingPointScope {
    unsigned saved_mxcsr;
    unsigned short saved_x87;
public:
    GameFloatingPointScope() noexcept : saved_mxcsr(__builtin_ia32_stmxcsr()), saved_x87(0) {
        __asm__ __volatile__(COZY_TEXT_GAME_IMGUI_FP_FNSTCW_0_38C2DB2E : COZY_TEXT_GAME_IMGUI_FP_M_9FEA8A0D(saved_x87));
        const unsigned short masked_x87=static_cast<unsigned short>(saved_x87|0x003fu);
        __asm__ __volatile__(COZY_TEXT_GAME_IMGUI_FP_FNCLEX_N_TFLDCW_0_E3EC25B3 : : COZY_TEXT_GAME_IMGUI_FP_M_95FF0AC7(masked_x87) : COZY_TEXT_GAME_IMGUI_FP_MEMORY_D21AC13A);
        __builtin_ia32_ldmxcsr((saved_mxcsr|0x1f80u)&~0x003fu);
    }
    ~GameFloatingPointScope() noexcept {
        __asm__ __volatile__(COZY_TEXT_GAME_IMGUI_FP_FNCLEX_N_TFLDCW_0_E3EC25B3 : : COZY_TEXT_GAME_IMGUI_FP_M_95FF0AC7(saved_x87) : COZY_TEXT_GAME_IMGUI_FP_MEMORY_D21AC13A);
        __builtin_ia32_ldmxcsr(saved_mxcsr);
    }
    GameFloatingPointScope(const GameFloatingPointScope&)=delete;
    GameFloatingPointScope& operator=(const GameFloatingPointScope&)=delete;
};

#endif
