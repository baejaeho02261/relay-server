#ifndef GAME_IMGUI_CONFIG_H
#define GAME_IMGUI_CONFIG_H
#define IMGUI_DISABLE_WIN32_FUNCTIONS
#define IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS
#define IMGUI_DISABLE_TIME_FUNCTIONS
#define IMGUI_DISABLE_FILE_FUNCTIONS
#define IMGUI_DISABLE_DEFAULT_ALLOCATORS
#define IMGUI_DISABLE_DEMO_WINDOWS
#define IMGUI_DISABLE_DEBUG_TOOLS
/* Assertions are retained as fail-closed traps; no C assert/CRT dependency. */
#define IM_ASSERT(expression) do { if (!(expression)) game_imgui_assert_failed(); } while (0)
#endif
