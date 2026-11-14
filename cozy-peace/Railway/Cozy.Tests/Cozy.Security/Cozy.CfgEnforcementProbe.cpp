/* Cozy central native text imports. */
#include "../../Cozy.ImGui/Cozy.Strings/Cozy.Strings.Tests.h"
#line 1
/* Cozy central native text imports. */
#line 1
/* Cozy central native text imports. */
#line 1
// Standalone MSVC/Windows CFG experiment, never linked into A/B/O.
// The same source is compiled with and without CFG to provide a negative control.
// Only self-created child processes and a six-byte constant-return function are used.
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#if !defined(_WIN64) || !defined(_M_X64) || !defined(_MSC_VER)
#error This probe requires the actual Microsoft Windows x64 C++ toolchain.
#endif
#if !defined(GAME_EXPECT_CFG)
#error Build with GAME_EXPECT_CFG=1 or GAME_EXPECT_CFG=0.
#endif

static_assert(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE == 10,
              COZY_TEXT_CFGENFORCEMENTPROBE_REVIEW_THE_INSTALLED_WINDOWS_SDK_CFG_FAILURE_CON_329FF3B5);
static const DWORD kCfgFailFast = 0xC0000409UL;
static const DWORD kTimeoutExit = 0xE000CF01UL;
typedef int(__cdecl* GeneratedFunction)();
static GeneratedFunction volatile gTarget = nullptr;

// Prevent whole-program devirtualization of the operation being tested.
__declspec(noinline) static int InvokeGeneratedFunction() {
    GeneratedFunction target = gTarget;
    _ReadWriteBarrier();
    const int result = target();
    _ReadWriteBarrier();
    return result;
}

static int Child(bool valid) {
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy = {};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy,
                                    &policy, sizeof(policy))) return 101;
#if GAME_EXPECT_CFG
    if (!policy.EnableControlFlowGuard) return 102;
#endif
    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    const SIZE_T bytes = info.dwPageSize;
    // PAGE_TARGETS_INVALID is intentionally retained when changing RWX -> RX.
    BYTE* page = static_cast<BYTE*>(VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE | PAGE_TARGETS_INVALID));
    if (!page) return 103;
    const BYTE code[] = {0xB8, 0x56, 0x34, 0x00, 0x00, 0xC3}; // mov eax,3456h; ret
    CopyMemory(page, code, sizeof(code));
    DWORD oldProtection = 0;
    if (!VirtualProtect(page, bytes, PAGE_EXECUTE_READ | PAGE_TARGETS_NO_UPDATE,
                        &oldProtection)) { VirtualFree(page, 0, MEM_RELEASE); return 104; }
    if (!FlushInstructionCache(GetCurrentProcess(), page, sizeof(code))) {
        VirtualFree(page, 0, MEM_RELEASE); return 105;
    }
    if (valid) {
        CFG_CALL_TARGET_INFO target = {};
        target.Offset = 0;
        target.Flags = CFG_CALL_TARGET_VALID;
        if (!SetProcessValidCallTargets(GetCurrentProcess(), page, bytes, 1, &target)) {
            VirtualFree(page, 0, MEM_RELEASE); return 106;
        }
    }
    gTarget = reinterpret_cast<GeneratedFunction>(page);
    // The debugger requires this exact marker before accepting a CFG exception.
    OutputDebugStringA(valid ? COZY_TEXT_CFGENFORCEMENTPROBE_GAME_CFG_READY_VALID_V1_53384093 : COZY_TEXT_CFGENFORCEMENTPROBE_GAME_CFG_READY_INVALID_V1_36FB3958);
    const int actual = InvokeGeneratedFunction();
    gTarget = nullptr;
    VirtualFree(page, 0, MEM_RELEASE);
    return actual == 0x3456 ? 0 : 107;
}

#if GAME_EXPECT_CFG
struct CaseResult {
    const char* id;
    bool launched;
    bool ready;
    bool policyQueried;
    bool cfgEnabled;
    bool exited;
    bool timedOut;
    bool secondChance;
    DWORD exitCode;
    DWORD exceptionCode;
    ULONG_PTR fastFailCode;
    DWORD unexpectedException;
    DWORD error;
    unsigned int expectedExceptionCount;
};

static bool ExactReadyMarker(HANDLE child, const OUTPUT_DEBUG_STRING_INFO& value, bool valid) {
    const char* expected = valid ? COZY_TEXT_CFGENFORCEMENTPROBE_GAME_CFG_READY_VALID_V1_53384093 : COZY_TEXT_CFGENFORCEMENTPROBE_GAME_CFG_READY_INVALID_V1_36FB3958;
    const SIZE_T expectedLength = valid ? sizeof(COZY_TEXT_CFGENFORCEMENTPROBE_GAME_CFG_READY_VALID_V1_53384093)
                                       : sizeof(COZY_TEXT_CFGENFORCEMENTPROBE_GAME_CFG_READY_INVALID_V1_36FB3958);
    if (value.fUnicode || value.nDebugStringLength != expectedLength) return false;
    char buffer[64] = {};
    SIZE_T read = 0;
    return ReadProcessMemory(child, value.lpDebugStringData, buffer, expectedLength, &read) &&
           read == expectedLength && memcmp(buffer, expected, expectedLength) == 0;
}

static CaseResult RunChild(const char* id, const wchar_t* executable, bool valid) {
    CaseResult result = {};
    result.id = id;
    result.exitCode = STILL_ACTIVE;
    wchar_t command[32768] = {};
    if (swprintf_s(command, COZY_TEXT_CFGENFORCEMENTPROBE_S_CHILD_S_15472C08, executable,
                   valid ? COZY_TEXT_CFGENFORCEMENTPROBE_VALID_B2561407 : COZY_TEXT_CFGENFORCEMENTPROBE_INVALID_96F4E495) < 0) { result.error = ERROR_BAD_ARGUMENTS; return result; }
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child = {};
    if (!CreateProcessW(executable, command, nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &child)) { result.error = GetLastError(); return result; }
    result.launched = true;
    if (!DebugSetProcessKillOnExit(TRUE)) {
        result.error = GetLastError();
        TerminateProcess(child.hProcess, kTimeoutExit);
    }
    const ULONGLONG deadline = GetTickCount64() + 15000;
    bool initialBreakpointSeen = false;
    bool terminating = false;
    ULONGLONG terminationDeadline = 0;
    while (!result.exited) {
        const ULONGLONG now = GetTickCount64();
        if (!terminating && now >= deadline) {
            result.timedOut = true;
            terminating = true;
            terminationDeadline = now + 3000;
            if (!TerminateProcess(child.hProcess, kTimeoutExit)) result.error = GetLastError();
        }
        if (terminating && now >= terminationDeadline) { result.error = ERROR_TIMEOUT; break; }
        DEBUG_EVENT event = {};
        if (!WaitForDebugEvent(&event, 100)) {
            if (GetLastError() != ERROR_SEM_TIMEOUT) { result.error = GetLastError(); break; }
            continue;
        }
        DWORD continueStatus = DBG_CONTINUE;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            if (ExactReadyMarker(child.hProcess, event.u.DebugString, valid)) {
                if (result.ready) { result.error = ERROR_INVALID_DATA; break; }
                result.ready = true;
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy = {};
                result.policyQueried = GetProcessMitigationPolicy(child.hProcess,
                    ProcessControlFlowGuardPolicy, &policy, sizeof(policy)) != FALSE;
                result.cfgEnabled = result.policyQueried && policy.EnableControlFlowGuard != 0;
                if (!result.policyQueried) result.error = GetLastError();
            }
            break;
        case EXCEPTION_DEBUG_EVENT: {
            const EXCEPTION_DEBUG_INFO& detail = event.u.Exception;
            const EXCEPTION_RECORD& record = detail.ExceptionRecord;
            if (!initialBreakpointSeen && !result.ready && record.ExceptionCode == EXCEPTION_BREAKPOINT &&
                detail.dwFirstChance) {
                initialBreakpointSeen = true;
            } else {
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                result.exceptionCode = record.ExceptionCode;
                if (result.ready && record.ExceptionCode == kCfgFailFast &&
                    record.NumberParameters >= 1 &&
                    record.ExceptionInformation[0] == FAST_FAIL_GUARD_ICALL_CHECK_FAILURE &&
                    detail.dwFirstChance == 0 && (record.ExceptionFlags & EXCEPTION_NONCONTINUABLE)) {
                    result.secondChance = true;
                    result.fastFailCode = record.ExceptionInformation[0];
                    ++result.expectedExceptionCount;
                } else {
                    result.unexpectedException = record.ExceptionCode;
                }
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            result.exitCode = event.u.ExitProcess.dwExitCode;
            result.exited = true;
            break;
        default:
            break;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus)) {
            result.error = GetLastError(); break;
        }
    }
    if (!result.exited) TerminateProcess(child.hProcess, kTimeoutExit);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return result;
}

static bool Pass(const CaseResult& value, bool expectFailure, bool requireCfg) {
    if (!value.launched || !value.ready || !value.policyQueried || !value.exited ||
        value.timedOut || value.error || value.unexpectedException ||
        (requireCfg && !value.cfgEnabled)) return false;
    if (expectFailure) return value.exitCode == kCfgFailFast && value.exceptionCode == kCfgFailFast &&
        value.secondChance && value.fastFailCode == FAST_FAIL_GUARD_ICALL_CHECK_FAILURE &&
        value.expectedExceptionCount == 1;
    return value.exitCode == 0 && value.exceptionCode == 0 && value.expectedExceptionCount == 0;
}

static void Print(const CaseResult& value) {
    printf(COZY_TEXT_CFGENFORCEMENTPROBE_ID_S_LAUNCHED_S_READY_S_POLICYQUERYSUCCEEDED_S_CF4EA582
           COZY_TEXT_CFGENFORCEMENTPROBE_CONTROLFLOWGUARDENABLED_S_EXITED_S_TIMEDOUT_S_126B4B56
           COZY_TEXT_CFGENFORCEMENTPROBE_EXITCODE_LU_EXCEPTIONCODE_LU_SECONDCHANCE_S_0C616BE1
           COZY_TEXT_CFGENFORCEMENTPROBE_FASTFAILCODE_LLU_EXPECTEDEXCEPTIONCOUNT_U_AC7CFED4
           COZY_TEXT_CFGENFORCEMENTPROBE_UNEXPECTEDEXCEPTION_LU_WIN32ERROR_LU_C29A6DB8, value.id,
           value.launched ? COZY_TEXT_CFGENFORCEMENTPROBE_TRUE_E002152D : COZY_TEXT_CFGENFORCEMENTPROBE_FALSE_98039F5C, value.ready ? COZY_TEXT_CFGENFORCEMENTPROBE_TRUE_E002152D : COZY_TEXT_CFGENFORCEMENTPROBE_FALSE_98039F5C,
           value.policyQueried ? COZY_TEXT_CFGENFORCEMENTPROBE_TRUE_E002152D : COZY_TEXT_CFGENFORCEMENTPROBE_FALSE_98039F5C, value.cfgEnabled ? COZY_TEXT_CFGENFORCEMENTPROBE_TRUE_E002152D : COZY_TEXT_CFGENFORCEMENTPROBE_FALSE_98039F5C,
           value.exited ? COZY_TEXT_CFGENFORCEMENTPROBE_TRUE_E002152D : COZY_TEXT_CFGENFORCEMENTPROBE_FALSE_98039F5C, value.timedOut ? COZY_TEXT_CFGENFORCEMENTPROBE_TRUE_E002152D : COZY_TEXT_CFGENFORCEMENTPROBE_FALSE_98039F5C,
           value.exitCode, value.exceptionCode, value.secondChance ? COZY_TEXT_CFGENFORCEMENTPROBE_TRUE_E002152D : COZY_TEXT_CFGENFORCEMENTPROBE_FALSE_98039F5C,
           static_cast<unsigned long long>(value.fastFailCode), value.expectedExceptionCount,
           value.unexpectedException, value.error);
}
#endif

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 3 && wcscmp(argv[1], COZY_TEXT_CFGENFORCEMENTPROBE_CHILD_CDAFD69B) == 0) {
        if (wcscmp(argv[2], COZY_TEXT_CFGENFORCEMENTPROBE_VALID_B2561407) == 0) return Child(true);
        if (wcscmp(argv[2], COZY_TEXT_CFGENFORCEMENTPROBE_INVALID_96F4E495) == 0) return Child(false);
        return 108;
    }
    if (argc != 3 || wcscmp(argv[1], COZY_TEXT_CFGENFORCEMENTPROBE_CONTROL_DB7EA9CD) != 0) return 109;
#if !GAME_EXPECT_CFG
    return 110;
#else
    wchar_t self[32768] = {};
    const DWORD length = GetModuleFileNameW(nullptr, self, static_cast<DWORD>(_countof(self)));
    if (!length || length >= _countof(self)) return 111;
    const CaseResult valid = RunChild(COZY_TEXT_CFGENFORCEMENTPROBE_GUARDED_VALID_TARGET_496438F4, self, true);
    const CaseResult invalid = RunChild(COZY_TEXT_CFGENFORCEMENTPROBE_GUARDED_INVALID_TARGET_F8D038D2, self, false);
    const CaseResult control = RunChild(COZY_TEXT_CFGENFORCEMENTPROBE_UNGUARDED_INVALID_TARGET_C965E7EC, argv[2], false);
    const bool pass = Pass(valid, false, true) && Pass(invalid, true, true) && Pass(control, false, false);
    printf(COZY_TEXT_CFGENFORCEMENTPROBE_VERSION_1_KIND_CFG_ENFORCEMENT_PROBE_SCOPE_MSVC__52D94563
           COZY_TEXT_CFGENFORCEMENTPROBE_PRODUCTIONCOVERAGE_FALSE_OUTCOME_S_CASES_64DCBB6A, pass ? COZY_TEXT_CFGENFORCEMENTPROBE_PASS_1505311B : COZY_TEXT_CFGENFORCEMENTPROBE_FAIL_91E35237);
    Print(valid); printf(COZY_TEXT_CFGENFORCEMENTPROBE_TEXT_1109AA1D); Print(invalid); printf(COZY_TEXT_CFGENFORCEMENTPROBE_TEXT_1109AA1D); Print(control); printf(COZY_TEXT_CFGENFORCEMENTPROBE_N_E38996A5);
    return pass ? 0 : 1;
#endif
}
