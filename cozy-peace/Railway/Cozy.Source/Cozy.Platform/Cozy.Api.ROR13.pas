unit Cozy.Api.ROR13;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$J-}

interface

{ API identifiers only: unsigned 32-bit ROR13, seed 0, rotate THEN add each
  case-sensitive ANSI byte, modulo 2^32. The terminating NUL is not included.
  These are numeric constants, not an array of API-name string literals.
  This is a lookup hash, not a cryptographic integrity/authentication hash. }
const
  HASH_D3D11CreateDevice: Cardinal = $4B00B47B;
  HASH_DCompositionCreateDevice: Cardinal = $7E9EB0FE;
  HASH_PeekMessageW: Cardinal = $F2667C0A;
  HASH_MsgWaitForMultipleObjectsEx: Cardinal = $94F0F084;
  HASH_SetCursor: Cardinal = $BC4F79F4;
  HASH_CreateRoundRectRgn: Cardinal = $75A18632;
  HASH_SetWindowRgn: Cardinal = $8AA0B25A;
  HASH_DeleteObject: Cardinal = $FE3DA875;
  HASH_LookupPrivilegeValueW: Cardinal = $97E8C2B8;
  HASH_ResumeThread: Cardinal = $9E4A3F88;
  HASH_CreateProcessAsUserW: Cardinal = $635DC4A1;
  HASH_SetTokenInformation: Cardinal = $DEDB6E5A;
  HASH_GetTokenInformation: Cardinal = $DBDB6E5A;
  HASH_CreateRestrictedToken: Cardinal = $E2E2E846;
  HASH_OpenProcessToken: Cardinal = $591EA70F;
  HASH_FreeAddrInfoExW: Cardinal = $C0B8BE6F;
  HASH_GetAddrInfoExW: Cardinal = $AB55A66F;
  HASH_BCryptVerifySignature: Cardinal = $B079EC11;
  HASH_IsWindowVisible: Cardinal = $8015A186;
  HASH___stdio_common_vsprintf: Cardinal = $5871BAA2;
  HASH___stdio_common_vsscanf: Cardinal = $1947B900;
  HASH_acos: Cardinal = $C5781933;
  HASH_AcquireSRWLockExclusive: Cardinal = $A77D8D5A;
  HASH_ReleaseSRWLockExclusive: Cardinal = $557E6DA6;
  HASH_DeviceIoControl: Cardinal = $A8E14A7D;
  HASH_GetIfTable2: Cardinal = $FCC95C8E;
  HASH_FreeMibTable: Cardinal = $AC988AD3;
  HASH_AcquireCredentialsHandleW: Cardinal = $820951D2;
  HASH_AllocConsole: Cardinal = $D9F868D8;
  HASH_atan2: Cardinal = $EB762872;
  HASH_BCryptCloseAlgorithmProvider: Cardinal = $F783037B;
  HASH_BCryptCreateHash: Cardinal = $8105A138;
  HASH_BCryptDecrypt: Cardinal = $592029A4;
  HASH_BCryptDestroyHash: Cardinal = $2616AE7A;
  HASH_BCryptDestroyKey: Cardinal = $D5E24588;
  HASH_BCryptEncrypt: Cardinal = $D92429A8;
  HASH_BCryptExportKey: Cardinal = $D465F1AD;
  HASH_BCryptFinalizeKeyPair: Cardinal = $90B2A65B;
  HASH_BCryptFinishHash: Cardinal = $F825EA57;
  HASH_BCryptGenerateKeyPair: Cardinal = $08BA6A5D;
  HASH_BCryptGenerateSymmetricKey: Cardinal = $6AC778ED;
  HASH_BCryptGenRandom: Cardinal = $4AACE573;
  HASH_BCryptHashData: Cardinal = $E3122629;
  HASH_BCryptImportKeyPair: Cardinal = $024CF639;
  HASH_BCryptOpenAlgorithmProvider: Cardinal = $AD3B3E2C;
  HASH_BCryptSetProperty: Cardinal = $211E1E4F;
  HASH_BeginPaint: Cardinal = $2C1B37CC;
  HASH_CancelIoEx: Cardinal = $76BD022B;
  HASH_CancelSynchronousIo: Cardinal = $7E2FD007;
  HASH_ceil: Cardinal = $C94819AC;
  HASH_CertFreeCertificateContext: Cardinal = $76331805;
  HASH_CertVerifyTimeValidity: Cardinal = $535F301F;
  HASH_CloseClipboard: Cardinal = $089B753A;
  HASH_CloseHandle: Cardinal = $0FFD97FB;
  HASH_closesocket: Cardinal = $79C679E7;
  HASH_CoCreateGuid: Cardinal = $C55A929A;
  HASH_connect: Cardinal = $60AAF9EC;
  HASH_cos: Cardinal = $03781933;
  HASH_CreateEventW: Cardinal = $30C4B297;
  HASH_CreateFileW: Cardinal = $7C0017BB;
  HASH_CreatePipe: Cardinal = $170C8F80;
  HASH_CreateProcessW: Cardinal = $16B3FE88;
  HASH_CreateThread: Cardinal = $CA2BD06B;
  HASH_CreateWindowExW: Cardinal = $84454957;
  HASH_CryptHashCertificate2: Cardinal = $83865CAE;
  HASH_D3D11CreateDeviceAndSwapChain: Cardinal = $5860BF97;
  HASH_D3DCompile: Cardinal = $9775135D;
  HASH_DecodePointer: Cardinal = $853C36A3;
  HASH_DecryptMessage: Cardinal = $7D3D25C5;
  HASH_DefWindowProcW: Cardinal = $B9A87739;
  HASH_DeleteProcThreadAttributeList: Cardinal = $1806CEBD;
  HASH_DeleteSecurityContext: Cardinal = $8FB67092;
  HASH_DestroyWindow: Cardinal = $94305BE0;
  HASH_DispatchMessageW: Cardinal = $690A1717;
  HASH_DuplicateHandle: Cardinal = $BD566724;
  HASH_EncodePointer: Cardinal = $854E36B3;
  HASH_EncryptMessage: Cardinal = $7DBD2655;
  HASH_EndPaint: Cardinal = $C72D2386;
  HASH_EnumProcessModulesEx: Cardinal = $AEFBDF52;
  HASH_fabs: Cardinal = $CF1018B3;
  HASH_FillConsoleOutputCharacterW: Cardinal = $423B9F86;
  HASH_FindResourceW: Cardinal = $3BD09A6B;
  HASH_floor: Cardinal = $DB7E7C32;
  HASH_FlushFileBuffers: Cardinal = $37F385D9;
  HASH_fmod: Cardinal = $CF781BA4;
  HASH_FreeConsole: Cardinal = $4F76990F;
  HASH_FreeContextBuffer: Cardinal = $29A8B16E;
  HASH_FreeCredentialsHandle: Cardinal = $2E9700B2;
  HASH_FreeLibrary: Cardinal = $4DC9D5A0;
  HASH_GetCapture: Cardinal = $D1A56456;
  HASH_GetClientRect: Cardinal = $157F8399;
  HASH_GetClipboardData: Cardinal = $4A077F0E;
  HASH_GetComputerNameW: Cardinal = $96A422A5;
  HASH_GetConsoleMode: Cardinal = $F14DF91C;
  HASH_GetCurrentProcess: Cardinal = $7B8F17E6;
  HASH_GetCurrentProcessId: Cardinal = $E60DFA02;
  HASH_GetCurrentThreadId: Cardinal = $35BBF99E;
  HASH_GetCursorPos: Cardinal = $ECD8B366;
  HASH_GetDpiForWindow: Cardinal = $DA5322DF;
  HASH_WTSRegisterSessionNotification: Cardinal = $CE267ECE;
  HASH_WTSUnRegisterSessionNotification: Cardinal = $1E415D06;
  HASH_MonitorFromWindow: Cardinal = $68E1A6EE;
  HASH_GetMonitorInfoW: Cardinal = $3D574BED;
  HASH_GetEnvironmentVariableW: Cardinal = $F2E1A979;
  HASH_GetExitCodeThread: Cardinal = $1B3F95F9;
  HASH_GetFileAttributesW: Cardinal = $56F73920;
  HASH_GetFileInformationByHandle: Cardinal = $C0132B93;
  HASH_GetFileType: Cardinal = $E12D9FAD;
  HASH_GetFinalPathNameByHandleW: Cardinal = $D86A2FE6;
  HASH_GetFullPathNameW: Cardinal = $31EC0070;
  HASH_GetHandleInformation: Cardinal = $7F9DF944;
  HASH_gethostbyname: Cardinal = $510CFDC4;
  HASH_GetLastError: Cardinal = $75DA1966;
  HASH_GetMessageW: Cardinal = $7AC67C03;
  HASH_GetModuleFileNameExW: Cardinal = $6FDB5EE8;
  HASH_GetModuleFileNameW: Cardinal = $45B06D8C;
  HASH_GetModuleHandleExW: Cardinal = $D052428B;
  HASH_GetModuleHandleW: Cardinal = $D332491A;
  HASH_GetOverlappedResult: Cardinal = $C087DCE8;
  HASH_GetProcAddress: Cardinal = $7C0DFCAA;
  HASH_GetProcessId: Cardinal = $FA9C1BAF;
  HASH_GetProcessMitigationPolicy: Cardinal = $B1179355;
  HASH_getsockopt: Cardinal = $C05592EC;
  HASH_GetStdHandle: Cardinal = $7487D823;
  HASH_GetSystemDirectoryW: Cardinal = $B8E579D7;
  HASH_GetSystemFirmwareTable: Cardinal = $5ADBD192;
  HASH_GetSystemTimeAsFileTime: Cardinal = $89D7610D;
  HASH_GetTickCount64: Cardinal = $E62EC931;
  HASH_GetWindowDisplayAffinity: Cardinal = $04ACA921;
  HASH_GetWindowRect: Cardinal = $927C5439;
  HASH_GlobalLock: Cardinal = $88A9223C;
  HASH_GlobalSize: Cardinal = $976120B6;
  HASH_GlobalUnlock: Cardinal = $BF608091;
  HASH_htons: Cardinal = $EB769C33;
  HASH_InitializeProcThreadAttributeList: Cardinal = $DE64CEFF;
  HASH_InitializeSecurityContextW: Cardinal = $9AC76E0C;
  HASH_InvalidateRect: Cardinal = $7711DD67;
  HASH_ioctlsocket: Cardinal = $EDE29208;
  HASH_IsClipboardFormatAvailable: Cardinal = $ED1162E0;
  HASH_KillTimer: Cardinal = $21DD6909;
  HASH_LoadCursorW: Cardinal = $CBA6C0E5;
  HASH_LdrRegisterDllNotification: Cardinal = $085BA97C;
  HASH_LdrUnregisterDllNotification: Cardinal = $37F49B95;
  HASH_LoadLibraryExW: Cardinal = $0753A512;
  HASH_log: Cardinal = $03781B67;
  HASH_MultiByteToWideChar: Cardinal = $EF4AC4E4;
  HASH_NCryptCreatePersistedKey: Cardinal = $120B6E36;
  HASH_NtGetNextThread: Cardinal = $88AC555C;
  HASH_NtQueryInformationThread: Cardinal = $00D83695;
  HASH_NCryptDeleteKey: Cardinal = $B5563F48;
  HASH_NCryptExportKey: Cardinal = $D46621AD;
  HASH_NCryptFinalizeKey: Cardinal = $DA9AD6A8;
  HASH_NCryptFreeObject: Cardinal = $C4958A33;
  HASH_NCryptGetProperty: Cardinal = $212A1E4C;
  HASH_NCryptImportKey: Cardinal = $D866204D;
  HASH_NCryptOpenKey: Cardinal = $D0F43EEE;
  HASH_NCryptOpenStorageProvider: Cardinal = $13A2CA10;
  HASH_NCryptSetProperty: Cardinal = $212A1E4F;
  HASH_NCryptSignHash: Cardinal = $F12A878A;
  HASH_NtTerminateProcess: Cardinal = $7929BBF3;
  HASH_OpenClipboard: Cardinal = $671DBB66;
  HASH_PeekNamedPipe: Cardinal = $B407C411;
  HASH_PostQuitMessage: Cardinal = $4BE0469D;
  HASH_pow: Cardinal = $03781C77;
  HASH_QueryContextAttributesW: Cardinal = $039B570A;
  HASH_QueryFullProcessImageNameW: Cardinal = $F660F694;
  HASH_ReadConsoleInputW: Cardinal = $27702B95;
  HASH_ReadFile: Cardinal = $10FA6516;
  HASH_recv: Cardinal = $E71819B6;
  HASH_RegCloseKey: Cardinal = $35E273E6;
  HASH_RegisterClassExW: Cardinal = $51E20CE0;
  HASH_RegOpenKeyExW: Cardinal = $A84AEB97;
  HASH_RegQueryValueExW: Cardinal = $FCBA95C1;
  HASH_ReleaseCapture: Cardinal = $497E38E0;
  HASH_ReOpenFile: Cardinal = $762994B8;
  HASH_RtlGetVersion: Cardinal = $D0C1869C;
  HASH_select: Cardinal = $5B1E69EE;
  HASH_send: Cardinal = $E97019A4;
  HASH_SetCapture: Cardinal = $D1A5C456;
  HASH_SetConsoleCtrlHandler: Cardinal = $C40E481F;
  HASH_SetConsoleCursorPosition: Cardinal = $982DAB93;
  HASH_SetConsoleMode: Cardinal = $F74DF91C;
  HASH_SetConsoleTitleW: Cardinal = $76A5E958;
  HASH_SetEvent: Cardinal = $F108744E;
  HASH_SetFileInformationByHandle: Cardinal = $20132B94;
  HASH_SetHandleInformation: Cardinal = $7F9E1144;
  HASH_SetLastError: Cardinal = $75F21966;
  HASH_SetProcessMitigationPolicy: Cardinal = $11179356;
  HASH_setsockopt: Cardinal = $C055F2EC;
  HASH_SetTimer: Cardinal = $D6C1664C;
  HASH_SetWindowDisplayAffinity: Cardinal = $062CA921;
  HASH_SetWindowPos: Cardinal = $8AE0B1DF;
  HASH_ShowWindow: Cardinal = $C95D4F83;
  HASH_shutdown: Cardinal = $4D5F6AC9;
  HASH_sin: Cardinal = $03481D2E;
  HASH_SizeofResource: Cardinal = $3F2A9609;
  HASH_Sleep: Cardinal = $DB2D49B0;
  HASH_socket: Cardinal = $492F0B6E;
  HASH_sqrt: Cardinal = $E9901CB4;
  HASH_strtod: Cardinal = $677F5D9E;
  HASH_Tbsip_Submit_Command: Cardinal = $55B56BCE;
  HASH_TerminateProcess: Cardinal = $78B5B983;
  HASH_TrackMouseEvent: Cardinal = $DA0A36B2;
  HASH_TranslateMessage: Cardinal = $8FDE2C7E;
  HASH_UnregisterClassW: Cardinal = $D53A404E;
  HASH_UpdateProcThreadAttribute: Cardinal = $41E5D7CB;
  HASH_VirtualAlloc: Cardinal = $91AFCA54;
  HASH_VirtualFree: Cardinal = $030633AC;
  HASH_VirtualProtect: Cardinal = $7946C61B;
  HASH_VirtualQuery: Cardinal = $A3C8C8AA;
  HASH_WaitForMultipleObjects: Cardinal = $23EAD524;
  HASH_WaitForSingleObject: Cardinal = $CE05D9AD;
  HASH_WriteConsoleW: Cardinal = $88D2F979;
  HASH_WriteFile: Cardinal = $E80A791F;
  HASH_WSACleanup: Cardinal = $19BD2C47;
  HASH_WSAGetLastError: Cardinal = $9F5B7976;
  HASH_WSAStartup: Cardinal = $3BFCEDCB;

{ One hash step, also used directly on the loaded DLL's export-name bytes.
  Explicit masking keeps the computation valid with overflow/range checking (Q+/R+). }
function ApiHashROR13Byte(Value: Cardinal; Octet: Byte): Cardinal; inline;
{ Utility for Cozy.tests/tools. Value contains the name bytes, without its NUL. }
function ApiHashROR13(const Value: AnsiString): Cardinal;

implementation

function ApiHashROR13Byte(Value: Cardinal; Octet: Byte): Cardinal;
var
  Rotated: Cardinal;
begin
  Rotated := Cardinal((UInt64(Value) shr 13) or
    ((UInt64(Value) and UInt64($00001FFF)) shl 19));
  Result := Cardinal((UInt64(Rotated) + UInt64(Octet)) and UInt64($FFFFFFFF));
end;

function ApiHashROR13(const Value: AnsiString): Cardinal;
var
  I: Integer;
begin
  Result := 0;
  for I := 1 to Length(Value) do
    Result := ApiHashROR13Byte(Result, Byte(Ord(Value[I])));
end;

end.
