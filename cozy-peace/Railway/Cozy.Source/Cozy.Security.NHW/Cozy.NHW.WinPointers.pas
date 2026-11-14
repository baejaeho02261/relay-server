unit Cozy.NHW.WinPointers;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils, System.SyncObjs;

// Explicit Win32 calls in all NHW units go through these resolved pointers.
// The TWO bootstrap imports GetModuleHandleW/GetProcAddress are used ONLY here
// to initialize the resolver. Delphi RTL/OS startup is outside this boundary.
// This does not bypass Windows access checks or make remote pointers readable.
procedure ResolveWinPointers;
function SnapshotWinFunctionPointers: TArray<NativeUInt>;
function WinModule(const Name: string): HMODULE;
function WinLoadLibrary(const Name: string): HMODULE;
function WinFreeLibrary(Module: HMODULE): BOOL;
function WinExport(Module: HMODULE; const Name: AnsiString): Pointer;
function WinCurrentProcessId: Cardinal;
function WinCurrentProcess: THandle;
function WinProcessIdToSessionId(PID: Cardinal; out SessionID: Cardinal): BOOL;
function WinWaitForSingleObject(Handle: THandle; Timeout: Cardinal): Cardinal;
procedure WinSleep(Milliseconds: Cardinal);
function WinTick64: UInt64;
function WinIsWow64Process(Handle: THandle; out Wow64: BOOL): BOOL;
function WinGetProcessTimes(Handle: THandle; out Created, Exited, Kernel, UserTime: TFileTime): BOOL;
function WinGetThreadTimes(Handle: THandle; out Created, Exited, Kernel, UserTime: TFileTime): BOOL;
function WinGetFileAttributes(Path: PWideChar): Cardinal;
function WinGetLastError: Cardinal;
function WinCreateFile(Path: PWideChar; Access, ShareMode: Cardinal;
  Security: Pointer; Disposition, Flags: Cardinal; TemplateHandle: THandle): THandle;
function WinCloseHandle(Handle: THandle): BOOL;
function WinDeviceIoControl(Device: THandle; Code: Cardinal; Input: Pointer;
  InputSize: Cardinal; Output: Pointer; OutputSize: Cardinal;
  var Returned: Cardinal; Overlapped: Pointer): BOOL;
function WinGetFileInformationByHandle(Handle: THandle;
  var Info: BY_HANDLE_FILE_INFORMATION): BOOL;

implementation

type
  TModuleW = function(Name: PWideChar): HMODULE; stdcall;
  TLibraryW = function(Name: PWideChar; Reserved: THandle;
    Flags: DWORD): HMODULE; stdcall;
  TFreeLibrary = function(Module: HMODULE): BOOL; stdcall;
  TProcA = function(Module: HMODULE; Name: PAnsiChar): Pointer; stdcall;
  TCurrentPID = function: Cardinal; stdcall;
  TProcessSession = function(PID: Cardinal; var SessionID: Cardinal): BOOL; stdcall;
  TCurrentProcess = function: THandle; stdcall;
  TWait = function(Handle: THandle; Milliseconds: Cardinal): Cardinal; stdcall;
  TSleep = procedure(Milliseconds: Cardinal); stdcall;
  TTick = function: UInt64; stdcall;
  TIsWow64 = function(Handle: THandle; var Wow64: BOOL): BOOL; stdcall;
  TTimes = function(Handle: THandle; var Created, Exited, Kernel, UserTime: TFileTime): BOOL; stdcall;
  TAttrs = function(Path: PWideChar): Cardinal; stdcall;
  TLastError = function: Cardinal; stdcall;
  TCreateFile = function(Path: PWideChar; Access, ShareMode: Cardinal;
    Security: Pointer; Disposition, Flags: Cardinal; TemplateHandle: THandle): THandle; stdcall;
  TCloseHandle = function(Handle: THandle): BOOL; stdcall;
  TDeviceIoControl = function(Device: THandle; Code: Cardinal; Input: Pointer;
    InputSize: Cardinal; Output: Pointer; OutputSize: Cardinal;
    var Returned: Cardinal; Overlapped: Pointer): BOOL; stdcall;
  TFileInfo = function(Handle: THandle; var Info: BY_HANDLE_FILE_INFORMATION): BOOL; stdcall;

var
  ResolutionLock: TLightweightMREW;
  ResolutionReady: Boolean;
  ModuleW: TModuleW = nil;
  LoadW: TLibraryW = nil;
  FreeLibraryPtr: TFreeLibrary = nil;
  ProcA: TProcA = nil;
  CurrentPID: TCurrentPID = nil;
  ProcessSessionPtr: TProcessSession = nil;
  CurrentProcess: TCurrentProcess = nil;
  WaitPtr: TWait = nil;
  SleepPtr: TSleep = nil;
  TickPtr: TTick = nil;
  Wow64Ptr: TIsWow64 = nil;
  ProcessTimesPtr: TTimes = nil;
  ThreadTimesPtr: TTimes = nil;
  AttrsPtr: TAttrs = nil;
  LastErrorPtr: TLastError = nil;
  CreateFilePtr: TCreateFile = nil;
  ClosePtr: TCloseHandle = nil;
  DeviceControlPtr: TDeviceIoControl = nil;
  FileInfoPtr: TFileInfo = nil;

function WinExport(Module: HMODULE; const Name: AnsiString): Pointer;
begin
  Result := nil;
  if (Module <> 0) and Assigned(ProcA) then
    Result := ProcA(Module, PAnsiChar(Name));
end;

function WinModule(const Name: string): HMODULE;
begin
  Result := 0;
  if Assigned(ModuleW) then
    Result := ModuleW(PWideChar(Name));
end;

function WinLoadLibrary(const Name: string): HMODULE;
const
  SystemDirectoryOnly = $00000800; // LOAD_LIBRARY_SEARCH_SYSTEM32
var
  Ch: Char;
begin
  Result := 0;
  if not Assigned(LoadW) or (Name = '') then Exit;
  for Ch in Name do
    if not CharInSet(Ch, ['a'..'z', 'A'..'Z', '0'..'9', '.', '_', '-']) then
      Exit;
  Result := LoadW(PWideChar(Name), 0, SystemDirectoryOnly);
end;

function WinFreeLibrary(Module: HMODULE): BOOL;
begin
  Result := False;
  if (Module <> 0) and Assigned(FreeLibraryPtr) then
    Result := FreeLibraryPtr(Module);
end;

function RequirePtr(Module: HMODULE; const Name: AnsiString): Pointer;
begin
  Result := WinExport(Module, Name);
  if Result = nil then raise Exception.Create('Win32 export unavailable');
end;

procedure ResolveBootstrapPointers(Kernel32: HMODULE);
begin
  ProcA := TProcA(Winapi.Windows.GetProcAddress(Kernel32, 'GetProcAddress'));
  if not Assigned(ProcA) then raise Exception.Create('Export bootstrap unavailable');
  ModuleW := TModuleW(RequirePtr(Kernel32, 'GetModuleHandleW'));
  LoadW := TLibraryW(WinExport(Kernel32, 'LoadLibraryExW'));
  FreeLibraryPtr := TFreeLibrary(WinExport(Kernel32, 'FreeLibrary'));
end;

procedure ResolveProcessAndTimingPointers(Kernel32: HMODULE);
begin
  CurrentPID := TCurrentPID(RequirePtr(Kernel32, 'GetCurrentProcessId'));
  ProcessSessionPtr := TProcessSession(WinExport(Kernel32, 'ProcessIdToSessionId'));
  CurrentProcess := TCurrentProcess(RequirePtr(Kernel32, 'GetCurrentProcess'));
  WaitPtr := TWait(RequirePtr(Kernel32, 'WaitForSingleObject'));
  SleepPtr := TSleep(RequirePtr(Kernel32, 'Sleep'));
  TickPtr := TTick(RequirePtr(Kernel32, 'GetTickCount64'));
  Wow64Ptr := TIsWow64(RequirePtr(Kernel32, 'IsWow64Process'));
  ProcessTimesPtr := TTimes(RequirePtr(Kernel32, 'GetProcessTimes'));
  ThreadTimesPtr := TTimes(RequirePtr(Kernel32, 'GetThreadTimes'));
end;

procedure ResolveFileAndDevicePointers(Kernel32: HMODULE);
begin
  AttrsPtr := TAttrs(RequirePtr(Kernel32, 'GetFileAttributesW'));
  LastErrorPtr := TLastError(RequirePtr(Kernel32, 'GetLastError'));
  CreateFilePtr := TCreateFile(RequirePtr(Kernel32, 'CreateFileW'));
  ClosePtr := TCloseHandle(RequirePtr(Kernel32, 'CloseHandle'));
  DeviceControlPtr := TDeviceIoControl(RequirePtr(Kernel32, 'DeviceIoControl'));
  FileInfoPtr := TFileInfo(RequirePtr(Kernel32, 'GetFileInformationByHandle'));
end;

procedure ResolveWinPointers;
var
  Kernel32: HMODULE;
begin
  ResolutionLock.BeginWrite;
  try
  if ResolutionReady then Exit;
  // Only Win32 bootstrap calls. All later explicit Win32 calls use ProcA.
  Kernel32 := Winapi.Windows.GetModuleHandle('kernel32.dll');
  if Kernel32 = 0 then raise Exception.Create('Win32 bootstrap unavailable');
  ResolveBootstrapPointers(Kernel32);
  ResolveProcessAndTimingPointers(Kernel32);
  ResolveFileAndDevicePointers(Kernel32);
  ResolutionReady := True;
  finally ResolutionLock.EndWrite; end;
end;

function WinCurrentProcessId: Cardinal;
begin Result := CurrentPID(); end;

function WinCurrentProcess: THandle;
begin Result := CurrentProcess(); end;

function WinProcessIdToSessionId(PID: Cardinal; out SessionID: Cardinal): BOOL;
begin
  SessionID := 0;
  if not Assigned(ProcessSessionPtr) then Exit(False);
  Result := ProcessSessionPtr(PID, SessionID);
end;

function WinWaitForSingleObject(Handle: THandle; Timeout: Cardinal): Cardinal;
begin Result := WaitPtr(Handle, Timeout); end;

procedure WinSleep(Milliseconds: Cardinal);
begin SleepPtr(Milliseconds); end;

function WinTick64: UInt64;
begin Result := TickPtr(); end;

function WinIsWow64Process(Handle: THandle; out Wow64: BOOL): BOOL;
begin
  Wow64 := False;
  Result := Assigned(Wow64Ptr);
  if Result then Result := Wow64Ptr(Handle, Wow64);
end;

function WinGetProcessTimes(Handle: THandle; out Created, Exited, Kernel, UserTime: TFileTime): BOOL;
begin
  Created := Default(TFileTime); Exited := Default(TFileTime);
  Kernel := Default(TFileTime); UserTime := Default(TFileTime);
  Result := Assigned(ProcessTimesPtr);
  if Result then Result := ProcessTimesPtr(Handle, Created, Exited, Kernel, UserTime);
end;

function WinGetThreadTimes(Handle: THandle; out Created, Exited, Kernel, UserTime: TFileTime): BOOL;
begin
  Created := Default(TFileTime); Exited := Default(TFileTime);
  Kernel := Default(TFileTime); UserTime := Default(TFileTime);
  Result := Assigned(ThreadTimesPtr);
  if Result then Result := ThreadTimesPtr(Handle, Created, Exited, Kernel, UserTime);
end;
function WinGetFileAttributes(Path: PWideChar): Cardinal;
begin Result := AttrsPtr(Path); end;

function WinGetLastError: Cardinal;
begin Result := LastErrorPtr(); end;

function WinCreateFile(Path: PWideChar; Access, ShareMode: Cardinal;
  Security: Pointer; Disposition, Flags: Cardinal; TemplateHandle: THandle): THandle;
begin
  Result := CreateFilePtr(Path, Access, ShareMode, Security, Disposition, Flags, TemplateHandle);
end;

function WinCloseHandle(Handle: THandle): BOOL;
begin Result := ClosePtr(Handle); end;

function WinGetFileInformationByHandle(Handle: THandle;
  var Info: BY_HANDLE_FILE_INFORMATION): BOOL;
begin
  Info := Default(BY_HANDLE_FILE_INFORMATION);
  Result := Assigned(FileInfoPtr);
  if Result then Result := FileInfoPtr(Handle, Info);
end;

function WinDeviceIoControl(Device: THandle; Code: Cardinal; Input: Pointer;
  InputSize: Cardinal; Output: Pointer; OutputSize: Cardinal;
  var Returned: Cardinal; Overlapped: Pointer): BOOL;
begin
  Returned := 0;
  Result := False;
  if not Assigned(DeviceControlPtr) then Exit;
  if ((InputSize <> 0) and (Input = nil)) or
     ((OutputSize <> 0) and (Output = nil)) then Exit;
  Result := DeviceControlPtr(Device, Code, Input, InputSize, Output,
    OutputSize, Returned, Overlapped);
end;

procedure FillWinPointerSnapshot(var Values: TArray<NativeUInt>);
begin
  Values[0] := PNativeUInt(@ModuleW)^;
  Values[1] := PNativeUInt(@LoadW)^;
  Values[2] := PNativeUInt(@ProcA)^;
  Values[3] := PNativeUInt(@CurrentPID)^;
  Values[4] := PNativeUInt(@CurrentProcess)^;
  Values[5] := PNativeUInt(@WaitPtr)^;
  Values[6] := PNativeUInt(@SleepPtr)^;
  Values[7] := PNativeUInt(@TickPtr)^;
  Values[8] := PNativeUInt(@Wow64Ptr)^;
  Values[9] := PNativeUInt(@ProcessTimesPtr)^;
  Values[10] := PNativeUInt(@ThreadTimesPtr)^;
  Values[11] := PNativeUInt(@FreeLibraryPtr)^;
  Values[12] := PNativeUInt(@CreateFilePtr)^;
  Values[13] := PNativeUInt(@ClosePtr)^;
end;

function SnapshotWinFunctionPointers: TArray<NativeUInt>;
begin
  // Snapshot actual live procedure-variable cells used by Win32 wrappers.
  SetLength(Result, 14);
  FillWinPointerSnapshot(Result);
end;

end.
