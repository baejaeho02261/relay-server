unit Cozy.NHW.CaptureNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.CaptureRules,
  Cozy.NHW.CaptureSnapshot.Decoders;

type
  TCaptureProcessInfo = Cozy.NHW.CaptureSnapshot.Decoders.TCaptureProcessInfo;
  TCaptureProcessList = Cozy.NHW.CaptureSnapshot.Decoders.TCaptureProcessList;
  TCapturePIDSet = Cozy.NHW.CaptureSnapshot.Decoders.TCapturePIDSet;

function RefreshCaptureProcesses(List: TCaptureProcessList): Boolean;
function InspectCaptureModules(PID: Cardinal; out ImagePath: string;
  out CreateTime: UInt64; out Families: TCaptureFamilies): Boolean;
function CaptureDriverFamilies: TCaptureFamilies;
function RefreshProxyListeners(OutPIDs: TCapturePIDSet): Boolean;

{$IFDEF NHW_NATIVE5B_TESTS}
function TestCaptureNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.WinPointers,
  Cozy.NHW.Native,
  Cozy.NHW.Types;

const
  MAX_MODULE_COUNT = 384;
  MAX_TCP_BYTES = 2 * 1024 * 1024;
  AF_INET_VALUE = 2;
  TCP_TABLE_OWNER_PID_LISTENER_VALUE = 3;
  SERVICE_RUNNING_VALUE = 4;
  SCM_CONNECT_RIGHT = 1;
  SERVICE_QUERY_STATUS_RIGHT = 4;
  SERVICE_STATUS_PROCESS_INFO = 0;
  ERROR_MORE_DATA = 234;
  ERROR_INSUFFICIENT_BUFFER = 122;

type
  TK32EnumModules = function(Proc: THandle; Modules: Pointer;
    Size: Cardinal; var Needed: Cardinal; Filter: Cardinal): BOOL; stdcall;
  TK32ModuleBaseName = function(Proc: THandle; Module: HMODULE;
    Buffer: PWideChar; Size: Cardinal): Cardinal; stdcall;
  TOpenManager = function(Machine, Database: PWideChar;
    Rights: Cardinal): THandle; stdcall;
  TOpenService = function(Manager: THandle; Name: PWideChar;
    Rights: Cardinal): THandle; stdcall;
  TCloseService = function(Handle: THandle): BOOL; stdcall;
  TQueryStatus = function(Service: THandle; InfoLevel: Cardinal;
    Buffer: Pointer; BufferSize: Cardinal; var Needed: Cardinal): BOOL; stdcall;
  TGetTCPTable = function(Buffer: Pointer; var Size: Cardinal;
    Order: BOOL; AF: Cardinal; TableKind: Cardinal;
    Reserved: Cardinal): Cardinal; stdcall;

  TServiceStatusProcessNative = record
    ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
    ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessID,
    ServiceFlags: Cardinal;
  end;


var
  EnumModulesPtr: TK32EnumModules = nil;
  ModuleBaseNamePtr: TK32ModuleBaseName = nil;
  OpenManagerPtr: TOpenManager = nil;
  OpenServicePtr: TOpenService = nil;
  CloseServicePtr: TCloseService = nil;
  QueryStatusPtr: TQueryStatus = nil;
  GetTCPPtr: TGetTCPTable = nil;
  CaptureResolveLock: TCriticalSection;
  KernelResolved, ServicesResolved, TcpResolved: Boolean;

procedure ResolveCaptureKernel;
var
  M: HMODULE;
begin
  if not KernelResolved then
  begin
    M := WinModule('kernel32.dll');
    if M <> 0 then
    begin
      EnumModulesPtr := TK32EnumModules(WinExport(M, 'K32EnumProcessModulesEx'));
      ModuleBaseNamePtr := TK32ModuleBaseName(WinExport(M, 'K32GetModuleBaseNameW'));
      KernelResolved := True;
    end;
  end;
end;

procedure ResolveCaptureServices;
var
  M: HMODULE;
begin
  if not ServicesResolved then
  begin
    M := WinModule('advapi32.dll');
    if M = 0 then M := WinLoadLibrary('advapi32.dll');
    if M <> 0 then
    begin
      OpenManagerPtr := TOpenManager(WinExport(M, 'OpenSCManagerW'));
      OpenServicePtr := TOpenService(WinExport(M, 'OpenServiceW'));
      QueryStatusPtr := TQueryStatus(WinExport(M, 'QueryServiceStatusEx'));
      CloseServicePtr := TCloseService(WinExport(M, 'CloseServiceHandle'));
      ServicesResolved := True;
    end;
  end;
end;

procedure ResolveCaptureTCP;
var
  M: HMODULE;
begin
  if not TcpResolved then
  begin
    M := WinModule('iphlpapi.dll');
    if M = 0 then M := WinLoadLibrary('iphlpapi.dll');
    if M <> 0 then
    begin
      GetTCPPtr := TGetTCPTable(WinExport(M, 'GetExtendedTcpTable'));
      TcpResolved := True;
    end;
  end;
end;

procedure ResolveCaptureAPI;
begin
  CaptureResolveLock.Acquire;
  try
    ResolveCaptureKernel;
    ResolveCaptureServices;
    ResolveCaptureTCP;
    // Module-load failures are retryable; completed tables never change.
    // Keep successfully loaded modules resident while their pointers are used.
  finally
    CaptureResolveLock.Release;
  end;
end;

function RefreshCaptureProcesses(List: TCaptureProcessList): Boolean;
var
  Data: TBytes;
  Failure: TNTStatus;
begin
  Result := False;
  if List = nil then Exit;
  List.Clear;
  if not FetchSystemData(SYSTEM_PROCESS_INFORMATION_CLASS,
    1024 * 1024, MAX_PROCESS_BYTES, Data, Failure) then Exit;
  Result := ParseCaptureProcesses(Data, List);
end;

function InspectCaptureModules(PID: Cardinal; out ImagePath: string;
  out CreateTime: UInt64; out Families: TCaptureFamilies): Boolean;
var
  ProcessHandle: THandle;
  Handles: array[0..MAX_MODULE_COUNT - 1] of HMODULE;
  Needed, Total: Cardinal;
  CandidateTime: UInt64;
  CandidatePath: string;
  CandidateFamilies: TCaptureFamilies;

  function ReadProcessIdentity: Boolean;
  var
    Buf: array[0..511] of WideChar;
    N: Cardinal;
    Created, Exited, KernelTime, UserTime: TFileTime;
  begin
    Result := False;
      FillChar(Buf, SizeOf(Buf), 0);
      N := Length(Buf);
      if not QueryProcessImageName(ProcessHandle, @Buf[0], N) or
         (N = 0) or (N >= Cardinal(Length(Buf))) then Exit;
      SetString(CandidatePath, PWideChar(@Buf[0]), Integer(N));
      if Pos(#0, CandidatePath) <> 0 then Exit;
      if not WinGetProcessTimes(ProcessHandle, Created, Exited,
        KernelTime, UserTime) then Exit;
      if (Exited.dwHighDateTime <> 0) or (Exited.dwLowDateTime <> 0) then Exit;
      CandidateTime := (UInt64(Created.dwHighDateTime) shl 32) or Created.dwLowDateTime;
      if CandidateTime = 0 then Exit;
    Result := True;
  end;

  function ReadModuleFamilies: Boolean;
  var
    Buf: array[0..511] of WideChar;
    I, N: Cardinal;
    ModuleName: string;
  begin
    Result := False;
      FillChar(Handles, SizeOf(Handles), 0);
      Needed := 0;
      if not EnumModulesPtr(ProcessHandle, @Handles[0], SizeOf(Handles), Needed, 3) then Exit;
      if (Needed > Cardinal(SizeOf(Handles))) or (Needed = 0) or
         ((Needed mod SizeOf(HMODULE)) <> 0) then Exit;
      Total := Needed div SizeOf(HMODULE);
      CandidateFamilies := [];
      for I := 0 to Total - 1 do
      begin
        if (Handles[I] = 0) or (Handles[I] = INVALID_HANDLE_VALUE) then Exit;
        FillChar(Buf, SizeOf(Buf), 0);
        N := ModuleBaseNamePtr(ProcessHandle, Handles[I], @Buf[0], Length(Buf));
        if (N = 0) or (N >= Cardinal(Length(Buf))) then Exit;
        SetString(ModuleName, PWideChar(@Buf[0]), Integer(N));
        if Pos(#0, ModuleName) <> 0 then Exit;
        CandidateFamilies := CandidateFamilies + LibraryKind(ModuleName);
      end;
    Result := True;
  end;

  function ConfirmModuleIdentity: Boolean;
  var
    Confirmed: array[0..MAX_MODULE_COUNT - 1] of HMODULE;
    ConfirmedBytes, I: Cardinal;
    Created, Exited, KernelTime, UserTime: TFileTime;
    ConfirmedTime: UInt64;
  begin
    Result := False;
      // Two bounded views reduce load/unload races; this is not an atomic snapshot.
      FillChar(Confirmed, SizeOf(Confirmed), 0);
      ConfirmedBytes := 0;
      if not EnumModulesPtr(ProcessHandle, @Confirmed[0], SizeOf(Confirmed),
        ConfirmedBytes, 3) then Exit;
      if ConfirmedBytes <> Needed then Exit;
      for I := 0 to Total - 1 do
        if Confirmed[I] <> Handles[I] then Exit;
      if not WinGetProcessTimes(ProcessHandle, Created, Exited,
        KernelTime, UserTime) then Exit;
      ConfirmedTime := (UInt64(Created.dwHighDateTime) shl 32) or Created.dwLowDateTime;
      if (ConfirmedTime <> CandidateTime) or
         (Exited.dwHighDateTime <> 0) or (Exited.dwLowDateTime <> 0) then Exit;
    Result := True;
  end;

begin
  Result := False;
  ImagePath := '';
  CreateTime := 0;
  Families := [];
  if PID <= 4 then Exit;
  ResolveCaptureAPI;
  if not Assigned(EnumModulesPtr) or not Assigned(ModuleBaseNamePtr) then Exit;
  ProcessHandle := OpenNativeProcess(PID, ACCESS_QUERY_INFORMATION or ACCESS_VM_READ);
  if (ProcessHandle = 0) or (ProcessHandle = INVALID_HANDLE_VALUE) then Exit;
  try
    if not ReadProcessIdentity then Exit;
    if not ReadModuleFamilies then Exit;
    if not ConfirmModuleIdentity then Exit;
    ImagePath := CandidatePath;
    CreateTime := CandidateTime;
    Families := CandidateFamilies;
    Result := True;
  finally
    CloseNativeProcess(ProcessHandle);
  end;
end;

function ServiceRunning(const Name: string; Manager: THandle): Boolean;
var
  Service: THandle;
  Info: TServiceStatusProcessNative;
  Needed: Cardinal;
begin
  Result := False;
  if (Manager = 0) or (Manager = INVALID_HANDLE_VALUE) or
     (Name = '') or (Pos(#0, Name) <> 0) then Exit;
  if not Assigned(OpenServicePtr) or not Assigned(QueryStatusPtr) or
     not Assigned(CloseServicePtr) then Exit;
  Service := OpenServicePtr(Manager, PWideChar(Name),
    SERVICE_QUERY_STATUS_RIGHT);
  if Service = 0 then Exit;
  try
    Info := Default(TServiceStatusProcessNative);
    Needed := 0;
    if QueryStatusPtr(Service, SERVICE_STATUS_PROCESS_INFO, @Info,
      SizeOf(Info), Needed) then
      Result := ((Needed = 0) or (Needed = Cardinal(SizeOf(Info)))) and
        (Info.CurrentState = SERVICE_RUNNING_VALUE);
  finally
    CloseServicePtr(Service);
  end;
end;

function CaptureDriverFamilies: TCaptureFamilies;
var
  Manager: THandle;
begin
  Result := [];
  ResolveCaptureAPI;
  if not Assigned(OpenManagerPtr) or not Assigned(CloseServicePtr) then Exit;
  Manager := OpenManagerPtr(nil, nil, SCM_CONNECT_RIGHT);
  if Manager = 0 then Exit;
  try
    if ServiceRunning('npcap', Manager) or
       ServiceRunning('npf', Manager) then
      Include(Result, cfPcap);
    if ServiceRunning('WinDivert', Manager) or
       ServiceRunning('WinDivert1.4', Manager) or
       ServiceRunning('WinDivert2.2', Manager) then
      Include(Result, cfWinDivert);
  finally
    CloseServicePtr(Manager);
  end;
end;

function RefreshProxyListeners(OutPIDs: TCapturePIDSet): Boolean;
const
  MAX_TCP_ATTEMPTS = 3;
var
  Buffer: TBytes;
  Needed, Capacity, ErrorCode: Cardinal;
  Attempt: Integer;
begin
  Result := False;
  if OutPIDs = nil then Exit;
  OutPIDs.Clear;
  ResolveCaptureAPI;
  if not Assigned(GetTCPPtr) then Exit;
  Needed := 0;
  ErrorCode := GetTCPPtr(nil, Needed, False, AF_INET_VALUE,
    TCP_TABLE_OWNER_PID_LISTENER_VALUE, 0);
  if ErrorCode <> ERROR_INSUFFICIENT_BUFFER then Exit;
  for Attempt := 1 to MAX_TCP_ATTEMPTS do
  begin
    if (Needed < 4) or (Needed > MAX_TCP_BYTES) then Exit;
    Capacity := Needed;
    SetLength(Buffer, Integer(Capacity));
    FillChar(Buffer[0], Length(Buffer), 0);
    ErrorCode := GetTCPPtr(@Buffer[0], Needed, False, AF_INET_VALUE,
      TCP_TABLE_OWNER_PID_LISTENER_VALUE, 0);
    if ErrorCode = ERROR_INSUFFICIENT_BUFFER then
    begin
      if Needed <= Capacity then Exit; // Refuse a non-progressing retry.
      Continue;
    end;
    if ErrorCode <> 0 then Exit;
    if Needed > Capacity then Exit;
    Result := ParseCaptureListeners(Buffer, Needed, OutPIDs);
    Exit;
  end;
end;

{$IFDEF NHW_NATIVE5B_TESTS}
  {$I Cozy.NHW.Native5B.Capture.inc}
{$ENDIF}
initialization
  CaptureResolveLock := TCriticalSection.Create;
finalization
  // The engine must have joined workers before Delphi unit finalization.
  CaptureResolveLock.Free;
end.
