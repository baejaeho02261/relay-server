unit Cozy.NHW.Observer.Launch;

{$A8}
{$B-}

interface

uses Winapi.Windows, Cozy.NHW.Observer.Protocol;

{ An anonymous inherited capability starts only the read-only observer role.
  It carries no license, device key, session token or network authority. }
function LaunchOwnedObserver(Mapping: THandle; View: PObserverShared;
  out ChildProcess, ChildJob: THandle; out ChildPID: Cardinal;
  out Cleanup: TObserverShutdownStatus): Boolean;
function ValidateObserverParent(Parent: THandle; View: PObserverShared): Boolean;
function ObserverHandleArgument(const Value: string; out Handle: THandle): Boolean;

implementation

uses System.SysUtils, System.SyncObjs;

type
  TObserverStartup = record
    Info: TStartupInfo;
    Attributes: Pointer;
  end;
  TObserverBasicLimit = record
    ProcessTime, JobTime: Int64;
    Flags: DWORD;
    MinimumWorkingSet, MaximumWorkingSet: NativeUInt;
    ActiveProcessLimit: DWORD;
    Affinity: NativeUInt;
    PriorityClass, SchedulingClass: DWORD;
  end;
  TObserverJobLimit = record
    Basic: TObserverBasicLimit;
    IO: array[0..5] of UInt64;
    ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory: NativeUInt;
  end;
  TObserverProcessBasic = record
    ExitStatus: LongInt;
    Padding0: DWORD;
    PEB: Pointer;
    Affinity: NativeUInt;
    BasePriority: LongInt;
    Padding1: DWORD;
    PID, ParentPID: NativeUInt;
  end;

function ObserverInitAttributes(List: Pointer; Count, Flags: DWORD;
  var Bytes: NativeUInt): BOOL; stdcall;
  external 'kernel32.dll' name 'InitializeProcThreadAttributeList';
function ObserverUpdateAttribute(List: Pointer; Flags: DWORD;
  Attribute: NativeUInt; Value: Pointer; Bytes: NativeUInt;
  Previous, Returned: Pointer): BOOL; stdcall;
  external 'kernel32.dll' name 'UpdateProcThreadAttribute';
procedure ObserverDeleteAttributes(List: Pointer); stdcall;
  external 'kernel32.dll' name 'DeleteProcThreadAttributeList';
function ObserverProcessID(Process: THandle): DWORD; stdcall;
  external 'kernel32.dll' name 'GetProcessId';
function ObserverImageName(Process: THandle; Flags: DWORD; Buffer: PWideChar;
  var Chars: DWORD): BOOL; stdcall;
  external 'kernel32.dll' name 'QueryFullProcessImageNameW';
function ObserverProcessBasic(Process: THandle; Kind: DWORD; Buffer: Pointer;
  Bytes: DWORD; Returned: PDWORD): LongInt; stdcall;
  external 'ntdll.dll' name 'NtQueryInformationProcess';

function ObserverHandleArgument(const Value: string; out Handle: THandle): Boolean;
var Number: UInt64; I: Integer;
begin
  Handle := 0;
  Result := False;
  if (Value = '') or (Length(Value) > 20) then Exit;
  for I := 1 to Length(Value) do
    if (Value[I] < '0') or (Value[I] > '9') then Exit;
  if not TryStrToUInt64(Value, Number) or (Number = 0) or
    (Number >= UInt64(High(NativeInt))) then Exit;
  Handle := THandle(Number);
  Result := True;
end;

function ImageIdentity(Process: THandle; out Info: TByHandleFileInformation): Boolean;
var Path: string; Chars: DWORD; FileHandle: THandle;
begin
  Info := Default(TByHandleFileInformation);
  Result := False;
  SetLength(Path, 32768); Chars := Length(Path);
  if not ObserverImageName(Process, 0, PWideChar(Path), Chars) or
    (Chars = 0) or (Chars >= DWORD(Length(Path))) then Exit;
  SetLength(Path, Chars);
  FileHandle := CreateFileW(PWideChar(Path), FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if FileHandle = INVALID_HANDLE_VALUE then Exit;
  try Result := GetFileInformationByHandle(FileHandle, Info);
  finally CloseHandle(FileHandle); end;
end;

function ValidateObserverParent(Parent: THandle; View: PObserverShared): Boolean;
var Basic: TObserverProcessBasic; Returned, Flags: DWORD;
  Created, OwnCreated: UInt64; ParentInfo, OwnInfo: TByHandleFileInformation;
  I: Integer; Nonzero: Byte;
begin
  Result := False;
  if (Parent = 0) or (View = nil) or
    (View^.Magic <> OBSERVER_MAGIC) or (View^.Version <> OBSERVER_VERSION) or
    (View^.OwnerPID <= 4) or (View^.OwnerCreated = 0) or
    (View^.ExpectedChildPID <> GetCurrentProcessId) or
    (View^.ExpectedChildCreated = 0) or ObserverStopped(View) then Exit;
  if not GetHandleInformation(Parent, Flags) or
    ((Flags and HANDLE_FLAG_INHERIT) = 0) then Exit;
  if (ObserverProcessID(Parent) <> View^.OwnerPID) or
    (WaitForSingleObject(Parent, 0) <> WAIT_TIMEOUT) or
    not QueryProcessCreation(Parent, Created) or
    (Created <> View^.OwnerCreated) or
    not QueryProcessCreation(GetCurrentProcess, OwnCreated) or
    (OwnCreated <> View^.ExpectedChildCreated) then Exit;
  Basic := Default(TObserverProcessBasic); Returned := 0;
  if (ObserverProcessBasic(GetCurrentProcess, 0, @Basic,
    SizeOf(Basic), @Returned) < 0) or (Returned <> SizeOf(Basic)) or
    (Basic.PID <> GetCurrentProcessId) or
    (Basic.ParentPID <> View^.OwnerPID) then Exit;
  if not ImageIdentity(Parent, ParentInfo) or
    not ImageIdentity(GetCurrentProcess, OwnInfo) or
    (ParentInfo.dwVolumeSerialNumber <> OwnInfo.dwVolumeSerialNumber) or
    (ParentInfo.nFileIndexHigh <> OwnInfo.nFileIndexHigh) or
    (ParentInfo.nFileIndexLow <> OwnInfo.nFileIndexLow) then Exit;
  Nonzero := 0;
  for I := 0 to High(View^.SessionKey) do Nonzero := Nonzero or View^.SessionKey[I];
  if Nonzero = 0 then Exit;
  { Exactly the intended child consumes the one-use launch permit. }
  if TInterlocked.CompareExchange(PInteger(@View^.LaunchClaimed)^, 1, 0) <> 0 then Exit;
  Result := True;
end;

function LaunchOwnedObserver(Mapping: THandle; View: PObserverShared;
  out ChildProcess, ChildJob: THandle; out ChildPID: Cardinal;
  out Cleanup: TObserverShutdownStatus): Boolean;
const AttributeHandleList = $00020002; ExtendedStartup = $00080000;
  KillOnJobClose = $00002000;
var Parent: THandle; InheritedHandles: array[0..1] of THandle;
  Startup: TObserverStartup; Process: TProcessInformation;
  Limit: TObserverJobLimit; AttributeBytes: NativeUInt;
  AttributesReady, Started: Boolean; Exe, CommandLine: string;
  Created, StopStarted: UInt64;
begin
  Result := False; ChildProcess := 0; ChildJob := 0; ChildPID := 0;
  Cleanup := Default(TObserverShutdownStatus);
  Parent := 0; Startup := Default(TObserverStartup);
  Process := Default(TProcessInformation); Limit := Default(TObserverJobLimit);
  AttributesReady := False; Started := False;
  if (Mapping = 0) or (View = nil) then Exit;
  try
    { Only two explicitly enumerated capabilities can cross this boundary. }
    if not SetHandleInformation(Mapping, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) then Exit;
    Parent := OpenProcess(OBSERVER_QUERY_LIMITED or SYNCHRONIZE, True, GetCurrentProcessId);
    if Parent = 0 then Exit;
    ChildJob := CreateJobObject(nil, nil);
    if ChildJob = 0 then Exit;
    Limit.Basic.Flags := KillOnJobClose;
    if not SetInformationJobObject(ChildJob, JobObjectExtendedLimitInformation,
      @Limit, SizeOf(Limit)) then Exit;
    AttributeBytes := 0;
    ObserverInitAttributes(nil, 1, 0, AttributeBytes);
    if (AttributeBytes = 0) or (AttributeBytes > 65536) then Exit;
    GetMem(Startup.Attributes, AttributeBytes);
    if not ObserverInitAttributes(Startup.Attributes, 1, 0, AttributeBytes) then Exit;
    AttributesReady := True;
    InheritedHandles[0] := Mapping; InheritedHandles[1] := Parent;
    if not ObserverUpdateAttribute(Startup.Attributes, 0, AttributeHandleList,
      @InheritedHandles[0], SizeOf(InheritedHandles), nil, nil) then Exit;
    Startup.Info.cb := SizeOf(Startup);
    Exe := ExpandFileName(ParamStr(0));
    CommandLine := '"' + Exe + '" --cozy-nhw-observer ' +
      UIntToStr(UInt64(Mapping)) + ' ' + UIntToStr(UInt64(Parent));
    UniqueString(CommandLine);
    if not CreateProcessW(PWideChar(Exe), PWideChar(CommandLine), nil, nil,
      True, ExtendedStartup or CREATE_SUSPENDED or CREATE_NO_WINDOW,
      nil, nil, Startup.Info, Process) then Exit;
    if not AssignProcessToJobObject(ChildJob, Process.hProcess) then Exit;
    if not QueryProcessCreation(Process.hProcess, Created) then Exit;
    View^.ExpectedChildPID := Process.dwProcessId;
    View^.ExpectedChildCreated := Created;
    View^.LaunchClaimed := 0;
    ObserverStore64(View^.OwnerTick, ObserverClockTick);
    if ResumeThread(Process.hThread) = DWORD(-1) then Exit;
    Started := True;
    ChildProcess := Process.hProcess; Process.hProcess := 0;
    ChildPID := Process.dwProcessId;
    Result := True;
  finally
    { Never leave a suspended or unauthenticated child on an error path. }
    if Process.hProcess <> 0 then
    begin
      StopStarted := ObserverClockTick;
      Cleanup.HadChild := True;
      Cleanup.ForcedTerminationRequested := not Started;
      if not Started then TerminateProcess(Process.hProcess, 1);
      Cleanup.ExitObserved := WaitForSingleObject(Process.hProcess, 1500) = WAIT_OBJECT_0;
      Cleanup.ElapsedMs := ObserverClockTick - StopStarted;
      CloseHandle(Process.hProcess);
    end;
    if Process.hThread <> 0 then CloseHandle(Process.hThread);
    if AttributesReady then ObserverDeleteAttributes(Startup.Attributes);
    if Startup.Attributes <> nil then FreeMem(Startup.Attributes);
    if Parent <> 0 then CloseHandle(Parent);
    SetHandleInformation(Mapping, HANDLE_FLAG_INHERIT, 0);
    if not Result and (ChildJob <> 0) then
    begin CloseHandle(ChildJob); ChildJob := 0; end;
  end;
end;

end.
