unit Cozy.NHW.Native;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Types,
  Cozy.NHW.WinPointers;

// NT interfaces used by the v13 read-only process/thread/token monitor.
// Internal structures are Windows-version sensitive; x64 only.
const
  SYSTEM_EXTENDED_HANDLE_INFORMATION = 64;
  SYSTEM_PROCESS_INFORMATION_CLASS = 5;
  STATUS_INFO_LENGTH_MISMATCH = $C0000004;
  NATIVE_PROCESS_QUERY_LIMITED_INFORMATION = $1000;

type
  TNTStatus = LongInt;

  TNativeObjectAttributes = record
    Length: Cardinal;
    RootDirectory: THandle;
    ObjectName: Pointer;
    Attributes: Cardinal;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;

  TNativeClientId = record
    UniqueProcess: THandle;
    UniqueThread: THandle;
  end;

  // Windows x64 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; internal layout.
  PNativeHandleEntry = ^TNativeHandleEntry;
  TNativeHandleEntry = record
    ObjectPointer: Pointer;
    OwnerPID: NativeUInt;
    HandleValue: NativeUInt;
    GrantedAccess: Cardinal;
    CreatorBackTraceIndex: Word;
    ObjectTypeIndex: Word;
    HandleAttributes: Cardinal;
    Reserved: Cardinal;
  end;

  TNativeUnicode = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

  // x64 prefix of SYSTEM_PROCESS_INFORMATION; validate SizeOf = 88.
  TProcessPrefix = record
    NextEntryOffset: Cardinal;
    NumberOfThreads: Cardinal;
    Reserved1: array[0..47] of Byte;
    ImageName: TNativeUnicode;
    BasePriority: LongInt;
    UniqueProcessId: THandle;
  end;

  TNtQuerySystemInformation = function(InformationClass: Cardinal; Buffer: Pointer;
    BufferSize: Cardinal; ReturnLength: PCardinal): TNTStatus; stdcall;
  TNtOpenProcess = function(var OutHandle: THandle; DesiredAccess: Cardinal;
    ObjectAttributes: Pointer; ClientId: Pointer): TNTStatus; stdcall;
  TNtClose = function(Handle: THandle): TNTStatus; stdcall;
  TNtGetNextThread = function(ProcessHandle: THandle;
    PreviousThreadHandle: THandle; DesiredAccess: Cardinal;
    HandleAttributes: Cardinal; Flags: Cardinal;
    var OutThreadHandle: THandle): TNTStatus; stdcall;
  TNtOpenProcessToken = function(ProcessHandle: THandle;
    DesiredAccess: Cardinal; var TokenHandle: THandle): TNTStatus; stdcall;
  TNtOpenThread = function(var ThreadHandle: THandle;
    DesiredAccess: Cardinal; ObjectAttributes: Pointer;
    ClientId: Pointer): TNTStatus; stdcall;
  TNtOpenThreadToken = function(ThreadHandle: THandle;
    DesiredAccess: Cardinal; OpenAsSelf: Byte;
    var TokenHandle: THandle): TNTStatus; stdcall;
  TNtQueryInformationToken = function(TokenHandle: THandle;
    TokenInformationClass: Cardinal; TokenInformation: Pointer;
    TokenInformationLength: Cardinal;
    ReturnLength: PCardinal): TNTStatus; stdcall;
  TNtQuerySecurityObject = function(Handle: THandle;
    SecurityInformation: Cardinal; SecurityDescriptor: Pointer;
    Length: Cardinal; LengthNeeded: PCardinal): TNTStatus; stdcall;
  TNtQueryObject = function(Handle: THandle; InformationClass: Cardinal;
    Buffer: Pointer; BufferSize: Cardinal; ReturnLength: PCardinal): TNTStatus; stdcall;
  TNtDuplicateObject = function(SourceProcess: THandle; SourceHandle: THandle;
    TargetProcess: THandle; var TargetHandle: THandle; DesiredAccess: Cardinal;
    HandleAttributes: Cardinal; Options: Cardinal): TNTStatus; stdcall;
  TNtIsProcessInJob = function(ProcessHandle: THandle;
    JobHandle: THandle): TNTStatus; stdcall;
  TQueryFullImageName = function(H: THandle; Flags: Cardinal;
    Buffer: PWideChar; var CharacterCount: Cardinal): BOOL; stdcall;

procedure ResolveNativeAPIs;
function SnapshotNativeFunctionPointers: TArray<NativeUInt>;
function IPCNativeAvailable: Boolean;
function QueryNativeObjectType(H: THandle; out TypeName: string): Boolean;
function DuplicateNativeHandle(SourceProcess: THandle; SourceHandle: THandle;
  out CopyHandle: THandle): Boolean;
function QueryNativeJobState(ProcessHandle: THandle;
  out InJob: Boolean): Boolean;
function OpenNativeProcess(PID: Cardinal; Rights: Cardinal): THandle;
procedure CloseNativeProcess(var ProcessHandle: THandle);
function NativeThreadEnumerationAvailable: Boolean;
function GetNextNativeThread(ProcessHandle, PreviousThreadHandle: THandle;
  DesiredAccess: Cardinal; out NextThread: THandle): TNTStatus;
function SecurityNativeAvailable: Boolean;
function OpenNativeProcessToken(ProcessHandle: THandle;
  Rights: Cardinal): THandle;
function OpenNativeThread(PID, ThreadID, Rights: Cardinal): THandle;
function OpenNativeThreadToken(ThreadHandle: THandle;
  Rights: Cardinal; out TokenHandle: THandle): TNTStatus;
function QueryNativeTokenInformation(TokenHandle: THandle;
  InfoClass: Cardinal; Buffer: Pointer; BufferSize: Cardinal;
  out ReturnSize: Cardinal): TNTStatus;
function QueryNativeSecurity(Handle: THandle; Info: Cardinal;
  Buffer: Pointer; BufferSize: Cardinal; out ReturnSize: Cardinal): TNTStatus;
function QueryProcessImageName(H: THandle; Buffer: PWideChar;
  var CharacterCount: Cardinal): Boolean;
function FetchSystemData(InformationClass, InitialBytes, Cap: Cardinal;
  out Data: TBytes; out Failure: TNTStatus): Boolean;
function FetchSnapshot(out Data: TBytes; out Failure: TNTStatus): Boolean;

implementation

uses Cozy.NHW.NativeSafety;

type
  TNativeObjectTypeBuffer = array[0..1023] of Byte;

var
  NtQuerySystemInformation: TNtQuerySystemInformation;
  NtOpenProcess: TNtOpenProcess;
  NtClose: TNtClose;
  NtGetNextThread: TNtGetNextThread;
  NtOpenProcessToken: TNtOpenProcessToken;
  NtOpenThread: TNtOpenThread;
  NtOpenThreadToken: TNtOpenThreadToken;
  NtQueryInformationToken: TNtQueryInformationToken;
  NtQuerySecurityObject: TNtQuerySecurityObject;
  QueryFullImageName: TQueryFullImageName;
  NtQueryObjectPtr: TNtQueryObject;
  NtDuplicateObjectPtr: TNtDuplicateObject;
  NtIsProcessInJobPtr: TNtIsProcessInJob;

function OptionalExport(Module: HMODULE; const Name: AnsiString): Pointer;
begin
  Result := WinExport(Module, Name);
end;

function RequiredExport(Module: HMODULE; const Name: AnsiString): Pointer;
begin
  Result := WinExport(Module, Name);
  if Result = nil then
    raise Exception.Create('Missing export: ' + string(Name));
end;

procedure ResolveRequiredNative(NtdllMod, KernelMod: HMODULE);
begin
  NtQuerySystemInformation := TNtQuerySystemInformation(
    RequiredExport(NtdllMod, 'NtQuerySystemInformation'));
  NtOpenProcess := TNtOpenProcess(RequiredExport(NtdllMod, 'NtOpenProcess'));
  NtClose := TNtClose(RequiredExport(NtdllMod, 'NtClose'));
  QueryFullImageName := TQueryFullImageName(
    RequiredExport(KernelMod, 'QueryFullProcessImageNameW'));
end;

procedure ResolveOptionalThreadSecurity(NtdllMod: HMODULE);
begin
  NtGetNextThread := TNtGetNextThread(OptionalExport(NtdllMod, 'NtGetNextThread'));
  NtOpenProcessToken := TNtOpenProcessToken(
    OptionalExport(NtdllMod, 'NtOpenProcessToken'));
  NtOpenThread := TNtOpenThread(OptionalExport(NtdllMod, 'NtOpenThread'));
  NtOpenThreadToken := TNtOpenThreadToken(
    OptionalExport(NtdllMod, 'NtOpenThreadToken'));
  NtQueryInformationToken := TNtQueryInformationToken(
    OptionalExport(NtdllMod, 'NtQueryInformationToken'));
  NtQuerySecurityObject := TNtQuerySecurityObject(
    OptionalExport(NtdllMod, 'NtQuerySecurityObject'));
end;

procedure ResolveOptionalObjectAPIs(NtdllMod: HMODULE);
begin
  NtQueryObjectPtr := TNtQueryObject(OptionalExport(NtdllMod, 'NtQueryObject'));
  NtDuplicateObjectPtr := TNtDuplicateObject(
    OptionalExport(NtdllMod, 'NtDuplicateObject'));
  NtIsProcessInJobPtr := TNtIsProcessInJob(
    OptionalExport(NtdllMod, 'NtIsProcessInJob'));
end;

procedure ResolveNativeAPIs;
var
  NtdllMod, KernelMod: HMODULE;
begin
  NtdllMod := WinModule('ntdll.dll');
  KernelMod := WinModule('kernel32.dll');
  if (NtdllMod = 0) or (KernelMod = 0) then
    raise Exception.Create('Required system DLL is unavailable.');
  ResolveRequiredNative(NtdllMod, KernelMod);
  ResolveOptionalThreadSecurity(NtdllMod);
  ResolveOptionalObjectAPIs(NtdllMod);
end;

procedure InitNativeObjectAttributes(out Attr: TNativeObjectAttributes);
begin
  FillChar(Attr, SizeOf(Attr), 0);
  Attr.Length := SizeOf(Attr);
end;

procedure InitNativeClientId(out Id: TNativeClientId; PID, TID: Cardinal);
begin
  FillChar(Id, SizeOf(Id), 0);
  Id.UniqueProcess := THandle(PID);
  Id.UniqueThread := THandle(TID);
end;

function IPCNativeAvailable: Boolean;
begin
  Result := Assigned(NtQueryObjectPtr) and Assigned(NtDuplicateObjectPtr);
end;

function DecodeNativeObjectType(const Data: TNativeObjectTypeBuffer;
  out TypeName: string): Boolean;
var
  U: ^TNativeUnicode;
  StartAddr, EndAddr, TextAddr: NativeUInt;
begin
  Result := False;
  TypeName := '';
  U := Pointer(@Data[0]);
  if (U^.Length = 0) or ((U^.Length and 1) <> 0) or
     (U^.MaximumLength < U^.Length) or (U^.Buffer = nil) then Exit;
  StartAddr := NativeUInt(@Data[0]);
  EndAddr := StartAddr + SizeOf(Data);
  TextAddr := NativeUInt(U^.Buffer);
  if (TextAddr < StartAddr) or (TextAddr >= EndAddr) then Exit;
  if NativeUInt(U^.Length) > EndAddr - TextAddr then Exit;
  SetString(TypeName, U^.Buffer, U^.Length div SizeOf(WideChar));
  Result := True;
end;

function QueryNativeObjectType(H: THandle; out TypeName: string): Boolean;
var
  Data: TNativeObjectTypeBuffer;
  Needed: Cardinal;
begin
  Result := False;
  TypeName := '';
  if not Assigned(NtQueryObjectPtr) then Exit;
  Needed := 0;
  if NtQueryObjectPtr(H, 2, @Data[0], SizeOf(Data), @Needed) <> 0 then Exit;
  Result := DecodeNativeObjectType(Data, TypeName);
end;

function DuplicateNativeHandle(SourceProcess: THandle; SourceHandle: THandle;
  out CopyHandle: THandle): Boolean;
const
  DUPLICATE_SAME_ACCESS = 2;
begin
  CopyHandle := 0;
  Result := Assigned(NtDuplicateObjectPtr) and
    (NtDuplicateObjectPtr(SourceProcess, SourceHandle, WinCurrentProcess,
     CopyHandle, 0, 0, DUPLICATE_SAME_ACCESS) = 0) and
    (CopyHandle <> 0);
end;

function QueryNativeJobState(ProcessHandle: THandle;
  out InJob: Boolean): Boolean;
const
  STATUS_PROCESS_NOT_IN_JOB = $00000123;
  STATUS_PROCESS_IN_JOB = $00000124;
var
  Status: TNTStatus;
begin
  Result := False;
  InJob := False;
  if not Assigned(NtIsProcessInJobPtr) then Exit;
  Status := NtIsProcessInJobPtr(ProcessHandle, 0);
  case Cardinal(Status) of
    STATUS_PROCESS_NOT_IN_JOB: begin InJob := False; Result := True; end;
    STATUS_PROCESS_IN_JOB: begin InJob := True; Result := True; end;
  end;
end;

function NtSucceeded(Status: TNTStatus): Boolean; inline;
begin
  Result := Status >= 0;
end;

function OpenNativeProcess(PID: Cardinal; Rights: Cardinal): THandle;
var
  Attr: TNativeObjectAttributes;
  Id: TNativeClientId;
begin
  Result := 0;
  InitNativeObjectAttributes(Attr);
  InitNativeClientId(Id, PID, 0);
  if not NtSucceeded(NtOpenProcess(Result, Rights, @Attr, @Id)) then
    Result := 0;
end;

procedure CloseNativeProcess(var ProcessHandle: THandle);
begin
  if ProcessHandle <> 0 then
  begin
    NtClose(ProcessHandle);
    ProcessHandle := 0;
  end;
end;

function NativeThreadEnumerationAvailable: Boolean;
begin
  Result := Assigned(NtGetNextThread);
end;

function GetNextNativeThread(ProcessHandle, PreviousThreadHandle: THandle;
  DesiredAccess: Cardinal; out NextThread: THandle): TNTStatus;
begin
  NextThread := 0;
  if not NativeThreadEnumerationAvailable then
    Exit(TNTStatus($C0000002)); // STATUS_NOT_IMPLEMENTED
  Result := NtGetNextThread(ProcessHandle, PreviousThreadHandle,
    DesiredAccess, 0, 0, NextThread);
end;

function SecurityNativeAvailable: Boolean;
begin
  Result := Assigned(NtOpenProcessToken) and Assigned(NtOpenThread) and
    Assigned(NtOpenThreadToken) and Assigned(NtQueryInformationToken) and
    Assigned(NtQuerySecurityObject);
end;

function OpenNativeProcessToken(ProcessHandle: THandle;
  Rights: Cardinal): THandle;
begin
  Result := 0;
  if Assigned(NtOpenProcessToken) then
    if NtOpenProcessToken(ProcessHandle, Rights, Result) < 0 then
      Result := 0;
end;

function OpenNativeThread(PID, ThreadID, Rights: Cardinal): THandle;
var
  Attr: TNativeObjectAttributes;
  Client: TNativeClientId;
begin
  Result := 0;
  if not Assigned(NtOpenThread) then Exit;
  InitNativeObjectAttributes(Attr);
  InitNativeClientId(Client, PID, ThreadID);
  if NtOpenThread(Result, Rights, @Attr, @Client) < 0 then
    Result := 0;
end;

function OpenNativeThreadToken(ThreadHandle: THandle;
  Rights: Cardinal; out TokenHandle: THandle): TNTStatus;
begin
  TokenHandle := 0;
  if not Assigned(NtOpenThreadToken) then
    Exit(TNTStatus($C0000002));
  Result := NtOpenThreadToken(ThreadHandle, Rights, 1, TokenHandle);
  if Result < 0 then TokenHandle := 0;
end;

function QueryNativeTokenInformation(TokenHandle: THandle;
  InfoClass: Cardinal; Buffer: Pointer; BufferSize: Cardinal;
  out ReturnSize: Cardinal): TNTStatus;
begin
  ReturnSize := 0;
  if not Assigned(NtQueryInformationToken) then
    Exit(TNTStatus($C0000002));
  Result := NtQueryInformationToken(TokenHandle, InfoClass, Buffer,
    BufferSize, @ReturnSize);
end;

function QueryNativeSecurity(Handle: THandle; Info: Cardinal;
  Buffer: Pointer; BufferSize: Cardinal;
  out ReturnSize: Cardinal): TNTStatus;
begin
  ReturnSize := 0;
  if not Assigned(NtQuerySecurityObject) then
    Exit(TNTStatus($C0000002));
  Result := NtQuerySecurityObject(Handle, Info, Buffer,
    BufferSize, @ReturnSize);
end;

function QueryProcessImageName(H: THandle; Buffer: PWideChar;
  var CharacterCount: Cardinal): Boolean;
begin
  Result := QueryFullImageName(H, 0, Buffer, CharacterCount);
end;

function FetchSystemData(InformationClass, InitialBytes, Cap: Cardinal;
  out Data: TBytes; out Failure: TNTStatus): Boolean;
var
  BufferSize, Needed, NextSize: Cardinal;
  Status: TNTStatus;
  Attempts: Integer;
begin
  Result := False;
  Data := nil;
  Failure := TNTStatus($C000000D); // STATUS_INVALID_PARAMETER
  if not Assigned(NtQuerySystemInformation) or
     (InitialBytes = 0) or (InitialBytes > Cap) or
     (Cap > Cardinal(High(Integer))) then Exit;
  BufferSize := InitialBytes;
  Attempts := 0;
  // Bounded retries even when a provider repeatedly changes its requirement.
  repeat
    Inc(Attempts);
    SetLength(Data, Integer(BufferSize));
    Needed := 0;
    Status := NtQuerySystemInformation(InformationClass, @Data[0],
      BufferSize, @Needed);
    if NtSucceeded(Status) then
    begin
      if Needed > BufferSize then
      begin
        Failure := TNTStatus($C0000004); // incomplete result, not success
        Data := nil;
        Exit;
      end;
      Failure := Status;
      Exit(True);
    end;
    if Cardinal(Status) <> STATUS_INFO_LENGTH_MISMATCH then Break;
    if not NHWNextBufferSize(BufferSize, Needed, Cap, NextSize) then Break;
    BufferSize := NextSize;
  until Attempts >= 24;
  Failure := Status;
  Data := nil; // failed snapshots must not expose stale/partially filled data
end;

function FetchSnapshot(out Data: TBytes; out Failure: TNTStatus): Boolean;
begin
  Result := FetchSystemData(SYSTEM_EXTENDED_HANDLE_INFORMATION,
    2 * 1024 * 1024, MAX_SNAPSHOT_BYTES, Data, Failure);
end;

function SnapshotNativeFunctionPointers: TArray<NativeUInt>;
begin
  SetLength(Result, 8);
  Result[0] := PNativeUInt(@NtQuerySystemInformation)^;
  Result[1] := PNativeUInt(@NtOpenProcess)^;
  Result[2] := PNativeUInt(@NtClose)^;
  Result[3] := PNativeUInt(@NtGetNextThread)^;
  Result[4] := PNativeUInt(@NtOpenProcessToken)^;
  Result[5] := PNativeUInt(@NtQuerySecurityObject)^;
  Result[6] := PNativeUInt(@NtQueryObjectPtr)^;
  Result[7] := PNativeUInt(@QueryFullImageName)^;
end;

end.
