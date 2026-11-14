unit Cozy.NHW.RegistryNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.WinPointers;

// Native NT registry APIs. All registry operations use resolved function
// pointers. Returned kernel structures are bounds-checked before parsing.
// This module never writes to the registry.
const
  REG_KEY_QUERY_VALUE = $0001;
  REG_KEY_ENUMERATE_SUB_KEYS = $0008;
  REG_KEY_NOTIFY = $0010;
  REG_READ_CONTROL = $00020000;
  REG_REQUEST_ACCESS = REG_KEY_QUERY_VALUE or REG_KEY_ENUMERATE_SUB_KEYS or
    REG_KEY_NOTIFY or REG_READ_CONTROL;
  REG_FALLBACK_ACCESS = REG_KEY_QUERY_VALUE or REG_KEY_ENUMERATE_SUB_KEYS or
    REG_KEY_NOTIFY;

  REG_NOTIFY_NAME = $00000001;
  REG_NOTIFY_ATTRIBUTES = $00000002;
  REG_NOTIFY_LAST_SET = $00000004;
  REG_NOTIFY_SECURITY = $00000008;
  REG_NOTIFY_ALL = REG_NOTIFY_NAME or REG_NOTIFY_ATTRIBUTES or
    REG_NOTIFY_LAST_SET or REG_NOTIFY_SECURITY;

  REG_STATUS_PENDING = $00000103;
  REG_STATUS_TIMEOUT = $00000102;
  REG_STATUS_NO_MORE_ENTRIES = $8000001A;
  REG_STATUS_BUFFER_OVERFLOW = $80000005;
  REG_STATUS_BUFFER_TOO_SMALL = $C0000023;
  REG_DACL_SECURITY_INFORMATION = 4;
  REG_TOKEN_QUERY = 8;
  REG_TOKEN_USER_CLASS = 1;

type
  TRegNtStatus = LongInt;

  TRegUnicodeString = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

  TRegObjectAttributes = record
    Length: Cardinal;
    RootDirectory: THandle;
    ObjectName: ^TRegUnicodeString;
    Attributes: Cardinal;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;

  // IO_STATUS_BLOCK, 16 bytes on Win64. Address must remain stable while a
  // change notification is pending. Each watch stores one in a class field.
  TRegIoStatusBlock = record
    Status: TRegNtStatus;
    Reserved: Cardinal;
    Information: NativeUInt;
  end;

  TRegTokenUser = record
    Sid: Pointer;
    Attributes: Cardinal;
  end;

  TRegKeyBasic = record
    LastWriteTime: Int64;
    TitleIndex: Cardinal;
    NameLength: Cardinal;
  end;

  TRegValueFull = record
    TitleIndex: Cardinal;
    DataType: Cardinal;
    DataOffset: Cardinal;
    DataLength: Cardinal;
    NameLength: Cardinal;
  end;

  TRegSelfRelativeSD = record
    Revision: Byte;
    Reserved: Byte;
    Control: Word;
    OwnerOffset: Cardinal;
    GroupOffset: Cardinal;
    SaclOffset: Cardinal;
    DaclOffset: Cardinal;
  end;

  TRegAclHeader = record
    Revision: Byte;
    Reserved: Byte;
    AclSize: Word;
    AceCount: Word;
    Reserved2: Word;
  end;

  TNtRegOpenKey = function(var KeyHandle: THandle; DesiredAccess: Cardinal;
    ObjAttributes: Pointer): TRegNtStatus; stdcall;
  TNtRegClose = function(Handle: THandle): TRegNtStatus; stdcall;
  TNtRegEnumerateKey = function(Handle: THandle; Index, InfoClass: Cardinal;
    Buffer: Pointer; BufferLength: Cardinal; ReturnLength: PCardinal): TRegNtStatus; stdcall;
  TNtRegEnumerateValue = function(Handle: THandle; Index, InfoClass: Cardinal;
    Buffer: Pointer; BufferLength: Cardinal; ReturnLength: PCardinal): TRegNtStatus; stdcall;
  TNtRegQuerySecurity = function(Handle: THandle; SecurityInformation: Cardinal;
    SecurityDescriptor: Pointer; Length: Cardinal; LengthNeeded: PCardinal): TRegNtStatus; stdcall;
  TNtRegNotify = function(KeyHandle, EventHandle: THandle; ApcRoutine,
    ApcContext: Pointer; IoStatusBlock: Pointer; CompletionFilter: Cardinal;
    WatchTree: ByteBool; Buffer: Pointer; BufferSize: Cardinal;
    Asynchronous: ByteBool): TRegNtStatus; stdcall;
  TNtRegCreateEvent = function(var EventHandle: THandle; AccessMask: Cardinal;
    ObjectAttributes: Pointer; EventType: Cardinal;
    InitialState: ByteBool): TRegNtStatus; stdcall;
  TNtRegWaitForSingleObject = function(Handle: THandle; Alertable: ByteBool;
    Timeout: PInt64): TRegNtStatus; stdcall;
  TNtRegOpenProcessToken = function(ProcessHandle: THandle; DesiredAccess: Cardinal;
    var TokenHandle: THandle): TRegNtStatus; stdcall;
  TNtRegQueryInformationToken = function(TokenHandle: THandle;
    TokenInformationClass: Cardinal; Buffer: Pointer; Length: Cardinal;
    ReturnLength: PCardinal): TRegNtStatus; stdcall;
  TRtlRegConvertSidToUnicode = function(Unicode: Pointer; Sid: Pointer;
    AllocateDestinationString: ByteBool): TRegNtStatus; stdcall;
  TRtlRegFreeUnicode = procedure(Unicode: Pointer); stdcall;

function RegistryNativeAvailable: Boolean;
function NativeOpenRegistryKey(const NativePath: string): THandle;
procedure NativeCloseRegistry(var Handle: THandle);
function NativeRegistryNotify(KeyHandle, EventHandle: THandle;
  Io: Pointer): TRegNtStatus;
function NativeCreateRegistryEvent: THandle;
function NativePollRegistryEvent(EventHandle: THandle): Boolean;
function NativeEnumerateRegistryKey(Key: THandle; Index: Cardinal;
  Data: Pointer; Size: Cardinal; out Required: Cardinal): TRegNtStatus;
function NativeEnumerateRegistryValue(Key: THandle; Index: Cardinal;
  Data: Pointer; Size: Cardinal; out Required: Cardinal): TRegNtStatus;
function NativeRegistryDacl(Key: THandle; Data: Pointer; Size: Cardinal;
  out Required: Cardinal): TRegNtStatus;
function NativeCurrentUserRegistryRoot: string;

{$IFDEF NHW_HARDENING_TESTS}
function TestRegistryHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.NativeSafety;

const
  REG_STATUS_NOT_IMPLEMENTED = $C0000002;
  REG_STATUS_INVALID_PARAMETER = $C000000D;
  REG_STATUS_INVALID_HANDLE = $C0000008;
  REG_STATUS_INFO_LENGTH_MISMATCH = $C0000004;
  REG_EVENT_ACCESS = $00100002; // SYNCHRONIZE | EVENT_MODIFY_STATE
  REG_MAX_SID_AUTHORITIES = 15;

var
  ResolveLock: TCriticalSection;
  TriedExports: Boolean = False;
  ApiAvailable: Boolean = False;
  POpenKey: TNtRegOpenKey = nil;
  PCloseKey: TNtRegClose = nil;
  PEnumerateKey: TNtRegEnumerateKey = nil;
  PEnumerateValue: TNtRegEnumerateValue = nil;
  PQuerySecurity: TNtRegQuerySecurity = nil;
  PNotify: TNtRegNotify = nil;
  PCreateEvent: TNtRegCreateEvent = nil;
  PWait: TNtRegWaitForSingleObject = nil;
  POpenToken: TNtRegOpenProcessToken = nil;
  PQueryToken: TNtRegQueryInformationToken = nil;
  PConvertSid: TRtlRegConvertSidToUnicode = nil;
  PFreeUnicode: TRtlRegFreeUnicode = nil;

procedure ResolveRegistryFunctionTable(N: HMODULE);
begin
  POpenKey := TNtRegOpenKey(WinExport(N, 'NtOpenKey'));
  PCloseKey := TNtRegClose(WinExport(N, 'NtClose'));
  PEnumerateKey := TNtRegEnumerateKey(WinExport(N, 'NtEnumerateKey'));
  PEnumerateValue := TNtRegEnumerateValue(WinExport(N, 'NtEnumerateValueKey'));
  PQuerySecurity := TNtRegQuerySecurity(WinExport(N, 'NtQuerySecurityObject'));
  PNotify := TNtRegNotify(WinExport(N, 'NtNotifyChangeKey'));
  PCreateEvent := TNtRegCreateEvent(WinExport(N, 'NtCreateEvent'));
  PWait := TNtRegWaitForSingleObject(WinExport(N, 'NtWaitForSingleObject'));
  POpenToken := TNtRegOpenProcessToken(WinExport(N, 'NtOpenProcessToken'));
  PQueryToken := TNtRegQueryInformationToken(WinExport(N, 'NtQueryInformationToken'));
  PConvertSid := TRtlRegConvertSidToUnicode(WinExport(N, 'RtlConvertSidToUnicodeString'));
  PFreeUnicode := TRtlRegFreeUnicode(WinExport(N, 'RtlFreeUnicodeString'));
end;

procedure ResolveRegistryExports;
var
  N: HMODULE;
begin
  ResolveLock.Acquire;
  try
    if TriedExports then Exit;
    N := WinModule('ntdll.dll');
    // Do not permanently poison availability when called before WinPointers
    // bootstrap. A later caller can resolve after bootstrap has completed.
    if N = 0 then Exit;
    ResolveRegistryFunctionTable(N);
    ApiAvailable := Assigned(POpenKey) and Assigned(PCloseKey) and
      Assigned(PEnumerateKey) and Assigned(PEnumerateValue) and
      Assigned(PNotify) and Assigned(PCreateEvent) and Assigned(PWait);
    // All exported pointers are immutable after publication under this lock.
    TriedExports := True;
  finally
    ResolveLock.Release;
  end;
end;

function RegistryLayoutsValid: Boolean;
begin
  Result := (SizeOf(TRegUnicodeString) = 16) and
    (SizeOf(TRegObjectAttributes) = 48) and
    (SizeOf(TRegIoStatusBlock) = 16) and
    (SizeOf(TRegTokenUser) = 16) and
    (SizeOf(TRegValueFull) = 20) and
    (SizeOf(TRegKeyBasic) = 16) and
    (SizeOf(TRegSelfRelativeSD) = 20) and
    (SizeOf(TRegAclHeader) = 8);
end;

function RegistryNativeAvailable: Boolean;
begin
  ResolveRegistryExports;
  Result := ApiAvailable and RegistryLayoutsValid;
end;

function RegistryHandleValid(H: THandle): Boolean; inline;
begin
  Result := (H <> 0) and (NativeUInt(H) <= NativeUInt(High(NativeInt)));
end;

function RegistryPathValid(const Path: string): Boolean;
begin
  Result := False;
  if (Length(Path) = 0) or (Length(Path) > 32760) then Exit;
  Result := (Path[1] = '\') and (Pos(#0, Path) = 0);
end;

function RegistryBufferValid(Data: Pointer; Size: Cardinal): Boolean;
begin
  // Zero length is a legal sizing query; never dereference Data here.
  if Size = 0 then Exit(True);
  Result := NHWAddressSpan(NativeUInt(Data), NativeUInt(Size));
end;

function CheckedRegistryResult(Status: TRegNtStatus; Size, Minimum: Cardinal;
  var Required: Cardinal): TRegNtStatus;
begin
  Result := Status;
  if Status = 0 then
    if (Required < Minimum) or (Required > Size) then
    begin
      Required := 0;
      Result := TRegNtStatus(REG_STATUS_INFO_LENGTH_MISMATCH);
    end;
  // On BUFFER_TOO_SMALL/OVERFLOW, preserve Required for the caller's bounded
  // resize/retry logic. An unsuccessful buffer must not be parsed as success.
end;

procedure PrepareRegistryKeyArguments(const NativePath: string;
  var Name: TRegUnicodeString; var Attr: TRegObjectAttributes);
begin
  Name := Default(TRegUnicodeString);
  Name.Buffer := PWideChar(NativePath);
  Name.Length := Word(Length(NativePath) * SizeOf(WideChar));
  Name.MaximumLength := Name.Length;
  Attr := Default(TRegObjectAttributes);
  Attr.Length := SizeOf(Attr);
  Attr.ObjectName := @Name;
  Attr.Attributes := $00000040; // OBJ_CASE_INSENSITIVE
end;

function NativeOpenRegistryKey(const NativePath: string): THandle;
const
  Rights: array[0..2] of Cardinal = (REG_REQUEST_ACCESS, REG_FALLBACK_ACCESS,
    REG_KEY_QUERY_VALUE or REG_KEY_ENUMERATE_SUB_KEYS);
var
  Name: TRegUnicodeString;
  Attr: TRegObjectAttributes;
  H: THandle;
  I: Integer;
  Status: TRegNtStatus;
begin
  Result := 0;
  if not RegistryPathValid(NativePath) then Exit;
  ResolveRegistryExports;
  if not RegistryLayoutsValid or not Assigned(POpenKey) or not Assigned(PCloseKey) then Exit;
  PrepareRegistryKeyArguments(NativePath, Name, Attr);
  for I := Low(Rights) to High(Rights) do
  begin
    H := 0;
    Status := POpenKey(H, Rights[I], @Attr);
    if Status = 0 then
    begin
      if RegistryHandleValid(H) then Result := H;
      Exit;
    end;
    // A failed API's output handle is unspecified: never close it or publish it.
  end;
end;

procedure NativeCloseRegistry(var Handle: THandle);
var
  Status: TRegNtStatus;
begin
  if Handle = 0 then Exit;
  if not RegistryHandleValid(Handle) then
  begin
    Handle := 0;
    Exit;
  end;
  ResolveRegistryExports;
  if not Assigned(PCloseKey) then Exit;
  // The caller owns this handle exclusively. Successful close (or an already
  // invalid handle) clears ownership; another close failure retains it for retry.
  Status := PCloseKey(Handle);
  if (Status = 0) or (Cardinal(Status) = REG_STATUS_INVALID_HANDLE) then Handle := 0;
end;

function NativeRegistryNotify(KeyHandle, EventHandle: THandle;
  Io: Pointer): TRegNtStatus;
begin
  Result := TRegNtStatus(REG_STATUS_INVALID_PARAMETER);
  if not RegistryHandleValid(KeyHandle) or not RegistryHandleValid(EventHandle) or
     ((NativeUInt(Io) and 7) <> 0) or
     not NHWAddressSpan(NativeUInt(Io), SizeOf(TRegIoStatusBlock)) then Exit;
  ResolveRegistryExports;
  Result := TRegNtStatus(REG_STATUS_NOT_IMPLEMENTED);
  if Assigned(PNotify) then
    // Io remains caller-owned and must stay alive until completion/key close.
    // Do not copy it to a temporary stack variable or re-arm while still pending.
    Result := PNotify(KeyHandle, EventHandle, nil, nil, Io,
      REG_NOTIFY_ALL, True, nil, 0, True);
end;

function NativeCreateRegistryEvent: THandle;
var
  H: THandle;
begin
  Result := 0;
  ResolveRegistryExports;
  if not Assigned(PCreateEvent) or not Assigned(PCloseKey) then Exit;
  H := 0;
  // SynchronizationEvent auto-reset; only signal/wait rights are required.
  if PCreateEvent(H, REG_EVENT_ACCESS, nil, 1, False) = 0 then
    if RegistryHandleValid(H) then Result := H;
end;

function NativePollRegistryEvent(EventHandle: THandle): Boolean;
var
  Zero: Int64;
begin
  Result := False;
  if not RegistryHandleValid(EventHandle) then Exit;
  ResolveRegistryExports;
  if not Assigned(PWait) then Exit;
  Zero := 0;
  Result := PWait(EventHandle, False, @Zero) = 0;
end;

function NativeEnumerateRegistryKey(Key: THandle; Index: Cardinal;
  Data: Pointer; Size: Cardinal; out Required: Cardinal): TRegNtStatus;
begin
  Required := 0;
  Result := TRegNtStatus(REG_STATUS_INVALID_PARAMETER);
  if not RegistryHandleValid(Key) or not RegistryBufferValid(Data, Size) then Exit;
  ResolveRegistryExports;
  Result := TRegNtStatus(REG_STATUS_NOT_IMPLEMENTED);
  if Assigned(PEnumerateKey) then
  begin
    Result := PEnumerateKey(Key, Index, 0, Data, Size, @Required);
    Result := CheckedRegistryResult(Result, Size, SizeOf(TRegKeyBasic), Required);
  end;
end;

function NativeEnumerateRegistryValue(Key: THandle; Index: Cardinal;
  Data: Pointer; Size: Cardinal; out Required: Cardinal): TRegNtStatus;
begin
  Required := 0;
  Result := TRegNtStatus(REG_STATUS_INVALID_PARAMETER);
  if not RegistryHandleValid(Key) or not RegistryBufferValid(Data, Size) then Exit;
  ResolveRegistryExports;
  Result := TRegNtStatus(REG_STATUS_NOT_IMPLEMENTED);
  if Assigned(PEnumerateValue) then
  begin
    Result := PEnumerateValue(Key, Index, 1, Data, Size, @Required);
    Result := CheckedRegistryResult(Result, Size, SizeOf(TRegValueFull), Required);
  end;
end;

function NativeRegistryDacl(Key: THandle; Data: Pointer; Size: Cardinal;
  out Required: Cardinal): TRegNtStatus;
begin
  Required := 0;
  Result := TRegNtStatus(REG_STATUS_INVALID_PARAMETER);
  if not RegistryHandleValid(Key) or not RegistryBufferValid(Data, Size) then Exit;
  ResolveRegistryExports;
  Result := TRegNtStatus(REG_STATUS_NOT_IMPLEMENTED);
  if Assigned(PQuerySecurity) then
  begin
    Result := PQuerySecurity(Key, REG_DACL_SECURITY_INFORMATION, Data, Size, @Required);
    Result := CheckedRegistryResult(Result, Size, SizeOf(TRegSelfRelativeSD), Required);
  end;
end;

function TokenSidInBounds(Buffer: Pointer; Capacity, Returned: Cardinal;
  out Sid: Pointer): Boolean;
var
  U: TRegTokenUser;
  Base, Address, Offset, SidBytes: NativeUInt;
  Revision, SubCount: Byte;
begin
  Result := False;
  Sid := nil;
  if (Returned < Cardinal(SizeOf(U))) or (Returned > Capacity) or
     not NHWAddressSpan(NativeUInt(Buffer), NativeUInt(Returned)) then Exit;
  U := Default(TRegTokenUser);
  Move(Buffer^, U, SizeOf(U));
  Base := NativeUInt(Buffer);
  Address := NativeUInt(U.Sid);
  if (Address < Base) or ((Address and 3) <> 0) then Exit;
  Offset := Address - Base;
  if (Offset < NativeUInt(SizeOf(U))) or
     not NHWBufferSpan(Returned, Offset, 8) then Exit;
  Revision := PByte(Address)^;
  SubCount := PByte(Address + 1)^;
  if (Revision <> 1) or (SubCount > REG_MAX_SID_AUTHORITIES) then Exit;
  SidBytes := NativeUInt(8) + NativeUInt(SubCount) * NativeUInt(SizeOf(Cardinal));
  if not NHWBufferSpan(Returned, Offset, SidBytes) then Exit;
  Sid := U.Sid;
  Result := True;
end;

function RegistryRootFromSid(Sid: Pointer): string;
var
  U: TRegUnicodeString;
begin
  Result := '';
  U := Default(TRegUnicodeString);
  try
    if PConvertSid(@U, Sid, True) <> 0 then Exit;
    if (U.Buffer = nil) or (U.Length = 0) or
       ((U.Length and 1) <> 0) or ((U.MaximumLength and 1) <> 0) or
       (U.Length > U.MaximumLength) then Exit;
    SetString(Result, U.Buffer, Integer(U.Length) div SizeOf(WideChar));
    if Pos(#0, Result) <> 0 then Result := ''
    else Result := '\Registry\User\' + Result;
  finally
    if U.Buffer <> nil then PFreeUnicode(@U);
  end;
end;

function NativeCurrentUserRegistryRoot: string;
var
  Token: THandle;
  B: array[0..2047] of Byte;
  Ret: Cardinal;
  Sid: Pointer;
begin
  Result := '';
  ResolveRegistryExports;
  if not RegistryLayoutsValid or not Assigned(PCloseKey) or
     not Assigned(POpenToken) or not Assigned(PQueryToken) or
     not Assigned(PConvertSid) or not Assigned(PFreeUnicode) then Exit;
  Token := 0;
  if POpenToken(WinCurrentProcess, REG_TOKEN_QUERY, Token) <> 0 then Exit;
  if not RegistryHandleValid(Token) then Exit;
  try
    FillChar(B, SizeOf(B), 0);
    Ret := 0;
    if PQueryToken(Token, REG_TOKEN_USER_CLASS, @B[0], SizeOf(B), @Ret) <> 0 then Exit;
    if not TokenSidInBounds(@B[0], SizeOf(B), Ret, Sid) then Exit;
    Result := RegistryRootFromSid(Sid);
  finally
    NativeCloseRegistry(Token);
  end;
end;

{$IFDEF NHW_HARDENING_TESTS}
function TestRegistryHardening(out Failure: string; out Checks: Integer): Boolean;
var
  B: array[0..127] of Byte;
  U: TRegTokenUser;
  Sid: Pointer;
  Required: Cardinal;
  Status: TRegNtStatus;

  procedure Check(Condition: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Text);
  end;

begin
  Result := False; Failure := ''; Checks := 0;
  try
    Check(RegistryLayoutsValid, 'registry ABI sizes');
    Check(RegistryPathValid('\Registry\Machine\Software'), 'absolute native path');
    Check(not RegistryPathValid('') and not RegistryPathValid('relative') and
      not RegistryPathValid('\Registry\User\x' + #0 + 'y'), 'invalid registry paths');
    Check(RegistryBufferValid(nil, 0) and not RegistryBufferValid(nil, 1), 'sizing query vs missing buffer');
    Required := 256;
    Status := CheckedRegistryResult(0, 128, 16, Required);
    Check((Status < 0) and (Required = 0), 'oversized success rejected');
    Required := 8;
    Status := CheckedRegistryResult(0, 128, 16, Required);
    Check((Status < 0) and (Required = 0), 'truncated success rejected');
    Required := 256;
    Status := CheckedRegistryResult(TRegNtStatus(REG_STATUS_BUFFER_TOO_SMALL), 128, 16, Required);
    Check((Cardinal(Status) = REG_STATUS_BUFFER_TOO_SMALL) and (Required = 256), 'resize hint preserved');
    FillChar(B, SizeOf(B), 0);
    U := Default(TRegTokenUser); U.Sid := @B[16];
    Move(U, B[0], SizeOf(U)); B[16] := 1; B[17] := 2;
    Check(TokenSidInBounds(@B[0], SizeOf(B), 32, Sid), 'complete token SID');
    Check(not TokenSidInBounds(@B[0], SizeOf(B), 31, Sid) and (Sid = nil), 'SID tail beyond returned data');
    Check(not TokenSidInBounds(@B[0], SizeOf(B), 129, Sid), 'reported size exceeds capacity');
    B[17] := 16;
    Check(not TokenSidInBounds(@B[0], SizeOf(B), 128, Sid), 'invalid SID subauthority count');
    B[17] := 2; B[16] := 2;
    Check(not TokenSidInBounds(@B[0], SizeOf(B), 128, Sid), 'invalid SID revision');
    U.Sid := @B[4]; Move(U, B[0], SizeOf(U));
    Check(not TokenSidInBounds(@B[0], SizeOf(B), 128, Sid), 'SID cannot overlap token header');
    Result := True;
  except
    on E: Exception do Failure := E.Message;
  end;
end;
{$ENDIF}

initialization
  ResolveLock := TCriticalSection.Create;

finalization
  ResolveLock.Free;

end.
