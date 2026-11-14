unit Cozy.Api.Contracts;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,
 {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF};
type
  { Internal lifetime capability. A copied scoped view retains this small
    revocation token, not an independently usable copy of sensitive bytes. }
  IApiBufferLease = interface
    ['{73CD4C8A-0863-480A-83A2-DB02A53AAC82}']
    procedure RequireActive;
    procedure Release;
  end;
  { Borrowed spans never allocate, free, transfer or extend an owner's lifetime.
    Owner must keep the allocation pinned for the complete synchronous call;
    asynchronous callers retain their owner until kernel completion. }
  TApiBuffer = record
  private
    FAddress: Pointer;
    FCapacity: NativeUInt;
    FWritable: Boolean;
    FLease: IApiBufferLease;
    procedure RequireLifetime;
    function GetCapacity: NativeUInt;
  public
    class function Borrow(Address: Pointer; Capacity: NativeUInt; Writable: Boolean): TApiBuffer; static;
    class function ReadBytes(const Bytes: TBytes): TApiBuffer; static;
    class function WriteBytes(var Bytes: TBytes): TApiBuffer; static;
    function Read(Offset, Count: NativeUInt): Pointer;
    function Write(Offset, Count: NativeUInt): Pointer;
    procedure Completed(Requested, Actual: NativeUInt);
    procedure Disjoint(const Other: TApiBuffer);
    property Capacity: NativeUInt read GetCapacity;
  end;
  { Use a scope only in one synchronous call chain. Never retain a returned raw
    pointer, reconstruct an unguarded Borrow from it, or submit it to async I/O.
    Free the scope in finally (including cancellation/exception). Closing the
    owner immediately revokes views; physical wiping waits for this scope to
    exit, so a synchronous native call already using its pointer can drain. }
  TApiSensitiveScope = class
  private
    FLease: IApiBufferLease;
    FBuffer: TApiBuffer;
    function GetBuffer: TApiBuffer;
  public
    destructor Destroy; override;
    procedure Close;
    property Buffer: TApiBuffer read GetBuffer;
  end;
  { Owns only this allocation. CreateUtf8 borrows the caller's UnicodeString;
    it cannot erase that original string or copies owned elsewhere. This is
    bounded lifetime/wiping, not encryption, page locking or dump protection. }
  TApiSensitiveBuffer = class
  private
    FState: IInterface;
    procedure InitializeUtf8(const Prefix: UTF8String; const Text: UnicodeString;
      const Suffix: UTF8String; MaximumBytes: Integer);
    function OpenScope(Writable: Boolean): TApiSensitiveScope;
    function GetCapacity: NativeUInt;
  public
    constructor Create(Capacity: NativeUInt);
    constructor CreateUtf8(const Text: UnicodeString);
    { Encodes directly into one exact-sized owner, without a second body copy.
      Prefix and Suffix are trusted wire bytes, not user-controlled JSON text. }
    constructor CreateUtf8Framed(const Prefix: UTF8String; const Text: UnicodeString;
      const Suffix: UTF8String; MaximumBytes: Integer);
    destructor Destroy; override;
    function OpenRead: TApiSensitiveScope;
    function OpenWrite: TApiSensitiveScope;
    procedure Clear;
    procedure Close;
    property Capacity: NativeUInt read GetCapacity;
  end;
const
  MaxApiSensitiveBytes = 16 * 1024 * 1024;
procedure RequireApiTarget(Target: Pointer);
procedure RequireApiStruct(Actual, Expected: NativeUInt);
procedure RequireProcessCommand(const Buffer: TApiBuffer; Characters: NativeUInt);
procedure RequireCngBuffers(const Input, Output: TApiBuffer;
  InputCount, OutputCount: NativeUInt; AllowInPlace: Boolean);
implementation
uses {$IFDEF FPC}SyncObjs{$ELSE}System.SyncObjs{$ENDIF};
type
  TApiEncodingAccess = class
  public
    class function EncodeUtf8(const Prefix: UTF8String; const Text: UnicodeString;
      const Suffix: UTF8String; MaximumBytes: Integer): TBytes; static;
  end;
  IApiSensitiveState = interface
    ['{C719CDF1-65C7-4422-BFB0-BC3EF0C435FA}']
    function Open(out Address: Pointer; out Capacity: NativeUInt): UInt64;
    procedure Check(Token: UInt64);
    procedure EndScope(Token: UInt64);
    procedure Close;
    procedure Clear;
    function Capacity: NativeUInt;
  end;
  TApiSensitiveState = class(TInterfacedObject, IApiSensitiveState)
  private
    FLock: TCriticalSection;
    FAddress: Pointer;
    FCapacity: NativeUInt;
    { Present only for internal UTF8 encoders. Never returned or resized while
      live: scoped views borrow the same stable backing allocation. }
    FOwnedBytes: TBytes;
    FToken: UInt64;
    FActive, FClosed: Boolean;
    procedure Retire;
  public
    constructor Create(Count: NativeUInt);
    constructor TakeEncoded(var Bytes: TBytes);
    destructor Destroy; override;
    function Open(out Address: Pointer; out Count: NativeUInt): UInt64;
    procedure Check(Token: UInt64);
    procedure EndScope(Token: UInt64);
    procedure Close;
    procedure Clear;
    function Capacity: NativeUInt;
  end;
  TApiSensitiveLease = class(TInterfacedObject, IApiBufferLease)
  private
    FState: IApiSensitiveState;
    FToken: UInt64;
  public
    constructor Create(const State: IApiSensitiveState; Token: UInt64);
    destructor Destroy; override;
    procedure RequireActive;
    procedure Release;
  end;

class function TApiEncodingAccess.EncodeUtf8(const Prefix: UTF8String;
  const Text: UnicodeString; const Suffix: UTF8String;
  MaximumBytes: Integer): TBytes;
var Encoded: TBytes; PrefixSize, BodySize, SuffixSize, Actual: Integer;
{$IFDEF FPC}
    BodyBytes: TBytes;
{$ENDIF}
begin
  Encoded := nil;
  if (MaximumBytes < 0) or (MaximumBytes > MaxApiSensitiveBytes) or
    (Length(Text) > MaximumBytes) then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_SENSITIVE_CAPACITY_3fe22bc3);
  PrefixSize := Length(Prefix); SuffixSize := Length(Suffix);
  if (PrefixSize > MaximumBytes) or (SuffixSize > MaximumBytes - PrefixSize) then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_SENSITIVE_CAPACITY_3fe22bc3);
  BodySize := TEncoding.UTF8.GetByteCount(Text);
  if (BodySize < 0) or (BodySize > MaximumBytes - PrefixSize - SuffixSize) then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_SENSITIVE_CAPACITY_3fe22bc3);
  try
    SetLength(Encoded, PrefixSize + BodySize + SuffixSize);
    if PrefixSize <> 0 then Move(Prefix[1], Encoded[0], PrefixSize);
    if BodySize <> 0 then
    begin
{$IFDEF FPC}
      { Compatibility fallback for older FPC, not the Windows Delphi path. }
      BodyBytes := TEncoding.UTF8.GetBytes(Text);
      try
        Actual := Length(BodyBytes);
        if Actual <> BodySize then raise EArgumentException.Create(CozyText_Api_Contracts_API_SENSITIVE_ENCODING_ef3c59a3);
        Move(BodyBytes[0], Encoded[PrefixSize], Actual);
      finally
        if Length(BodyBytes) <> 0 then FillChar(BodyBytes[0], Length(BodyBytes), 0);
        BodyBytes := nil;
      end;
{$ELSE}
      { Public indexed string overload: one-based UTF16 input, zero-based byte
        destination. No private pointer overload and no temporary body TBytes. }
      Actual := TEncoding.UTF8.GetBytes(Text, 1, Length(Text), Encoded, PrefixSize);
{$ENDIF}
      if Actual <> BodySize then raise EArgumentException.Create(CozyText_Api_Contracts_API_SENSITIVE_ENCODING_ef3c59a3);
    end;
    if SuffixSize <> 0 then Move(Suffix[1], Encoded[PrefixSize + BodySize], SuffixSize);
    Result := Encoded; Encoded := nil;
  finally
    { On any encoding failure, including a partial write, clear before release. }
    if Length(Encoded) <> 0 then FillChar(Encoded[0], Length(Encoded), 0);
    Encoded := nil;
  end;
end;

constructor TApiSensitiveState.Create(Count: NativeUInt);
begin
  inherited Create;
  if Count > MaxApiSensitiveBytes then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_SENSITIVE_CAPACITY_3fe22bc3);
  FLock := TCriticalSection.Create;
  if Count <> 0 then
  begin
    GetMem(FAddress, Count);
    FCapacity := Count;
    FillChar(FAddress^, FCapacity, 0);
  end;
end;
constructor TApiSensitiveState.TakeEncoded(var Bytes: TBytes);
begin
  inherited Create;
  if Length(Bytes) > MaxApiSensitiveBytes then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_SENSITIVE_CAPACITY_3fe22bc3);
  FLock := TCriticalSection.Create;
  { Called only with this unit's unaliased local encoding result. Transfer the
    backing array, never clone it or expose it to callers as a dynamic array. }
  FOwnedBytes := Bytes; Bytes := nil;
  FCapacity := Length(FOwnedBytes);
  if FCapacity <> 0 then FAddress := @FOwnedBytes[0];
end;
procedure TApiSensitiveState.Retire;
begin
  { Called with the state lock held, after the last synchronous scope drains.
    FillChar writes the complete allocation before it returns to the allocator. }
  if FAddress <> nil then
  begin
    FillChar(FAddress^, FCapacity, 0);
    if Length(FOwnedBytes) <> 0 then FOwnedBytes := nil
    else FreeMem(FAddress);
    FAddress := nil;
  end;
  FCapacity := 0;
end;
destructor TApiSensitiveState.Destroy;
begin
  Retire;
  FLock.Free;
  inherited Destroy;
end;
function TApiSensitiveState.Open(out Address: Pointer; out Count: NativeUInt): UInt64;
begin
  FLock.Acquire;
  try
    if FClosed then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_CLOSED_5d20ef8c);
    if FActive then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_SCOPE_ACTIVE_32c7429c);
    if FToken = High(UInt64) then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_SCOPE_EXHAUSTED_53ffb961);
    Inc(FToken);
    FActive := True;
    Address := FAddress; Count := FCapacity; Result := FToken;
  finally FLock.Release; end;
end;
procedure TApiSensitiveState.Check(Token: UInt64);
begin
  FLock.Acquire;
  try
    if FClosed or not FActive or (Token <> FToken) then
      raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_VIEW_REVOKED_127d77b0);
  finally FLock.Release; end;
end;
procedure TApiSensitiveState.EndScope(Token: UInt64);
begin
  FLock.Acquire;
  try
    if FActive and (Token = FToken) then FActive := False;
    if FClosed and not FActive then Retire;
  finally FLock.Release; end;
end;
procedure TApiSensitiveState.Close;
begin
  FLock.Acquire;
  try
    FClosed := True;
    if not FActive then Retire;
  finally FLock.Release; end;
end;
procedure TApiSensitiveState.Clear;
begin
  FLock.Acquire;
  try
    if FClosed then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_CLOSED_5d20ef8c);
    if FActive then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_SCOPE_ACTIVE_32c7429c);
    if FAddress <> nil then FillChar(FAddress^, FCapacity, 0);
  finally FLock.Release; end;
end;
function TApiSensitiveState.Capacity: NativeUInt;
begin
  FLock.Acquire;
  try
    if FClosed then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_CLOSED_5d20ef8c);
    Result := FCapacity;
  finally FLock.Release; end;
end;
constructor TApiSensitiveLease.Create(const State: IApiSensitiveState; Token: UInt64);
begin inherited Create; FState := State; FToken := Token; end;
destructor TApiSensitiveLease.Destroy;
begin Release; inherited Destroy; end;
procedure TApiSensitiveLease.RequireActive;
begin
  if FState = nil then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_VIEW_REVOKED_127d77b0);
  FState.Check(FToken);
end;
procedure TApiSensitiveLease.Release;
begin
  if FState <> nil then
  begin
    FState.EndScope(FToken);
    FState := nil;
  end;
end;
function TApiSensitiveScope.GetBuffer: TApiBuffer;
begin
  if FLease = nil then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_VIEW_REVOKED_127d77b0);
  FLease.RequireActive;
  Result := FBuffer;
end;
procedure TApiSensitiveScope.Close;
begin
  if FLease <> nil then FLease.Release;
  FLease := nil;
  FBuffer := Default(TApiBuffer);
end;
destructor TApiSensitiveScope.Destroy;
begin Close; inherited Destroy; end;
constructor TApiSensitiveBuffer.Create(Capacity: NativeUInt);
begin
  inherited Create;
  FState := TApiSensitiveState.Create(Capacity) as IApiSensitiveState;
end;
procedure TApiSensitiveBuffer.InitializeUtf8(const Prefix: UTF8String;
  const Text: UnicodeString; const Suffix: UTF8String; MaximumBytes: Integer);
var Encoded: TBytes; State: IApiSensitiveState;
begin
  Encoded := nil;
  try
    Encoded := TApiEncodingAccess.EncodeUtf8(Prefix, Text, Suffix, MaximumBytes);
    State := TApiSensitiveState.TakeEncoded(Encoded);
    FState := State;
  finally
    { Allocation/lock failure before the private ownership transfer. }
    if Length(Encoded) <> 0 then FillChar(Encoded[0], Length(Encoded), 0);
    Encoded := nil;
  end;
end;
constructor TApiSensitiveBuffer.CreateUtf8(const Text: UnicodeString);
begin
  inherited Create;
  InitializeUtf8('', Text, '', MaxApiSensitiveBytes);
end;
constructor TApiSensitiveBuffer.CreateUtf8Framed(const Prefix: UTF8String;
  const Text: UnicodeString; const Suffix: UTF8String; MaximumBytes: Integer);
begin
  inherited Create;
  InitializeUtf8(Prefix, Text, Suffix, MaximumBytes);
end;
function TApiSensitiveBuffer.OpenScope(Writable: Boolean): TApiSensitiveScope;
var State: IApiSensitiveState; Address: Pointer; Count: NativeUInt; Token: UInt64;
begin
  if FState = nil then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_CLOSED_5d20ef8c);
  State := FState as IApiSensitiveState;
  Token := State.Open(Address, Count);
  Result := nil;
  try
    Result := TApiSensitiveScope.Create;
    Result.FLease := TApiSensitiveLease.Create(State, Token);
    Result.FBuffer := TApiBuffer.Borrow(Address, Count, Writable);
    Result.FBuffer.FLease := Result.FLease;
  except
    Result.Free;
    State.EndScope(Token);
    raise;
  end;
end;
function TApiSensitiveBuffer.OpenRead: TApiSensitiveScope;
begin Result := OpenScope(False); end;
function TApiSensitiveBuffer.OpenWrite: TApiSensitiveScope;
begin Result := OpenScope(True); end;
function TApiSensitiveBuffer.GetCapacity: NativeUInt;
begin
  if FState = nil then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_CLOSED_5d20ef8c);
  Result := (FState as IApiSensitiveState).Capacity;
end;
procedure TApiSensitiveBuffer.Clear;
begin
  if FState = nil then raise EInvalidOpException.Create(CozyText_Api_Contracts_API_SENSITIVE_CLOSED_5d20ef8c);
  (FState as IApiSensitiveState).Clear;
end;
procedure TApiSensitiveBuffer.Close;
begin
  if FState <> nil then (FState as IApiSensitiveState).Close;
end;
destructor TApiSensitiveBuffer.Destroy;
begin Close; FState := nil; inherited Destroy; end;
procedure TApiBuffer.RequireLifetime;
begin if FLease <> nil then FLease.RequireActive; end;
function TApiBuffer.GetCapacity: NativeUInt;
begin RequireLifetime; Result := FCapacity; end;
procedure RequireApiTarget(Target: Pointer);
begin if Target = nil then raise EArgumentException.Create(CozyText_Api_Contracts_API_TARGET_REQUIRED_0ba34107); end;
procedure RequireApiStruct(Actual, Expected: NativeUInt);
begin if (Expected = 0) or (Actual <> Expected) then raise EArgumentException.Create(CozyText_Api_Contracts_API_STRUCT_SIZE_b731c1b7); end;
class function TApiBuffer.Borrow(Address: Pointer; Capacity: NativeUInt; Writable: Boolean): TApiBuffer;
begin
  if ((Address = nil) and (Capacity <> 0)) or
    ((Capacity <> 0) and (NativeUInt(Address) > High(NativeUInt) - (Capacity - 1))) then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_BUFFER_RANGE_17bfadf0);
  Result.FLease := nil;
  Result.FAddress := Address; Result.FCapacity := Capacity; Result.FWritable := Writable;
end;
class function TApiBuffer.ReadBytes(const Bytes: TBytes): TApiBuffer;
var P: Pointer;
begin P := nil; if Length(Bytes) <> 0 then P := @Bytes[0]; Result := Borrow(P, Length(Bytes), False); end;
class function TApiBuffer.WriteBytes(var Bytes: TBytes): TApiBuffer;
var P: Pointer;
begin P := nil; if Length(Bytes) <> 0 then P := @Bytes[0]; Result := Borrow(P, Length(Bytes), True); end;
function TApiBuffer.Read(Offset, Count: NativeUInt): Pointer;
begin
  RequireLifetime;
  if (Offset > FCapacity) or (Count > FCapacity - Offset) then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_BUFFER_CAPACITY_d5fbcca4);
  if Count = 0 then Exit(nil);
  Result := Pointer(NativeUInt(FAddress) + Offset);
end;
function TApiBuffer.Write(Offset, Count: NativeUInt): Pointer;
begin
  RequireLifetime;
  if not FWritable then raise EArgumentException.Create(CozyText_Api_Contracts_API_BUFFER_READ_ONLY_95c30e95);
  Result := Read(Offset, Count);
end;
procedure TApiBuffer.Completed(Requested, Actual: NativeUInt);
begin
  Read(0, Requested);
  if Actual > Requested then raise EArgumentException.Create(CozyText_Api_Contracts_API_RESULT_LENGTH_8817f1ef);
end;
procedure TApiBuffer.Disjoint(const Other: TApiBuffer);
begin
  RequireLifetime; Other.RequireLifetime;
  if (FCapacity = 0) or (Other.FCapacity = 0) then Exit;
  { Subtraction avoids wrapping one-past-end addresses. }
  if NativeUInt(FAddress) <= NativeUInt(Other.FAddress) then
  begin
    if NativeUInt(Other.FAddress) - NativeUInt(FAddress) < FCapacity then
      raise EArgumentException.Create(CozyText_Api_Contracts_API_BUFFER_OVERLAP_ad4e964c);
  end
  else if NativeUInt(FAddress) - NativeUInt(Other.FAddress) < Other.FCapacity then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_BUFFER_OVERLAP_ad4e964c);
end;
procedure RequireProcessCommand(const Buffer: TApiBuffer; Characters: NativeUInt);
var P: PWideChar; I: NativeUInt;
begin
  if (Characters = 0) or (Characters > 32767) then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_COMMAND_LENGTH_3163ea58);
  P := Buffer.Write(0, Characters * SizeOf(WideChar));
  if P[Characters - 1] <> #0 then raise EArgumentException.Create(CozyText_Api_Contracts_API_COMMAND_TERMINATOR_da284e92);
  if Characters > 1 then for I := 0 to Characters - 2 do
    if P[I] = #0 then raise EArgumentException.Create(CozyText_Api_Contracts_API_COMMAND_EMBEDDED_NUL_3a5b9df6);
end;
procedure RequireCngBuffers(const Input, Output: TApiBuffer;
  InputCount, OutputCount: NativeUInt; AllowInPlace: Boolean);
begin
  if (InputCount > High(Cardinal)) or (OutputCount > High(Cardinal)) then
    raise EArgumentException.Create(CozyText_Api_Contracts_API_CNG_LENGTH_986fdebc);
  Input.Read(0, InputCount); Output.Write(0, OutputCount);
  if not (AllowInPlace and (Input.FAddress = Output.FAddress)) then Input.Disjoint(Output);
end;
end.
