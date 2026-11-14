unit Cozy.Bootstrap;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Application,
 Cozy.OwnedRuntime,
  Winapi.Windows, System.SysUtils, Cozy.Lifetime, System.JSON, Cozy.Security,
  Cozy.Server.Profile, Cozy.Transport, Cozy.Integrity, Cozy.CodeIntegrity, Cozy.Measurement, Cozy.SensitiveText, Cozy.ServerAuthority, Cozy.NHW.Guard, Cozy.NHW.TpmQuote;

type
  EBootstrap = class(Exception);
  TBootstrapRelease = record
    ID, Version, SHA512, CRC64, XXH3_128, Blake3: string;
    CodeSHA512, CodeCRC64, CodeXXH3_128, CodeBlake3: string;
    Size: Int64;
  end;
  TBootstrapFlow = record
  private
    FDownloadTicket: TCozySecret;
    FFinishCanonical: TCozySecret;
    function GetDownloadTicket: string;
    procedure SetDownloadTicket(const Value: string);
    function GetFinishCanonical: string;
    procedure SetFinishCanonical(const Value: string);
  public
    FlowID: string;
    ExpiresAt: Int64;
    ChunkSize: Integer;
    Release: TBootstrapRelease;
    procedure ClearSecrets;
    procedure ReleaseSecrets;
    property DownloadTicket: string read GetDownloadTicket write SetDownloadTicket;
    property FinishCanonical: string read GetFinishCanonical write SetFinishCanonical;
  end;
  TBootstrapGrant = record
  private
    FHandoffToken: TCozySecret;
    FClaimCanonical: TCozySecret;
    function GetHandoffToken: string;
    procedure SetHandoffToken(const Value: string);
    function GetClaimCanonical: string;
    procedure SetClaimCanonical(const Value: string);
  public
    ExpiresAt: Int64;
    procedure ClearSecrets;
    procedure ReleaseSecrets;
    property HandoffToken: string read GetHandoffToken write SetHandoffToken;
    property ClaimCanonical: string read GetClaimCanonical write SetClaimCanonical;
  end;
  TBootstrapSession = record
  private
    FSessionToken: TCozySecret;
    function GetSessionToken: string;
    procedure SetSessionToken(const Value: string);
  public
    SessionID: string;
    ExpiresAt: Int64;
    Release: TBootstrapRelease;
    procedure ClearSecrets;
    procedure ReleaseSecrets;
    property SessionToken: string read GetSessionToken write SetSessionToken;
  end;
  TBootstrapClient = class
  private
    FNHWAuthority: ICozyAuthorityExtension;
    FNHWQuoter: ICozyTpmQuoter;
    FRuntimeGraph: TCozyOwnedRuntimeGraph;
    FOwnImage: TImageIntegrity;
    FGate: TGameCallGate;
    FLock: TObject;
    FClosed: Boolean;
    FTransport: TConnectTransport;
    FSession: TBootstrapSession;
    FFlowStarted: UInt64;
    FLauncherSHA512, FLauncherCRC64, FLauncherID: string;
    FLauncherCodeSHA512, FLauncherCodeCRC64: string;
    function OwnRuntime(Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity): ICozyRuntimeMeasurement;
    function Post(const Action: string; Body: TJSONObject): TJSONObject;
    function GetSession: TBootstrapSession;
    function BeginKeylessFlowCore(const RequestID, LauncherID,
      LauncherSHA512, LauncherCRC64: string; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity; DiagnosticCode: PInteger): TBootstrapFlow;
    function ChunkCore(const Flow: TBootstrapFlow; Offset: Int64): TBytes;
    function FinishCore(const Flow: TBootstrapFlow;
      Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapGrant;
    function ClaimCore(const FlowID, HandoffToken, ClaimCanonical,
      BinarySHA512, BinaryCRC64, BinaryXXH3_128, BinaryBlake3: string; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity): TBootstrapSession;
    function StatusCore: TJSONObject;
    procedure CloseCore;
    procedure AbortFlowCore(const Flow: TBootstrapFlow);
    procedure ReportIntegrityCore(const Flow: TBootstrapFlow; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity; const Image: TImageDigest; IncludeModules: Boolean;
      FailureStatus: TMeasurementStatus = msMeasured; OwnImage: TImageIntegrity = nil;
      const Cancelled: TAuthorityCancelled = nil);
    function GetSessionCore: TBootstrapSession;
  public
    procedure AttachNHW(Guard: TCozyNHWGuard);
    procedure FlushNHWReports(TimeoutMS: Cardinal = 3500);
    property NHWQuoter: ICozyTpmQuoter read FNHWQuoter;
    constructor Create(Profile: TConnectServerProfile);
    destructor Destroy; override;
    function BeginKeylessFlow(const RequestID, LauncherID,
      LauncherSHA512, LauncherCRC64: string; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity; DiagnosticCode: PInteger = nil): TBootstrapFlow;
    function Chunk(const Flow: TBootstrapFlow; Offset: Int64): TBytes;
    function Finish(const Flow: TBootstrapFlow;
      Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapGrant;
    function Claim(const FlowID, HandoffToken, ClaimCanonical,
      BinarySHA512, BinaryCRC64, BinaryXXH3_128, BinaryBlake3: string; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity): TBootstrapSession;
    { Explicit custom function call; no policy implementation is stored locally.
      Retain the client/context until return; cancellation is a nonblocking poll
      and must not reenter/free this client. }
    function InvokeServerPolicy(const Flow: TBootstrapFlow; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity; FunctionID: Word;
      const Args: array of Integer; const Cancelled: TAuthorityCancelled = nil): Integer;
    function Status: TJSONObject;
    procedure Close;
    procedure AbortFlow(const Flow: TBootstrapFlow);
    procedure ReportIntegrity(const Flow: TBootstrapFlow; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity; const Image: TImageDigest; IncludeModules: Boolean;
      FailureStatus: TMeasurementStatus = msMeasured; OwnImage: TImageIntegrity = nil);
    property Session: TBootstrapSession read GetSession;
  end;

function HashFileSHA512(const FileName: string): string;
function HashHandleSHA512(Handle: THandle): string;
function CurrentImagePath: string;
function BootstrapRequestID: string;
function BootstrapRandomFileName(const Extension: string): string;
function BootstrapUTCNowMS: Int64;
function BootstrapString(Obj: TJSONObject; const Name: string;
  MaxLength: Integer = 4096): string;
function BootstrapInteger(Obj: TJSONObject; const Name: string): Int64;
procedure BootstrapValidateObject(Obj: TJSONObject; const Fields: string;
  ExpectedCount: Integer);
procedure BootstrapCheckSHA512(const Value: string);
procedure BootstrapCheckCRC64(const Value: string);

implementation

uses Cozy.NHW.Authority, Cozy.NHW.ResponsePath.Dispatch, Cozy.Clock,
  System.NetEncoding, Cozy.OwnMeasurement, Cozy.DeviceIdentity, Cozy.KeylessBootstrap, System.Generics.Collections, Cozy.ModuleInventory, Cozy.ServerOperations,
  Winapi.WinSock2,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer, Cozy.Api.Guid;

function TBootstrapFlow.GetDownloadTicket: string;
begin Result := FDownloadTicket.CopyText; end;
procedure TBootstrapFlow.SetDownloadTicket(const Value: string);
begin FDownloadTicket.Assign(Value, 512); end;
function TBootstrapFlow.GetFinishCanonical: string;
begin Result := FFinishCanonical.CopyText; end;
procedure TBootstrapFlow.SetFinishCanonical(const Value: string);
begin FFinishCanonical.Assign(Value, 4096); end;
procedure TBootstrapFlow.ClearSecrets;
begin FDownloadTicket.Clear; FFinishCanonical.Clear; end;
procedure TBootstrapFlow.ReleaseSecrets;
begin FDownloadTicket.Release; FFinishCanonical.Release; end;

function TBootstrapGrant.GetHandoffToken: string;
begin Result := FHandoffToken.CopyText; end;
procedure TBootstrapGrant.SetHandoffToken(const Value: string);
begin FHandoffToken.Assign(Value, 512); end;
function TBootstrapGrant.GetClaimCanonical: string;
begin Result := FClaimCanonical.CopyText; end;
procedure TBootstrapGrant.SetClaimCanonical(const Value: string);
begin FClaimCanonical.Assign(Value, 4096); end;
procedure TBootstrapGrant.ClearSecrets;
begin FHandoffToken.Clear; FClaimCanonical.Clear; end;
procedure TBootstrapGrant.ReleaseSecrets;
begin FHandoffToken.Release; FClaimCanonical.Release; end;

function TBootstrapSession.GetSessionToken: string;
begin Result := FSessionToken.CopyText; end;
procedure TBootstrapSession.SetSessionToken(const Value: string);
begin FSessionToken.Assign(Value, 512); end;
procedure TBootstrapSession.ClearSecrets;
begin FSessionToken.Clear; end;
procedure TBootstrapSession.ReleaseSecrets;
begin FSessionToken.Release; end;

{ Private API pointers: initialized before application code starts. }
var

  ApiSlot_GetSystemTimeAsFileTime: TEncodedApiPointer;
  ApiSlot_GetModuleFileNameW: TEncodedApiPointer;
  ApiSlot_send: TEncodedApiPointer;


{ POINTER WRAPPERS 1 BEGIN }

procedure GetSystemTimeAsFileTime(var Time: TFileTime); stdcall;
var
  ApiTarget: TApiGetSystemTimeAsFileTime;
begin
  ApiTarget := TApiGetSystemTimeAsFileTime(DecodeApiPointer(ApiSlot_GetSystemTimeAsFileTime));
  ApiTarget(Time);
end;

function GetModuleFileNameW(Module: HMODULE; FileName: PWideChar; Size: DWORD): DWORD; stdcall;
var
  ApiTarget: TApiGetModuleFileNameW;
begin
  ApiTarget := TApiGetModuleFileNameW(DecodeApiPointer(ApiSlot_GetModuleFileNameW));
  Result := ApiTarget(Module, FileName, Size);
end;

function send(Socket: TSocket; const Buffer; Length, Flags: Integer): Integer; stdcall;
var
  ApiTarget: TApiSend;
begin
  ApiTarget := TApiSend(DecodeApiPointer(ApiSlot_send));
  Result := ApiTarget(Socket, Buffer, Length, Flags);
end;
{ POINTER WRAPPERS 1 END }

procedure InvalidResponse;
begin
  raise EBootstrap.Create(CozyText_Bootstrap_The_authenticated_bootstrap_response_is_invalid_999435b9);
end;

function BootstrapUTCNowMS: Int64;
var Time: TFileTime; Ticks: UInt64;
begin
  GetSystemTimeAsFileTime(Time);
  Ticks := (UInt64(Time.dwHighDateTime) shl 32) or Time.dwLowDateTime;
  Result := Int64(Ticks div 10000) - 11644473600000;
end;

function BootstrapString(Obj: TJSONObject; const Name: string;
  MaxLength: Integer): string;
var V: TJSONValue;
begin
  if Obj = nil then InvalidResponse;
  V := Obj.GetValue(Name);
  if not (V is TJSONString) then InvalidResponse;
  Result := V.Value;
  if (Result = '') or (Length(Result) > MaxLength) or (Pos(#0, Result) > 0) then
    InvalidResponse;
end;

function BootstrapInteger(Obj: TJSONObject; const Name: string): Int64;
var V: TJSONValue;
begin
  if Obj = nil then InvalidResponse;
  V := Obj.GetValue(Name);
  if not (V is TJSONNumber) then InvalidResponse;
  if not TryStrToInt64(V.Value, Result) or (Result < 0) then InvalidResponse;
end;

procedure BootstrapValidateObject(Obj: TJSONObject; const Fields: string;
  ExpectedCount: Integer);
var Pair: TJSONPair; Seen, Name: string;
begin
  if (Obj = nil) or (Obj.Count <> ExpectedCount) then InvalidResponse;
  Seen := '|';
  for Pair in Obj do
  begin
    Name := Pair.JsonString.Value;
    if (Pos('|' + Name + '|', Fields) = 0) or
      (Pos('|' + Name + '|', Seen) > 0) then InvalidResponse;
    Seen := Seen + Name + '|';
  end;
end;

procedure BootstrapCheckSHA512(const Value: string);
var C: Char;
begin
  if Length(Value) <> 128 then InvalidResponse;
  for C in Value do
    if not CharInSet(C, ['0'..'9', 'a'..'f']) then InvalidResponse;
end;

procedure BootstrapCheckCRC64(const Value: string);
var C: Char;
begin
  if Length(Value) <> 16 then InvalidResponse;
  for C in Value do
    if not CharInSet(C, ['0'..'9', 'A'..'F']) then InvalidResponse;
end;

function ParseHex(Obj: TJSONObject; const Name: string; Digits: Integer): string;
var C: Char;
begin
  Result := BootstrapString(Obj, Name, Digits);
  if Length(Result) <> Digits then InvalidResponse;
  for C in Result do
    if not CharInSet(C, ['0'..'9', 'a'..'f']) then InvalidResponse;
end;

function ParseRelease(Obj: TJSONObject): TBootstrapRelease;
begin
  BootstrapValidateObject(Obj, CozyText_Bootstrap_id_version_hashVersion_sha512_crc64_xxh3_128_bla_1dc22447, 13);
  if BootstrapInteger(Obj, CozyText_Bootstrap_hashVersion_7df8163c) <> 3 then InvalidResponse;
  Result.ID := BootstrapString(Obj, CozyText_Bootstrap_id_cf715291, 128);
  Result.Version := BootstrapString(Obj, CozyText_Bootstrap_version_cbab46bd, 80);
  Result.SHA512 := BootstrapString(Obj, CozyText_Bootstrap_sha512_3b04acae, 128);
  BootstrapCheckSHA512(Result.SHA512);
  Result.CRC64 := BootstrapString(Obj, CozyText_Bootstrap_crc64_fdc5f295, 16);
  BootstrapCheckCRC64(Result.CRC64);
  Result.CodeSHA512 := BootstrapString(Obj, CozyText_Bootstrap_codeSha512_8fcc1bdc, 128);
  BootstrapCheckSHA512(Result.CodeSHA512);
  Result.XXH3_128 := ParseHex(Obj, CozyText_Bootstrap_xxh3_128_f91c85f3, 32);
  Result.Blake3 := ParseHex(Obj, CozyText_Bootstrap_blake3_c3eac883, 64);
  Result.CodeXXH3_128 := ParseHex(Obj, CozyText_Bootstrap_codeXxh3_128_2cced299, 32);
  Result.CodeBlake3 := ParseHex(Obj, CozyText_Bootstrap_codeBlake3_af56d718, 64);
  Result.CodeCRC64 := BootstrapString(Obj, CozyText_Bootstrap_codeCrc64_4cf32dd6, 16);
  BootstrapCheckCRC64(Result.CodeCRC64);
  if BootstrapString(Obj, CozyText_Bootstrap_codeAlgorithm_a3cb7357, 32) <> CozyText_Bootstrap_PE64_CODE_V1_b34b3e6f then InvalidResponse;
  Result.Size := BootstrapInteger(Obj, CozyText_Bootstrap_size_f8e6c2a3);
  if (Result.Size < 1) or (Result.Size > 64 * 1024 * 1024) then InvalidResponse;
end;

{ Restrict signing to the exact bootstrap domain and this live flow. A
  transport-authenticated response must never become an arbitrary-signing API. }
function CheckBootstrapCanonical(const Canonical, Domain, FlowID, Token,
  BinarySHA512, BinaryCRC64: string; Security: TDeviceSecurity;
  const ExpectedDeviceID: string = ''): TArray<string>;
var I: Integer; C: Char; Expiry, ByteCount: Int64; TokenHash, DeviceID: string;
begin
  DeviceID := ExpectedDeviceID;
  if DeviceID = '' then DeviceID := Security.DeviceID;
  if (Length(Canonical) > 4096) or (Pos(#13, Canonical) > 0) or
    (Pos(#0, Canonical) > 0) then InvalidResponse;
  Result := Canonical.Split([#10]);
  if Length(Result) <> 18 then InvalidResponse;
  for I := 0 to High(Result) do
    if (Result[I] = '') or (Length(Result[I]) > 256) then InvalidResponse;
  if (Result[0] <> Domain) or (Result[1] <> FlowID) or
    (Result[7] <> DeviceID) or (Result[8] <> Security.MachineID) or
    (Result[10] <> BinarySHA512) or (Result[11] <> BinaryCRC64) then InvalidResponse;
  BootstrapCheckSHA512(Result[3]); BootstrapCheckSHA512(Result[5]);
  BootstrapCheckSHA512(Result[10]); BootstrapCheckSHA512(Result[12]);
  BootstrapCheckCRC64(Result[4]); BootstrapCheckCRC64(Result[6]);
  BootstrapCheckCRC64(Result[11]); BootstrapCheckCRC64(Result[13]);
  if (Length(Result[16]) <> 48) or
    not TryStrToInt64(Result[14], ByteCount) or (ByteCount < 1) or
    (ByteCount > 64 * 1024 * 1024) or
    not TryStrToInt64(Result[17], Expiry) or (Expiry <= BootstrapUTCNowMS) then
    InvalidResponse;
  for C in Result[16] do
    if not CharInSet(C, ['0'..'9', 'a'..'f']) then InvalidResponse;
  TokenHash := IntegritySHA256Text(Token); { Opaque token identity, not measurement. }
  try
    if Result[15] <> TokenHash then InvalidResponse;
  finally
    WipeText(TokenHash);
  end;
end;

function RequiredObject(Obj: TJSONObject; const Name: string): TJSONObject;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name);
  if not (V is TJSONObject) then InvalidResponse;
  Result := TJSONObject(V);
end;

function BootstrapRequestID: string;
var ID: TGUID;
begin
  if WindowsApiCreateGUID(ID) <> 0 then raise EBootstrap.Create(CozyText_Bootstrap_Cannot_create_request_ID_3db629c1);
  Result := LowerCase(Copy(GUIDToString(ID), 2, 36));
end;

type
  TResolved_BootstrapGenRandom = function(Algorithm: NativeUInt; Buffer: PByte;
  Count, Flags: Cardinal): LongInt; stdcall;
var
  ApiSlot_BootstrapGenRandom: TEncodedApiPointer;

{ POINTER WRAPPERS 2 BEGIN }
function BootstrapGenRandom(Algorithm: NativeUInt; Buffer: PByte;
  Count, Flags: Cardinal): LongInt; stdcall;
var
  ApiTarget: TResolved_BootstrapGenRandom;
begin
  ApiTarget := TResolved_BootstrapGenRandom(DecodeApiPointer(ApiSlot_BootstrapGenRandom));
  Result := ApiTarget(Algorithm, Buffer, Count, Flags);
end;
{ POINTER WRAPPERS 2 END }

function BootstrapRandomFileName(const Extension: string): string;
const Hex: array[0..15] of Char = '0123456789abcdef';
var Bytes: array[0..15] of Byte; I: Integer;
begin
  if Extension <> CozyText_Bootstrap_exe_cbc8c008 then
    raise EBootstrap.Create(CozyText_Bootstrap_Invalid_file_extension_b52c4182);
  if BootstrapGenRandom(0, @Bytes[0], SizeOf(Bytes), $00000002) < 0 then
    raise EBootstrap.Create(CozyText_Bootstrap_Cannot_create_file_name_3802a004);
  SetLength(Result, 32);
  for I := 0 to High(Bytes) do
  begin
    Result[I * 2 + 1] := Hex[Bytes[I] shr 4];
    Result[I * 2 + 2] := Hex[Bytes[I] and $0F];
  end;
  Result := Result + Extension;
end;

function CurrentImagePath: string;
var N: DWORD;
begin
  SetLength(Result, 32768);
  N := GetModuleFileNameW(0, PWideChar(Result), Length(Result));
  if (N = 0) or (N >= DWORD(Length(Result))) then
    raise EBootstrap.Create(CozyText_Bootstrap_Cannot_determine_the_executable_path_f2edb51f);
  SetLength(Result, N);
end;

function HashHandleSHA512(Handle: THandle): string;
var Digest: TImageDigest;
begin
  Digest := IntegrityHashHandle(Handle);
  Result := Digest.SHA512;
end;

function HashFileSHA512(const FileName: string): string;
var Digest: TImageDigest;
begin
  Digest := IntegrityHashFile(FileName);
  Result := Digest.SHA512;
end;

function TBootstrapClient.OwnRuntime(Security: TDeviceSecurity;
  CodeIntegrity: TCodeIntegrity): ICozyRuntimeMeasurement;
begin
  if FRuntimeGraph = nil then raise ECozyRuntimeGraph.Create(CozyText_Bootstrap_RUNTIME_GRAPH_REQUIRED_57632b2e);
  { Registration is explicit and rejects replacement of a live binding.
    All captures occur inside this client's existing lifetime gate. }
  FRuntimeGraph.BindDependencies(Security, FOwnImage, CodeIntegrity);
  Result := FRuntimeGraph.Measurement(
    function: TCozyRuntimeBindings
    begin
      Result := CozyRuntimeBindings(Self, FGate, FTransport, Security,
        FOwnImage, CodeIntegrity);
    end);
end;

procedure TBootstrapClient.FlushNHWReports(TimeoutMS: Cardinal);
begin
  { Best effort on independent report connections. A network failure never
    prevents exact-session cleanup and does not claim report delivery. }
  if TimeoutMS > 7000 then TimeoutMS := 7000;
  try
    if FNHWAuthority <> nil then FNHWAuthority.FlushSecurityReports(TimeoutMS);
  except
    { Session revocation and local disposal must still run. }
  end;
end;

procedure TBootstrapClient.AttachNHW(Guard: TCozyNHWGuard);
begin
  if (Guard = nil) or (FNHWAuthority <> nil) then
    raise EInvalidOpException.Create(CozyText_Bootstrap_NHW_attachment_is_not_available_a5c2f779);
  FNHWAuthority := TCozyNHWAuthority.Create(
    function(out State: TCozyNHWKernelState): Boolean
    begin Result := Guard.TryReadKernelState(State); end,
    function(Channel: TResponsePathChannel; out State: TCozyNHWKernelState): Boolean
    begin Result := Guard.TryReadPathState(Channel, State); end,
    procedure begin Guard.ApplyAuthenticatedServerStop; end, Guard);
  FNHWAuthority.SetQuoteProvider(FNHWQuoter);
end;

constructor TBootstrapClient.Create(Profile: TConnectServerProfile);
begin
  inherited Create;
  FGate := TGameCallGate.Create;
  FLock := TObject.Create;
  FTransport := TConnectTransport.Create(Profile);
  FRuntimeGraph := TCozyOwnedRuntimeGraph.Create(rpBootstrapClient, Self, FGate, FTransport);
end;

destructor TBootstrapClient.Destroy;
begin
  if FGate <> nil then FGate.CloseAndWait;
  if FRuntimeGraph <> nil then
  begin
    try FRuntimeGraph.Close;
    except { Teardown still releases resources; no closed graph can be evidence. } end;
    FreeAndNil(FRuntimeGraph);
  end;
  FNHWAuthority := nil;
  FNHWQuoter := nil;
  FSession.ClearSecrets;
  FTransport.Free;
  FLock.Free;
  FGate.Free;
  inherited;
end;

function TBootstrapClient.Post(const Action: string;
  Body: TJSONObject): TJSONObject;
var Response: TJSONObject; OKValue, DataValue, ErrorValue: TJSONValue;
  Code: string; Attempt, MaxAttempts: Integer;
  FlowAction, RetryAction, Retryable: Boolean;
  Deadline, NowTick: UInt64;
begin
  Response := nil;
  Body.AddPair(CozyText_Bootstrap_action_b189a5db, Action);
  FlowAction := (Action = CozyText_Bootstrap_beginKeyless_afff067d) or (Action = CozyText_Bootstrap_chunk_77e594ae) or (Action = CozyText_Bootstrap_finish_67838943);
  RetryAction := FlowAction or (Action = CozyText_Bootstrap_claim_57455bb5) or (Action = CozyText_Bootstrap_abort_b0faf2f2) or (Action = CozyText_Bootstrap_close_42871d0a);
  if FlowAction then MaxAttempts := 3 else MaxAttempts := 2;
  Deadline := CozyTick + UInt64(MaxAttempts) * 10000;
  if not FlowAction then Deadline := CozyTick + 15000;
  for Attempt := 1 to MaxAttempts do
  begin
    { Keep the same request, key and opaque tickets for all retries. Nothing
      is serialized locally; a restarted process requires fresh issuance. }
    if FlowAction and (CozyTick - FFlowStarted >= 290000) then
      raise EBootstrap.Create(CozyText_Bootstrap_BOOTSTRAP_DOWNLOAD_DEADLINE_9595e474);
    NowTick := CozyTick;
    if NowTick >= Deadline then
      raise EConnectTransport.Create(CozyText_Bootstrap_CONNECT_TIMEOUT_6e6f8113, CozyText_Bootstrap_Bootstrap_retry_deadline_expired_d5ba4455);
    try
      Response := FTransport.PostJSON(CozyText_Bootstrap_bootstrap_48b6258a, Body, Cardinal(Deadline - NowTick));
      Break;
    except
      on E: EConnectTransport do
      begin
        Retryable := (E.Code = CozyText_Bootstrap_CONNECT_TIMEOUT_6e6f8113) or
          (E.Code = CozyText_Bootstrap_CONNECT_UNAVAILABLE_23cc8029) or (E.Code = CozyText_Bootstrap_CONNECT_SEND_FAILED_7b3791ee) or
          (E.Code = CozyText_Bootstrap_CONNECT_RECEIVE_FAILED_58538581) or (E.Code = CozyText_Bootstrap_NETWORK_UNAVAILABLE_7fe957f5);
        if not RetryAction or not Retryable or (Attempt = MaxAttempts) then raise;
      end;
    end;
  end;
  try
    if Response = nil then InvalidResponse;
    OKValue := Response.GetValue(CozyText_Bootstrap_ok_97e65c38);
    if not (OKValue is TJSONBool) then InvalidResponse;
    if OKValue.Value <> CozyText_Bootstrap_true_0756b971 then
    begin
      Code := CozyText_Bootstrap_BOOTSTRAP_REJECTED_fc4693d7;
      ErrorValue := Response.GetValue(CozyText_Bootstrap_error_6c4bf2ef);
      if (ErrorValue is TJSONString) and (Length(ErrorValue.Value) <= 80) then
        Code := ErrorValue.Value;
      raise EBootstrap.Create(Code);
    end;
    DataValue := Response.GetValue(CozyText_Bootstrap_data_616a32af);
    if not (DataValue is TJSONObject) then InvalidResponse;
    Result := TJSONObject(DataValue.Clone);
  finally
    Response.Free;
  end;
end;

function TBootstrapClient.BeginKeylessFlowCore(const RequestID, LauncherID,
  LauncherSHA512, LauncherCRC64: string;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
  DiagnosticCode: PInteger): TBootstrapFlow;
var Body, Data: TJSONObject; Code, CurrentCode: TCodeIntegrityMeasurement;
begin
  Result := Default(TBootstrapFlow);
  if DiagnosticCode <> nil then DiagnosticCode^ := 31023;
  Code := CodeIntegrity.MeasureNow(TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
    function: Boolean begin Result := FGate.IsClosing; end));
  FLauncherSHA512 := LauncherSHA512;
  FLauncherCRC64 := LauncherCRC64;
  FLauncherID := LauncherID;
  FLauncherCodeSHA512 := Code.SHA512;
  FLauncherCodeCRC64 := Code.CRC64;
  Body := nil;
  Data := nil;
  try
    try
    Body := WaitForKeylessApproval(FTransport, Security, RequestID, LauncherID,
      LauncherSHA512, LauncherCRC64, Code.SHA512, Code.CRC64,
      function: Boolean begin Result := FGate.IsClosing; end, DiagnosticCode);
    { Approval never makes an old local measurement current. Recheck the code
      before consuming the server grant; subsequent reports include the file. }
    if DiagnosticCode <> nil then DiagnosticCode^ := 31023;
    CurrentCode := CodeIntegrity.MeasureNow(TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
      function: Boolean begin Result := FGate.IsClosing; end));
    if (CurrentCode.SHA512 <> Code.SHA512) or (CurrentCode.CRC64 <> Code.CRC64) then
      raise EBootstrap.Create(CozyText_Bootstrap_COZY_KEYLESS_IMAGE_CHANGED_75573e30);
    FFlowStarted := CozyTick;
    if DiagnosticCode <> nil then DiagnosticCode^ := 31029;
    Data := Post(CozyText_Bootstrap_beginKeyless_afff067d, Body);
    Result.FlowID := BootstrapString(Data, CozyText_Bootstrap_flowId_576a7cfc, 128);
    Result.DownloadTicket := BootstrapString(Data, CozyText_Bootstrap_downloadTicket_b0cf7027, 512);
    Result.FinishCanonical := BootstrapString(Data, CozyText_Bootstrap_finishCanonical_441b9c22, 4096);
    Result.ExpiresAt := BootstrapInteger(Data, CozyText_Bootstrap_expiresAt_6d380f30);
    if BootstrapInteger(Data, CozyText_Bootstrap_chunkSize_75ea683c) <> 262144 then InvalidResponse;
    Result.ChunkSize := 262144;
    Result.Release := ParseRelease(RequiredObject(Data, CozyText_Bootstrap_release_e46f9565));
    if (Result.ChunkSize <> 262144) or
      (Result.ExpiresAt <= BootstrapUTCNowMS) then InvalidResponse;
    EnsureDeviceIdentity(FTransport, Security, 'A', Result.FlowID, Result.DownloadTicket, FNHWQuoter);
    if FNHWAuthority <> nil then
    begin
      FNHWAuthority.SetQuoteProvider(FNHWQuoter);
      { Publish reports while A still owns the flow, including during download. }
      FNHWAuthority.ConfigureResponses(FTransport, Security, 'A',
        Result.FlowID, Result.DownloadTicket);
    end;
    except
      { The server may already have consumed the one-use A issue. If this
        invocation has its returned flow capability, retire exactly that flow
        before losing the local result. Never recursively enter FLock/FGate. }
      if (Result.FlowID <> '') and (Result.DownloadTicket <> '') then
        try
          AbortFlowCore(Result);
        except
          { Preserve the original parse/enrollment failure. Server expiry is
            the fallback when the bounded authenticated abort cannot finish. }
        end;
      Result.ClearSecrets;
      Result := Default(TBootstrapFlow);
      FFlowStarted := 0;
      raise;
    end;
  finally
    Body.Free;
    Data.Free;
  end;
end;

function TBootstrapClient.ChunkCore(const Flow: TBootstrapFlow;
  Offset: Int64): TBytes;
var Body, Data: TJSONObject; Encoded: string; Encoding: TBase64Encoding;
  Expected: Int64;
  Ticket: string;
begin
  Ticket := Flow.DownloadTicket;
  try
  if (Offset < 0) or (Offset >= Flow.Release.Size) then InvalidResponse;
  Body := TJSONObject.Create;
  Data := nil;
  Encoding := TBase64Encoding.Create(0);
  try
    Body.AddPair(CozyText_Bootstrap_flowId_576a7cfc, Flow.FlowID);
    Body.AddPair(CozyText_Bootstrap_downloadTicket_b0cf7027, Ticket);
    Body.AddPair(CozyText_Bootstrap_offset_a9e5f864, TJSONNumber.Create(Offset));
    Data := Post(CozyText_Bootstrap_chunk_77e594ae, Body);
    if BootstrapInteger(Data, CozyText_Bootstrap_offset_a9e5f864) <> Offset then InvalidResponse;
    Expected := Flow.Release.Size - Offset;
    if Expected > Flow.ChunkSize then Expected := Flow.ChunkSize;
    if BootstrapInteger(Data, CozyText_Bootstrap_size_f8e6c2a3) <> Expected then InvalidResponse;
    Encoded := BootstrapString(Data, CozyText_Bootstrap_data_616a32af, ((Flow.ChunkSize + 2) div 3) * 4);
    Result := Encoding.DecodeStringToBytes(Encoded);
    if (Length(Result) <> Expected) or
      (Encoding.EncodeBytesToString(Result) <> Encoded) then InvalidResponse;
  finally
    Encoding.Free;
    Body.Free;
    Data.Free;
  end;
  finally
    WipeText(Ticket);
  end;
end;

function TBootstrapClient.FinishCore(const Flow: TBootstrapFlow;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapGrant;
var Body, Data: TJSONObject; Code: TCodeIntegrityMeasurement;
  Parts: TArray<string>; I: Integer;
  Ticket, Canonical: string;
begin
  Ticket := ''; Canonical := '';
  try
    Ticket := Flow.DownloadTicket;
    Canonical := Flow.FinishCanonical;
  Result := Default(TBootstrapGrant);
  RequireServerObservation(FTransport, Security, CodeIntegrity, 'A',
    Flow.FlowID, Ticket, CozyText_Bootstrap_finish_67838943,
    AuthorityBinding(Flow.FlowID, Flow.Release.SHA512), FLauncherSHA512, FLauncherCRC64, nil, FOwnImage, OwnRuntime(Security, CodeIntegrity), FNHWAuthority);
  Code := CodeIntegrity.MeasureNow(TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
    function: Boolean begin Result := FGate.IsClosing; end));
  Parts := CheckBootstrapCanonical(Canonical, CozyText_Bootstrap_GAME_A85_FINISH_V2_16af553a,
    Flow.FlowID, Ticket, Flow.Release.SHA512, Flow.Release.CRC64, Security);
  try
    if (Parts[2] <> FLauncherID) or (Parts[3] <> FLauncherSHA512) or
      (Parts[4] <> FLauncherCRC64) or (Parts[5] <> FLauncherCodeSHA512) or
      (Parts[6] <> FLauncherCodeCRC64) or (Parts[9] <> Flow.Release.ID) or
      (Parts[12] <> Flow.Release.CodeSHA512) or (Parts[13] <> Flow.Release.CodeCRC64) or
      (Parts[14] <> IntToStr(Flow.Release.Size)) or
      (Parts[17] <> IntToStr(Flow.ExpiresAt)) then InvalidResponse;
  finally
    for I := 0 to High(Parts) do WipeText(Parts[I]);
  end;
  Body := TJSONObject.Create;
  Data := nil;
  try
    Body.AddPair(CozyText_Bootstrap_flowId_576a7cfc, Flow.FlowID);
    Body.AddPair(CozyText_Bootstrap_downloadTicket_b0cf7027, Ticket);
    Body.AddPair(CozyText_Bootstrap_sha512_3b04acae, Flow.Release.SHA512);
    Body.AddPair(CozyText_Bootstrap_crc64_fdc5f295, Flow.Release.CRC64);
    Body.AddPair(CozyText_Bootstrap_aCodeSha512_defb258f, Code.SHA512);
    Body.AddPair(CozyText_Bootstrap_aCodeCrc64_f37cec64, Code.CRC64);
    Body.AddPair(CozyText_Bootstrap_signature_01f9047f, Security.Sign(Canonical));
    Data := Post(CozyText_Bootstrap_finish_67838943, Body);
    try
    Result.HandoffToken := BootstrapString(Data, CozyText_Bootstrap_handoffToken_c531cb91, 512);
    Result.ClaimCanonical := BootstrapString(Data, CozyText_Bootstrap_claimCanonical_829f4f25, 4096);
    Result.ExpiresAt := BootstrapInteger(Data, CozyText_Bootstrap_expiresAt_6d380f30);
    if Result.ExpiresAt <= BootstrapUTCNowMS then InvalidResponse;
    except
      Result.ClearSecrets;
      raise;
    end;
  finally
    Body.Free;
    Data.Free;
  end;
  finally
    WipeText(Ticket);
    WipeText(Canonical);
  end;
end;

function TBootstrapClient.ClaimCore(const FlowID, HandoffToken, ClaimCanonical,
  BinarySHA512, BinaryCRC64, BinaryXXH3_128, BinaryBlake3: string; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity): TBootstrapSession;
var Body, Data: TJSONObject; Code: TCodeIntegrityMeasurement;
  Parts: TArray<string>; I: Integer;
begin
  Result := Default(TBootstrapSession);
  Code := CodeIntegrity.MeasureNow(TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
    function: Boolean begin Result := FGate.IsClosing; end));
  BootstrapCheckSHA512(BinarySHA512);
  BootstrapCheckCRC64(BinaryCRC64);
  Parts := CheckBootstrapCanonical(ClaimCanonical, CozyText_Bootstrap_GAME_B85_CLAIM_V2_3ed450e3,
    FlowID, HandoffToken, BinarySHA512, BinaryCRC64, Security, Security.ParentDeviceID);
  try
    if (Parts[12] <> Code.SHA512) or (Parts[13] <> Code.CRC64) then InvalidResponse;
  finally
    for I := 0 to High(Parts) do WipeText(Parts[I]);
  end;
  Body := TJSONObject.Create;
  Data := nil;
  try
    Body.AddPair(CozyText_Bootstrap_flowId_576a7cfc, FlowID);
    Body.AddPair(CozyText_Bootstrap_handoffToken_c531cb91, HandoffToken);
    Body.AddPair(CozyText_Bootstrap_handoffVersion_5cf24f0c, TJSONNumber.Create(3));
    Body.AddPair(CozyText_Bootstrap_childPublicKey_401d992c, Security.PublicKeyBlob);
    Body.AddPair(CozyText_Bootstrap_childKeyId_8a44e5cc, Security.DeviceID);
    Body.AddPair(CozyText_Bootstrap_childNonce_1ee8a6d0, Security.HandoffNonce);
    Body.AddPair(CozyText_Bootstrap_delegationSignature_c2a3b991, Security.DelegationSignature);
    Body.AddPair(CozyText_Bootstrap_signature_01f9047f, Security.SignHandoffClaim('B', ClaimCanonical));
    Body.AddPair(CozyText_Bootstrap_binarySha512_3aca3698, BinarySHA512);
    Body.AddPair(CozyText_Bootstrap_crc64_fdc5f295, BinaryCRC64);
    Body.AddPair(CozyText_Bootstrap_bCodeSha512_9cb3b3d3, Code.SHA512);
    Body.AddPair(CozyText_Bootstrap_bCodeCrc64_d7fc2bab, Code.CRC64);
    Data := Post(CozyText_Bootstrap_claim_57455bb5, Body);
    try
    Result.SessionID := BootstrapString(Data, CozyText_Bootstrap_sessionId_8bdf6750, 128);
    Result.SessionToken := BootstrapString(Data, CozyText_Bootstrap_sessionToken_02d0aee7, 512);
    Result.ExpiresAt := BootstrapInteger(Data, CozyText_Bootstrap_expiresAt_6d380f30);
    Result.Release := ParseRelease(RequiredObject(Data, CozyText_Bootstrap_release_e46f9565));
    if (Result.ExpiresAt <= BootstrapUTCNowMS) or
      (Result.Release.SHA512 <> BinarySHA512) or
      (Result.Release.CRC64 <> BinaryCRC64) or
      (Result.Release.XXH3_128 <> BinaryXXH3_128) or
      (Result.Release.Blake3 <> BinaryBlake3) or
      (Result.Release.CodeSHA512 <> Code.SHA512) or
      (Result.Release.CodeCRC64 <> Code.CRC64) or
      (Result.Release.CodeXXH3_128 <> Code.XXH3_128) or
      (Result.Release.CodeBlake3 <> Code.Blake3) then InvalidResponse;
    Security.CompleteHandoff;
    FSession := Result;
    EnsureDeviceIdentity(FTransport, Security, 'B', FSession.SessionID, FSession.SessionToken, FNHWQuoter);
    except
      { Enrollment or response validation may fail after the server claim.
        If a valid capability reached FSession, close it before revoking local
        aliases. If no capability arrived, the server lease is the fallback. }
      if FSession.SessionID <> '' then try CloseCore; except end;
      Result.ClearSecrets;
      raise;
    end;
  finally
    Body.Free;
    Data.Free;
  end;
end;

function TBootstrapClient.StatusCore: TJSONObject;
var Body: TJSONObject;
  Token: string;
begin
  Token := FSession.SessionToken;
  try
  if FSession.SessionID = '' then raise EBootstrap.Create(CozyText_Bootstrap_No_bootstrap_session_2b15e3a2);
  Body := TJSONObject.Create;
  try
    Body.AddPair(CozyText_Bootstrap_sessionId_8bdf6750, FSession.SessionID);
    Body.AddPair(CozyText_Bootstrap_sessionToken_02d0aee7, Token);
    Result := Post(CozyText_Bootstrap_status_a04c5d21, Body);
  finally
    Body.Free;
  end;
  finally
    WipeText(Token);
  end;
end;

procedure TBootstrapClient.AbortFlowCore(const Flow: TBootstrapFlow);
var Body, Data: TJSONObject;
  Ticket: string;
begin
  Ticket := Flow.DownloadTicket;
  try
  if (Flow.FlowID = '') or (Ticket = '') then Exit;
  Body := TJSONObject.Create;
  Data := nil;
  try
    Body.AddPair(CozyText_Bootstrap_flowId_576a7cfc, Flow.FlowID);
    Body.AddPair(CozyText_Bootstrap_downloadTicket_b0cf7027, Ticket);
    Data := Post(CozyText_Bootstrap_abort_b0faf2f2, Body);
  finally
    Data.Free;
    Body.Free;
  end;
  finally
    WipeText(Ticket);
  end;
end;

procedure TBootstrapClient.ReportIntegrityCore(const Flow: TBootstrapFlow;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity; const Image: TImageDigest;
  IncludeModules: Boolean; FailureStatus: TMeasurementStatus; OwnImage: TImageIntegrity;
  const Cancelled: TAuthorityCancelled);
var Code: TCodeIntegrityMeasurement; Snapshot, Payload, Own, CrcLayers, Bundle: TJSONObject;
  CurrentImage: TImageDigest;
  Modules, Value: TJSONValue; Batch: TJSONArray;
  I, Total, BatchIndex, BatchCount, GenerationRetries: Integer;
  GenerationStarted, GenerationNow: UInt64;
  SnapshotID, Ticket: string; Measured: Boolean; Failure: TMeasurementStatus;
  procedure RequireReportActive;
  begin
    if FGate.IsClosing or (Assigned(Cancelled) and Cancelled()) then
      raise EBootstrap.Create(CozyText_Bootstrap_COZY_SERVER_OPERATION_CANCELLED_879dd2d2);
  end;
  procedure AddAuth(Body: TJSONObject);
  begin
    Body.AddPair(CozyText_Bootstrap_stage_45365fff, 'A');
    Body.AddPair(CozyText_Bootstrap_sessionId_8bdf6750, Flow.FlowID);
    Body.AddPair(CozyText_Bootstrap_sessionToken_02d0aee7, Ticket);
    Body.AddPair(CozyText_Bootstrap_machineId_a56dd0fc, Security.MachineID);
  end;
  function ReportPost(Body: TJSONObject; ExactSubmitRetry: Boolean): TJSONObject;
  var Response: TJSONObject; OKValue, DataValue: TJSONValue;
    Attempt, Attempts: Integer; Deadline, NowTick: UInt64;
  begin
    Response := nil;
    Attempts := 1;
    if ExactSubmitRetry then Attempts := 2;
    Deadline := CozyTick + 15000;
    for Attempt := 1 to Attempts do
    begin
      RequireReportActive;
      NowTick := CozyTick;
      if NowTick >= Deadline then
        raise EConnectTransport.Create(CozyText_Bootstrap_CONNECT_TIMEOUT_6e6f8113, CozyText_Bootstrap_Report_retry_deadline_expired_8b2e5043);
      try
        Response := FTransport.PostJSON(CozyText_Bootstrap_report_537819d5, Body, Cardinal(Deadline - NowTick));
        Break;
      except
        on E: EConnectTransport do
          if (Attempt = Attempts) or
            ((E.Code <> CozyText_Bootstrap_CONNECT_TIMEOUT_6e6f8113) and (E.Code <> CozyText_Bootstrap_CONNECT_UNAVAILABLE_23cc8029) and
             (E.Code <> CozyText_Bootstrap_CONNECT_SEND_FAILED_7b3791ee) and (E.Code <> CozyText_Bootstrap_CONNECT_RECEIVE_FAILED_58538581) and
             (E.Code <> CozyText_Bootstrap_NETWORK_UNAVAILABLE_7fe957f5)) then raise;
      end;
    end;
    try
      RequireReportActive;
      if Response = nil then InvalidResponse;
      OKValue := Response.GetValue(CozyText_Bootstrap_ok_97e65c38);
      if not (OKValue is TJSONBool) or (OKValue.Value <> CozyText_Bootstrap_true_0756b971) then
        raise EBootstrap.Create(CozyText_Bootstrap_INTEGRITY_REPORT_REJECTED_a1a7e059);
      DataValue := Response.GetValue(CozyText_Bootstrap_data_616a32af);
      if not (DataValue is TJSONObject) then InvalidResponse;
      Result := TJSONObject(DataValue.Clone);
    finally
      Response.Free;
    end;
  end;
  procedure Send(Payload: TJSONObject);
  var ChallengeBody, Challenge, SubmitBody, Reply: TJSONObject;
    Text, Canonical, ReportID, Nonce: string; ExpiresAt: Int64;
  begin
    ChallengeBody := TJSONObject.Create;
    Challenge := nil;
    SubmitBody := nil;
    Reply := nil;
    try
      Payload.AddPair(CozyText_Bootstrap_hashVersion_7df8163c, TJSONNumber.Create(3));
      Text := Payload.ToJSON;
      if TEncoding.UTF8.GetByteCount(Text) > 24576 then InvalidResponse;
      AddAuth(ChallengeBody);
      ChallengeBody.AddPair(CozyText_Bootstrap_action_b189a5db, CozyText_Bootstrap_challenge_8669f0c1);
      Challenge := ReportPost(ChallengeBody, False);
      ReportID := BootstrapString(Challenge, CozyText_Bootstrap_reportId_b914f6b2, 128);
      Nonce := BootstrapString(Challenge, CozyText_Bootstrap_nonce_160beea8, 256);
      ExpiresAt := BootstrapInteger(Challenge, CozyText_Bootstrap_expiresAt_6d380f30);
      if (Length(ReportID) < 12) or (Length(Nonce) < 20) or
        (Pos(#10, ReportID) <> 0) or (Pos(#10, Nonce) <> 0) or
        (ExpiresAt <= 0) then InvalidResponse;
      Canonical := CozyText_Bootstrap_GAME_INTEGRITY_REPORT_V2_fd2a78f2 + #10 + Flow.FlowID + #10 +
        ReportID + #10 + Nonce + #10 + IntToStr(ExpiresAt) + #10 + IntegritySHA512Text(Text);
      SubmitBody := TJSONObject.Create;
      AddAuth(SubmitBody);
      SubmitBody.AddPair(CozyText_Bootstrap_action_b189a5db, CozyText_Bootstrap_submit_d87b791c);
      SubmitBody.AddPair(CozyText_Bootstrap_reportId_b914f6b2, ReportID);
      SubmitBody.AddPair(CozyText_Bootstrap_payload_3e550665, Text);
      RequireReportActive;
      SubmitBody.AddPair(CozyText_Bootstrap_signature_01f9047f, Security.Sign(Canonical));
      Reply := ReportPost(SubmitBody, True);
      Value := Reply.GetValue(CozyText_Bootstrap_accepted_dcedae8f);
      if not (Value is TJSONBool) or (Value.Value <> CozyText_Bootstrap_true_0756b971) then InvalidResponse;
      Value := Reply.GetValue(CozyText_Bootstrap_terminate_18cf035b);
      if not (Value is TJSONBool) then InvalidResponse;
      if (Value.Value = CozyText_Bootstrap_true_0756b971) or (BootstrapString(Reply, CozyText_Bootstrap_status_a04c5d21, 32) = CozyText_Bootstrap_REJECTED_f0cf1044) then
        raise EBootstrap.Create(CozyText_Bootstrap_INTEGRITY_REJECTED_a63e8935);
    finally
      WipeText(Text);
      WipeText(Canonical);
      Reply.Free;
      SubmitBody.Free;
      Challenge.Free;
      ChallengeBody.Free;
    end;
  end;
  procedure AddMetadata(const Name: string);
  begin
    Value := Snapshot.GetValue(Name);
    if Value <> nil then Payload.AddPair(Name, TJSONValue(Value.Clone));
  end;
begin
  RequireReportActive;
  Ticket := Flow.DownloadTicket;
  try
  Measured := False;
  CrcLayers := nil; Bundle := nil;
  if OwnImage <> nil then FOwnImage := OwnImage;
  Failure := FailureStatus;
  CurrentImage := Default(TImageDigest); Code := Default(TCodeIntegrityMeasurement);
  if Failure = msMeasured then
  try
    Failure := msNotMeasured;
    Bundle := CollectOwnMeasurement(FOwnImage, CodeIntegrity,
      TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
        function: Boolean
        begin Result := FGate.IsClosing or (Assigned(Cancelled) and Cancelled()); end), CurrentImage,
      Code, CrcLayers, Failure, OwnRuntime(Security, CodeIntegrity));
    Measured := OwnMeasurementComplete(Bundle, CurrentImage, Code, CrcLayers, Failure);
    if (Failure = msMeasured) and not Measured then
    begin Failure := msCoverageInsufficient; FreeAndNil(Bundle); end;
  except
    on E: Exception do
    begin
      Failure := MeasurementFailureStatus(E);
      FreeAndNil(CrcLayers);
    end;
  end;
  Payload := nil;
  try
    RequireReportActive;
    Payload := TJSONObject.Create;
    Payload.AddPair(CozyText_Bootstrap_version_cbab46bd, TJSONNumber.Create(1));
    Payload.AddPair(CozyText_Bootstrap_check_8b3c2457, CozyText_Bootstrap_OWN_IMAGE_5d5cf1ef);
    if Measured then Payload.AddPair(CozyText_Bootstrap_reason_953b57ef, CozyText_Bootstrap_PERIODIC_c0407e9e)
    else Payload.AddPair(CozyText_Bootstrap_reason_953b57ef, CozyText_Bootstrap_MEASUREMENT_FAILED_227f1d7c);
    Own := TJSONObject.Create;
    if Measured then
    begin
      Own.AddPair(CozyText_Bootstrap_status_a04c5d21, CozyText_Bootstrap_MEASURED_b6711e67);
      Own.AddPair(CozyText_Bootstrap_fileSha512_942d011c, CurrentImage.SHA512);
      Own.AddPair(CozyText_Bootstrap_fileCrc64_5525b4f0, CurrentImage.CRC64);
      Own.AddPair(CozyText_Bootstrap_codeSha512_8fcc1bdc, Code.SHA512);
      Own.AddPair(CozyText_Bootstrap_codeCrc64_4cf32dd6, Code.CRC64);
      Own.AddPair(CozyText_Bootstrap_fileXxh3_128_aa8d7f62, CurrentImage.XXH3_128);
      Own.AddPair(CozyText_Bootstrap_fileBlake3_e2be4b6d, CurrentImage.Blake3);
      Own.AddPair(CozyText_Bootstrap_codeXxh3_128_2cced299, Code.XXH3_128);
      Own.AddPair(CozyText_Bootstrap_codeBlake3_af56d718, Code.Blake3);
    end
    else Own.AddPair(CozyText_Bootstrap_status_a04c5d21, MeasurementStatusName(Failure));
    Payload.AddPair(CozyText_Bootstrap_own_9675d3ea, Own);
    if CrcLayers <> nil then
    begin Payload.AddPair(CozyText_Bootstrap_crcLayers_5f0b8ed6, CrcLayers); CrcLayers := nil; end;
    if Bundle <> nil then begin Payload.AddPair(CozyText_Bootstrap_ownMeasurement_8ac2a3b6, Bundle); Bundle := nil; end;
    Send(Payload);
  finally
    Bundle.Free; CrcLayers.Free;
    Payload.Free;
  end;
  if not Measured then raise EBootstrap.Create(CozyText_Bootstrap_INTEGRITY_MEASUREMENT_FAILED_a31c2ae0);
  if not IncludeModules then Exit;
  Snapshot := nil;
  GenerationRetries := 0;
  GenerationStarted := CozyTick;
  try
    repeat
      RequireReportActive;
      Snapshot := CollectModuleInventoryJSON(nil, FOwnImage, CodeIntegrity);
      GenerationNow := CozyTick;
      { Re-measure the complete inventory after a bounded loader transition,
        including transient MODULE_PATH failures. Do not transmit, grant or
        rely on a hash from a discarded scan. Exhausted/incomplete snapshots
        still receive the original fail-closed server decision. }
      if not ModuleInventoryGenerationRetryable(Snapshot) or
        (GenerationRetries >= 2) or (GenerationNow < GenerationStarted) or
        (GenerationNow - GenerationStarted >= 90000) then Break;
      Inc(GenerationRetries);
      FreeAndNil(Snapshot);
    until False;
    Modules := Snapshot.GetValue(CozyText_Bootstrap_modules_27c1b64e);
    if not (Modules is TJSONArray) then InvalidResponse;
    Total := TJSONArray(Modules).Count;
    if Total > 1024 then Total := 1024;
    I := 0;
    BatchIndex := 0;
    BatchCount := (Total + 5) div 6;
    if BatchCount = 0 then BatchCount := 1;
    SnapshotID := BootstrapRequestID;
    repeat
      Payload := TJSONObject.Create;
      try
        Payload.AddPair(CozyText_Bootstrap_version_cbab46bd, TJSONNumber.Create(1));
        Payload.AddPair(CozyText_Bootstrap_check_8b3c2457, CozyText_Bootstrap_MODULE_INVENTORY_935150b7);
        Payload.AddPair(CozyText_Bootstrap_reason_953b57ef, CozyText_Bootstrap_PERIODIC_c0407e9e);
        Payload.AddPair(CozyText_Bootstrap_snapshotId_34122597, SnapshotID);
        Payload.AddPair(CozyText_Bootstrap_batchIndex_14f3ca31, TJSONNumber.Create(BatchIndex));
        Payload.AddPair(CozyText_Bootstrap_batchCount_5f840bd9, TJSONNumber.Create(BatchCount));
        AddMetadata(CozyText_Bootstrap_complete_745e2c55);
        AddMetadata(CozyText_Bootstrap_truncated_c844fa38);
        AddMetadata(CozyText_Bootstrap_totalModules_13ff780c);
        AddMetadata(CozyText_Bootstrap_measuredModules_ecf80f34);
        AddMetadata(CozyText_Bootstrap_scope_c0f38357);
        AddMetadata(CozyText_Bootstrap_trust_d4ca9bee);
        AddMetadata(CozyText_Bootstrap_measurementContract_00b9286d);
        AddMetadata(CozyText_Bootstrap_measurementPlanVersion_080c4313);
        AddMetadata(CozyText_Bootstrap_measurementStartedTick_02c15a43);
        AddMetadata(CozyText_Bootstrap_measurementFinishedTick_0e4a2a08);
        AddMetadata(CozyText_Bootstrap_moduleGenerationStable_ca8662f1);
        AddMetadata(CozyText_Bootstrap_moduleGenerationStatus_d1a46039);
        AddMetadata(CozyText_Bootstrap_threadInventory_628eb251);
        AddMetadata(CozyText_Bootstrap_deviceSignals_626b34e0);
        AddMetadata(CozyText_Bootstrap_coverage_06f0fa37);
        Batch := TJSONArray.Create;
        Payload.AddPair(CozyText_Bootstrap_modules_27c1b64e, Batch);
        while (I < Total) and (Batch.Count < 6) do
        begin
          Batch.AddElement(TJSONValue(TJSONArray(Modules).Items[I].Clone));
          Inc(I);
        end;
        Send(Payload);
      finally
        Payload.Free;
      end;
      Inc(BatchIndex);
    until BatchIndex >= BatchCount;
  finally
    Snapshot.Free;
  end;
  finally WipeText(Ticket); end;
end;

procedure TBootstrapClient.CloseCore;
var Body, Data: TJSONObject;
  Token: string;
begin
  Token := FSession.SessionToken;
  try
  if FSession.SessionID = '' then begin FClosed := True; Exit; end;
  Body := TJSONObject.Create;
  Data := nil;
  try
    Body.AddPair(CozyText_Bootstrap_sessionId_8bdf6750, FSession.SessionID);
    Body.AddPair(CozyText_Bootstrap_sessionToken_02d0aee7, Token);
    Data := Post(CozyText_Bootstrap_close_42871d0a, Body);
  finally
    Data.Free;
    Body.Free;
    FClosed := True;
    FSession.SessionID := '';
    FSession.ClearSecrets;
    FSession.ExpiresAt := 0;
  end;
  finally
    WipeText(Token);
  end;
end;

function TBootstrapClient.GetSessionCore: TBootstrapSession;
begin Result := FSession; end;

function TBootstrapClient.BeginKeylessFlow(const RequestID, LauncherID,
      LauncherSHA512, LauncherCRC64: string; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity; DiagnosticCode: PInteger): TBootstrapFlow;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      Result := BeginKeylessFlowCore(RequestID, LauncherID, LauncherSHA512, LauncherCRC64,
        Security, CodeIntegrity, DiagnosticCode);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TBootstrapClient.Chunk(const Flow: TBootstrapFlow; Offset: Int64): TBytes;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      Result := ChunkCore(Flow, Offset);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TBootstrapClient.Finish(const Flow: TBootstrapFlow;
      Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapGrant;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      Result := FinishCore(Flow, Security, CodeIntegrity);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TBootstrapClient.Claim(const FlowID, HandoffToken, ClaimCanonical,
      BinarySHA512, BinaryCRC64, BinaryXXH3_128, BinaryBlake3: string; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity): TBootstrapSession;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      Result := ClaimCore(FlowID, HandoffToken, ClaimCanonical, BinarySHA512, BinaryCRC64, BinaryXXH3_128, BinaryBlake3, Security, CodeIntegrity);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TBootstrapClient.InvokeServerPolicy(const Flow: TBootstrapFlow;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity; FunctionID: Word;
  const Args: array of Integer; const Cancelled: TAuthorityCancelled): Integer;
var Image: TImageDigest; Ticket: string; FlowExpiresAt: Int64;
  LocalArgs: TArray<Integer>; OperationCancelled: TAuthorityCancelled;
  Value: Integer;
  procedure RequirePolicyContext;
  begin
    if FClosed or FGate.IsClosing then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
    if Assigned(Cancelled) and Cancelled() then
      raise EBootstrap.Create(CozyText_Bootstrap_COZY_SERVER_OPERATION_CANCELLED_879dd2d2);
    if (FlowExpiresAt <= BootstrapUTCNowMS) or Flow.FDownloadTicket.IsEmpty then
      raise EBootstrap.Create(CozyText_Bootstrap_COZY_SERVER_OPERATION_FLOW_EXPIRED_c075de6a);
  end;
begin
  LocalArgs := SnapshotServerOperationArgs(FunctionID, Args);
  try
    FlowExpiresAt := Flow.ExpiresAt;
    FGate.Enter;
    try
      TMonitor.Enter(FLock);
      try
        RequirePolicyContext;
        if FOwnImage = nil then raise EBootstrap.Create(CozyText_Bootstrap_COZY_SERVER_OPERATION_IMAGE_REQUIRED_ea1725ed);
        OperationCancelled :=
          function: Boolean
          begin
            Result := FGate.IsClosing or (BootstrapUTCNowMS >= FlowExpiresAt) or
              (Assigned(Cancelled) and Cancelled());
          end;
        Image := Default(TImageDigest);
        Image.SHA512 := FLauncherSHA512; Image.CRC64 := FLauncherCRC64;
        ReportIntegrityCore(Flow, Security, CodeIntegrity, Image, False,
          msMeasured, FOwnImage, OperationCancelled);
        RequirePolicyContext;
        Ticket := Flow.DownloadTicket;
        try
          Value := InvokeCozyServerOperation(FTransport, Security, CodeIntegrity, 'A',
            Flow.FlowID, Ticket, FLauncherSHA512, FLauncherCRC64, FunctionID, LocalArgs,
            OperationCancelled, FOwnImage, OwnRuntime(Security, CodeIntegrity));
          RequirePolicyContext;
          Result := Value;
        finally WipeText(Ticket); end;
      finally TMonitor.Exit(FLock); end;
    finally FGate.Leave; end;
  finally
    OperationCancelled := nil;
    ClearServerOperationArgs(LocalArgs);
  end;
end;

function TBootstrapClient.Status: TJSONObject;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      Result := StatusCore;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TBootstrapClient.Close;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then Exit;
      CloseCore;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TBootstrapClient.AbortFlow(const Flow: TBootstrapFlow);
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      AbortFlowCore(Flow);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TBootstrapClient.ReportIntegrity(const Flow: TBootstrapFlow; Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity; const Image: TImageDigest; IncludeModules: Boolean;
      FailureStatus: TMeasurementStatus; OwnImage: TImageIntegrity);
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      ReportIntegrityCore(Flow, Security, CodeIntegrity, Image, IncludeModules, FailureStatus, OwnImage);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TBootstrapClient.GetSession: TBootstrapSession;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Bootstrap_CLIENT_CLOSED_d2105c32);
      Result := GetSessionCore;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

initialization
  { API binding only; original startup actions follow unchanged. }

  BindApiPointer(ApiSlot_GetSystemTimeAsFileTime, RequireProcAddressHash64(CozyText_Bootstrap_kernel32_dll_d68812a5, HASH_GetSystemTimeAsFileTime));
  BindApiPointer(ApiSlot_GetModuleFileNameW, RequireProcAddressHash64(CozyText_Bootstrap_kernel32_dll_d68812a5, HASH_GetModuleFileNameW));
  BindApiPointer(ApiSlot_send, RequireProcAddressHash64(CozyText_Bootstrap_ws2_32_dll_4a996ac7, HASH_send));
  BindApiPointer(ApiSlot_BootstrapGenRandom, RequireProcAddressHash64(CozyText_Bootstrap_bcrypt_dll_f7bdaadf, HASH_BCryptGenRandom));

end.
