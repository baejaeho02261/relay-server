unit Cozy.Transport;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Network,

{ Cozy central text imports. }

  System.SysUtils, System.JSON, System.SyncObjs, System.Diagnostics,
  Cozy.Server.Profile, Cozy.Lifetime, Cozy.Api.Contracts;

type
  EConnectTransport = class(Exception)
  private
    FCode: string;
  public
    constructor Create(const Code, MessageText: string);
    property Code: string read FCode;
  end;

  {$IFDEF GAME_TRANSPORT_TESTS}
  { Native probe only: replace the ciphertext socket exchange, never crypto or
    profile authentication. The stage observer may retain only revocable views. }
  TTransportTestExchange = reference to function(const Frame: string;
    out PeerPin: string): string;
  TTransportTestStage = reference to procedure(const Stage: string;
    const View: TApiBuffer);
  {$ENDIF}

  { TLS 1.2 with a pinned certificate and independently pinned CNG envelope. Only an authenticated encrypted
    response may reach the API layer. No plaintext, HTTP or trust fallback. }
  TConnectTransport = class
  private
    FGate: TGameCallGate;
    FStateLock: TCriticalSection;
    FCancelled: Boolean;
    FGeneration: UInt64;
    {$IFDEF GAME_TRANSPORT_TESTS}
    FTestExchange: TTransportTestExchange;
    FTestStage: TTransportTestStage;
    {$ENDIF}
    FProfile: TConnectServerProfile;
    FRsaAlgorithm: NativeUInt;
    FRsaKey: NativeUInt;
    {$IFDEF GAME_TRANSPORT_TESTS}
    procedure TestStage(const Stage: string; const View: TApiBuffer);
    {$ENDIF}
    function IsCancelled(Generation: UInt64): Boolean;
    procedure RequireActiveLocked(Generation: UInt64;
      const RequestClock: TStopwatch; RequestBudgetMs: Cardinal);
    procedure RequireActive(Generation: UInt64;
      const RequestClock: TStopwatch; RequestBudgetMs: Cardinal);
    function PerformPostJSON(const Operation: string; Body: TJSONObject;
      RequestBudgetMs: Cardinal; Generation: UInt64;
      const RequestClock: TStopwatch; out PeerPin: string): TJSONObject;
    function GetBindingID: string;
    function GetDisplayEndpoint: string;
  public
    constructor Create(Profile: TConnectServerProfile);
    destructor Destroy; override;
    function Fork: TConnectTransport;
    procedure CancelPending;
    { Owner must join every caller before reset/reuse. Admission and reset are
      serialized, and reset fails while any admitted call remains. This cannot
      prove external thread joins: owner must still stop publishing references. }
    procedure ResetCancellationAfterJoin;
    {$IFDEF GAME_TRANSPORT_TESTS}
    procedure ConfigureTest(const Exchange: TTransportTestExchange;
      const Stage: TTransportTestStage);
    {$ENDIF}
    { Body is borrowed, unchanged, and remains caller-owned. A successful result
      is a new caller-owned JSON tree; caller must Free it. No result is published
      for an expired/cancelled request. System.JSON's internal string allocations
      are not a secure heap; owned byte buffers do not promise dump resistance. }
    function PostJSON(const Operation: string; Body: TJSONObject;
      RequestBudgetMs: Cardinal = 0): TJSONObject;
    property BindingID: string read GetBindingID;
    property DisplayEndpoint: string read GetDisplayEndpoint;
  end;

implementation

uses
  Winapi.Windows, System.NetEncoding, Cozy.Relay.Socket, Cozy.ProtocolJson,
  Winapi.WinSock2,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer, Cozy.JsonEnvelope, Cozy.Api.Guid;

{ Private API pointers: initialized before application code starts. }
var
  ApiSlot_MultiByteToWideChar: TEncodedApiPointer;
  ApiSlot_socket: TEncodedApiPointer;


{$ALIGN 8}

type
  TCngStatus = LongInt;
  TCngHandle = NativeUInt;
  TOaepPaddingInfo = TGameOaepPaddingInfo;
  TAuthenticatedCipherInfo = TGameAuthenticatedCipherInfo;

const
  ProtocolName = CozyText_Transport_GAME_CONNECT_4_e3fdb954;
  MaxFrameBytes = 65536;
  MaxPlainBytes = 32768;
  MaxResponseFrameBytes = 786432;
  MaxResponsePlainBytes = 524288;
  RequestTimeoutMs = 10000;
  SystemPreferredRng = $00000002;
  OaepPaddingFlag = $00000004;
  GcmMode = CozyText_Transport_ChainingModeGCM_52dc3d90;

type
  TResolved_BCryptOpenAlgorithmProvider = function(out Algorithm: TCngHandle;
  AlgorithmName, ImplementationName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptOpenAlgorithmProvider: TEncodedApiPointer;
type
  TResolved_BCryptCloseAlgorithmProvider = function(Algorithm: TCngHandle;
  Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptCloseAlgorithmProvider: TEncodedApiPointer;
type
  TResolved_BCryptSetProperty = function(Handle: TCngHandle; Name: PWideChar;
  Input: PByte; InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptSetProperty: TEncodedApiPointer;
type
  TResolved_BCryptImportKeyPair = function(Algorithm, ImportKey: TCngHandle;
  BlobType: PWideChar; out Key: TCngHandle; Input: PByte;
  InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptImportKeyPair: TEncodedApiPointer;
type
  TResolved_BCryptGenerateSymmetricKey = function(Algorithm: TCngHandle; out Key: TCngHandle;
  KeyObject: PByte; KeyObjectSize: DWORD; Secret: PByte;
  SecretSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptGenerateSymmetricKey: TEncodedApiPointer;
type
  TResolved_BCryptDestroyKey = function(Key: TCngHandle): TCngStatus; stdcall;
var
  ApiSlot_BCryptDestroyKey: TEncodedApiPointer;
type
  TResolved_BCryptGenRandom = function(Algorithm: TCngHandle; Buffer: PByte;
  BufferSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptGenRandom: TEncodedApiPointer;
type
  TResolved_BCryptEncrypt = function(Key: TCngHandle; Input: PByte; InputSize: DWORD;
  Padding: Pointer; IV: PByte; IVSize: DWORD; Output: PByte;
  OutputSize: DWORD; out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptEncrypt: TEncodedApiPointer;
type
  TResolved_BCryptDecrypt = function(Key: TCngHandle; Input: PByte; InputSize: DWORD;
  Padding: Pointer; IV: PByte; IVSize: DWORD; Output: PByte;
  OutputSize: DWORD; out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptDecrypt: TEncodedApiPointer;

{ POINTER WRAPPERS 1 BEGIN }
function MultiByteToWideChar(CodePage: UINT; Flags: DWORD; Input: PAnsiChar; InputLength: Integer;
    Output: PWideChar; OutputLength: Integer): Integer; stdcall;
var
  ApiTarget: TApiMultiByteToWideChar;
begin
  ApiTarget := TApiMultiByteToWideChar(DecodeApiPointer(ApiSlot_MultiByteToWideChar));
  Result := ApiTarget(CodePage, Flags, Input, InputLength, Output, OutputLength);
end;

function socket(AddressFamily, SocketType, Protocol: Integer): TSocket; stdcall;
var
  ApiTarget: TApiSocket;
begin
  ApiTarget := TApiSocket(DecodeApiPointer(ApiSlot_socket));
  Result := ApiTarget(AddressFamily, SocketType, Protocol);
end;

function BCryptOpenAlgorithmProvider(out Algorithm: TCngHandle;
  AlgorithmName, ImplementationName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptOpenAlgorithmProvider;
begin
  ApiTarget := TResolved_BCryptOpenAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptOpenAlgorithmProvider));
  Result := ApiTarget(Algorithm, AlgorithmName, ImplementationName, Flags);
end;

function BCryptCloseAlgorithmProvider(Algorithm: TCngHandle;
  Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptCloseAlgorithmProvider;
begin
  ApiTarget := TResolved_BCryptCloseAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptCloseAlgorithmProvider));
  Result := ApiTarget(Algorithm, Flags);
end;

function BCryptSetProperty(Handle: TCngHandle; Name: PWideChar;
  Input: PByte; InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptSetProperty;
begin
  ApiTarget := TResolved_BCryptSetProperty(DecodeApiPointer(ApiSlot_BCryptSetProperty));
  Result := ApiTarget(Handle, Name, Input, InputSize, Flags);
end;

function BCryptImportKeyPair(Algorithm, ImportKey: TCngHandle;
  BlobType: PWideChar; out Key: TCngHandle; Input: PByte;
  InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptImportKeyPair;
begin
  ApiTarget := TResolved_BCryptImportKeyPair(DecodeApiPointer(ApiSlot_BCryptImportKeyPair));
  Result := ApiTarget(Algorithm, ImportKey, BlobType, Key, Input, InputSize, Flags);
end;

function BCryptGenerateSymmetricKey(Algorithm: TCngHandle; out Key: TCngHandle;
  KeyObject: PByte; KeyObjectSize: DWORD; Secret: PByte;
  SecretSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptGenerateSymmetricKey;
begin
  ApiTarget := TResolved_BCryptGenerateSymmetricKey(DecodeApiPointer(ApiSlot_BCryptGenerateSymmetricKey));
  Result := ApiTarget(Algorithm, Key, KeyObject, KeyObjectSize, Secret, SecretSize, Flags);
end;

function BCryptDestroyKey(Key: TCngHandle): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptDestroyKey;
begin
  ApiTarget := TResolved_BCryptDestroyKey(DecodeApiPointer(ApiSlot_BCryptDestroyKey));
  Result := ApiTarget(Key);
end;

function BCryptGenRandom(Algorithm: TCngHandle; Buffer: PByte;
  BufferSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptGenRandom;
begin
  ApiTarget := TResolved_BCryptGenRandom(DecodeApiPointer(ApiSlot_BCryptGenRandom));
  Result := ApiTarget(Algorithm, Buffer, BufferSize, Flags);
end;

function BCryptEncrypt(Key: TCngHandle; Input: PByte; InputSize: DWORD;
  Padding: Pointer; IV: PByte; IVSize: DWORD; Output: PByte;
  OutputSize: DWORD; out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptEncrypt;
begin
  ApiTarget := TResolved_BCryptEncrypt(DecodeApiPointer(ApiSlot_BCryptEncrypt));
  Result := ApiTarget(Key, Input, InputSize, Padding, IV, IVSize, Output, OutputSize, ActualSize, Flags);
end;

function BCryptDecrypt(Key: TCngHandle; Input: PByte; InputSize: DWORD;
  Padding: Pointer; IV: PByte; IVSize: DWORD; Output: PByte;
  OutputSize: DWORD; out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptDecrypt;
begin
  ApiTarget := TResolved_BCryptDecrypt(DecodeApiPointer(ApiSlot_BCryptDecrypt));
  Result := ApiTarget(Key, Input, InputSize, Padding, IV, IVSize, Output, OutputSize, ActualSize, Flags);
end;
{ POINTER WRAPPERS 1 END }

function TConnectTransport.IsCancelled(Generation: UInt64): Boolean;
begin
  FStateLock.Acquire;
  try
    Result := FCancelled or (FGeneration <> Generation) or FGate.IsClosing;
  finally FStateLock.Release; end;
end;
procedure TConnectTransport.CancelPending;
begin
  if FStateLock = nil then Exit; { Partially constructed object. }
  FStateLock.Acquire;
  try
    FCancelled := True;
    if FGeneration < High(UInt64) then Inc(FGeneration);
  finally FStateLock.Release; end;
end;
procedure TConnectTransport.ResetCancellationAfterJoin;
begin
  FStateLock.Acquire;
  try
    if (FGate = nil) or FGate.IsClosing or (FGate.ActiveCount <> 0) then
      raise EInvalidOpException.Create(CozyText_Transport_TRANSPORT_STILL_IN_USE_bc762d31);
    if FGeneration = High(UInt64) then
      raise EInvalidOpException.Create(CozyText_Transport_TRANSPORT_GENERATION_EXHAUSTED_275c82cf);
    FCancelled := False;
  finally FStateLock.Release; end;
end;
procedure TConnectTransport.RequireActiveLocked(Generation: UInt64;
  const RequestClock: TStopwatch; RequestBudgetMs: Cardinal);
begin
  if FCancelled or (Generation <> FGeneration) or FGate.IsClosing then
    raise EConnectTransport.Create(CozyText_Transport_CONNECT_CANCELLED_539a9bd0, CozyText_Transport_Request_was_cancelled_7b0bf9b8);
  if RequestClock.ElapsedMilliseconds >= RequestBudgetMs then
    raise EConnectTransport.Create(CozyText_Transport_CONNECT_TIMEOUT_b3f71146, CozyText_Transport_Request_deadline_expired_fb214276);
end;
procedure TConnectTransport.RequireActive(Generation: UInt64;
  const RequestClock: TStopwatch; RequestBudgetMs: Cardinal);
begin
  FStateLock.Acquire;
  try RequireActiveLocked(Generation, RequestClock, RequestBudgetMs);
  finally FStateLock.Release; end;
end;
{$IFDEF GAME_TRANSPORT_TESTS}
procedure TConnectTransport.ConfigureTest(const Exchange: TTransportTestExchange;
  const Stage: TTransportTestStage);
begin
  FStateLock.Acquire;
  try
    if FGate.IsClosing or (FGate.ActiveCount <> 0) then
      raise EInvalidOpException.Create(CozyText_Transport_TRANSPORT_STILL_IN_USE_bc762d31);
    FTestExchange := Exchange; FTestStage := Stage;
  finally FStateLock.Release; end;
end;
procedure TConnectTransport.TestStage(const Stage: string; const View: TApiBuffer);
begin
  if Assigned(FTestStage) then FTestStage(Stage, View);
end;
{$ENDIF}

constructor EConnectTransport.Create(const Code, MessageText: string);
begin
  inherited Create(MessageText);
  FCode := Code;
end;

procedure InvalidResponse;
begin
  raise EConnectTransport.Create(CozyText_Transport_CONNECT_INVALID_RESPONSE_695727cd,
    CozyText_Transport_Text_7c73d273);
end;

procedure CheckCng(Status: TCngStatus);
begin
  if Status <> 0 then
    raise EConnectTransport.Create(CozyText_Transport_CONNECT_CRYPTO_FAILED_8a140893,
      CozyText_Transport_Windows_292bdf8d);
end;

procedure WipeText(var Value: string);
begin
  if Value <> '' then
  begin
    UniqueString(Value);
    FillChar(PChar(Value)^, Length(Value) * SizeOf(Char), 0);
    Value := '';
  end;
end;

procedure WipeBytes(var Value: TBytes);
begin
  if Length(Value) <> 0 then FillChar(Value[0], Length(Value), 0);
  Value := nil;
end;

function Base64Encode(const Bytes: TBytes): string;
var
  Encoding: TBase64Encoding;
begin
  Encoding := TBase64Encoding.Create(0);
  try
    Result := Encoding.EncodeBytesToString(Bytes);
  finally
    Encoding.Free;
  end;
end;

function Base64Decode(const Text: string; MinBytes, MaxBytes: Integer): TBytes;
var
  Encoding: TBase64Encoding;
  Canonical: string;
begin
  Result := nil;
  if (Length(Text) < 4) or (Length(Text) > ((MaxBytes + 2) div 3) * 4) then
    InvalidResponse;
  Encoding := TBase64Encoding.Create(0);
  try
    try
      try
        Result := Encoding.DecodeStringToBytes(Text);
      except
        InvalidResponse;
      end;
      if (Length(Result) < MinBytes) or (Length(Result) > MaxBytes) then
        InvalidResponse;
      Canonical := Encoding.EncodeBytesToString(Result);
      if Canonical <> Text then InvalidResponse;
    except
      WipeBytes(Result);
      raise;
    end;
  finally
    WipeText(Canonical);
    Encoding.Free;
  end;
end;

procedure ValidateFlatObject(const Text: string);
var
  C: Char;
  Started, Closed, InString, Escaped: Boolean;
begin
  Started := False;
  Closed := False;
  InString := False;
  Escaped := False;
  for C in Text do
  begin
    if InString then
    begin
      if Escaped then Escaped := False
      else if C = '\' then Escaped := True
      else if C = '"' then InString := False;
      Continue;
    end;
    if CharInSet(C, [#9, #10, #13, ' ']) then Continue;
    if Closed then InvalidResponse;
    if not Started then
    begin
      if C <> '{' then InvalidResponse;
      Started := True;
      Continue;
    end;
    case C of
      '"': InString := True;
      '{', '[', ']': InvalidResponse;
      '}': Closed := True;
    end;
  end;
  if not Started or not Closed or InString then InvalidResponse;
end;

function DecodeUTF8(const Bytes: TApiBuffer): string;
var
  Count, ByteCount: Integer;
  Input: PAnsiChar;
begin
  if (Bytes.Capacity = 0) or (Bytes.Capacity > MaxResponsePlainBytes) then InvalidResponse;
  ByteCount := Integer(Bytes.Capacity);
  Input := PAnsiChar(Bytes.Read(0, Bytes.Capacity));
  Count := MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, Input, ByteCount, nil, 0);
  if Count <= 0 then InvalidResponse;
  SetLength(Result, Count);
  try
    if MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      Input, ByteCount, PWideChar(Result), Count) <> Count then InvalidResponse;
  except WipeText(Result); raise; end;
end;

function RequiredString(Obj: TJSONObject; const Name: string): string;
var
  Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONString) then InvalidResponse;
  Result := Value.Value;
end;

procedure InitAuthInfo(out Info: TAuthenticatedCipherInfo;
  const Nonce, AAD: TBytes; var Tag: TBytes);
begin
  { Equivalent to BCRYPT_INIT_AUTH_MODE_INFO plus the single-message buffers.
    No chained calls, IV buffer, block padding or MAC context is used. }
  FillChar(Info, SizeOf(Info), 0);
  Info.Size := SizeOf(Info);
  Info.Version := 1;
  Info.Nonce := @Nonce[0];
  Info.NonceSize := Length(Nonce);
  Info.AuthData := @AAD[0];
  Info.AuthDataSize := Length(AAD);
  Info.Tag := @Tag[0];
  Info.TagSize := Length(Tag);
end;

constructor TConnectTransport.Create(Profile: TConnectServerProfile);
var
  Blob: TBytes;
begin
  inherited Create;
  FStateLock := TCriticalSection.Create;
  FGate := TGameCallGate.Create;
  if Profile = nil then
    raise EConnectTransport.Create(CozyText_Transport_CONNECT_PROFILE_REQUIRED_cccdaa6c,
      CozyText_Transport_A_4905d724);
  { Catch accidental record packing/platform changes before calling Windows. }
  if not Win64ApiLayoutValid then
    raise EConnectTransport.Create(CozyText_Transport_CONNECT_PLATFORM_INVALID_b5b4b993,
      CozyText_Transport_Windows_64_64ae4a0c);
  FProfile := Profile.Clone;
  try
    Blob := Base64Decode(FProfile.ServerPublicKey, 281, 288);
    CheckCng(BCryptOpenAlgorithmProvider(FRsaAlgorithm, CozyText_Transport_RSA_b94db0f4, nil, 0));
    CheckCng(BCryptImportKeyPair(FRsaAlgorithm, 0, CozyText_Transport_RSAPUBLICBLOB_77898084,
      FRsaKey, @Blob[0], Length(Blob), 0));
  finally WipeBytes(Blob); end;
end;

destructor TConnectTransport.Destroy;
begin
  CancelPending;
  if FGate <> nil then FGate.CloseAndWait;
  if FRsaKey <> 0 then BCryptDestroyKey(FRsaKey);
  if FRsaAlgorithm <> 0 then BCryptCloseAlgorithmProvider(FRsaAlgorithm, 0);
  FProfile.Free;
  FGate.Free;
  {$IFDEF GAME_TRANSPORT_TESTS}
  FTestExchange := nil; FTestStage := nil;
  {$ENDIF}
  FStateLock.Free;
  inherited Destroy;
end;

function TConnectTransport.Fork: TConnectTransport;
begin
  FGate.Enter;
  try
    { Separate CNG handles, cancellation state and sockets; public pin-window
      transitions remain shared through the authenticated profile clone. }
    Result := TConnectTransport.Create(FProfile);
  finally FGate.Leave; end;
end;

function TConnectTransport.GetBindingID: string;
begin
  FGate.Enter;
  try
    Result := FProfile.BindingID;
  finally FGate.Leave; end;
end;

function TConnectTransport.GetDisplayEndpoint: string;
begin
  FGate.Enter;
  try
    Result := FProfile.DisplayEndpoint;
  finally FGate.Leave; end;
end;

function TConnectTransport.PostJSON(const Operation: string; Body: TJSONObject;
  RequestBudgetMs: Cardinal): TJSONObject;
var
  RequestClock: TStopwatch;
  Generation: UInt64;
  Candidate: TJSONObject;
  PeerPin, PlanJSON: string;
  PinValue: TJSONValue;
  PinPair: TJSONPair;
  Admitted: Boolean;
begin
  Candidate := nil; Admitted := False;
  RequestClock := TStopwatch.StartNew;
  if RequestBudgetMs = 0 then RequestBudgetMs := RequestTimeoutMs;
  if RequestBudgetMs > RequestTimeoutMs then RequestBudgetMs := RequestTimeoutMs;
  try
    FStateLock.Acquire;
    try
      FGate.Enter; Admitted := True;
      Generation := FGeneration;
      RequireActiveLocked(Generation, RequestClock, RequestBudgetMs);
    finally FStateLock.Release; end;
    Candidate := PerformPostJSON(Operation, Body, RequestBudgetMs, Generation, RequestClock, PeerPin);
    PinValue := Candidate.GetValue(CozyText_Transport_tlsPinPlan_d42e652f);
    if PinValue <> nil then
    begin
      if not (PinValue is TJSONObject) then InvalidResponse;
      PlanJSON := PinValue.ToJSON;
      PinPair := Candidate.RemovePair(CozyText_Transport_tlsPinPlan_d42e652f); PinPair.Free;
    end;
    {$IFDEF GAME_TRANSPORT_TESTS}
    TestStage(CozyText_Transport_before_publication_bb6d404e, TApiBuffer.Borrow(nil, 0, False));
    {$ENDIF}
    FStateLock.Acquire;
    try
      { Linearization point: all temporary crypto/plaintext storage is already
        gone. A cancellation that wins this lock prevents ownership transfer. }
      RequireActiveLocked(Generation, RequestClock, RequestBudgetMs);
      try
        FProfile.CheckTlsPeer(PeerPin);
        if PlanJSON <> '' then
          FProfile.LearnTlsPlan(PlanJSON, PeerPin,
            procedure begin RequireActiveLocked(Generation, RequestClock, RequestBudgetMs); end)
        else RequireActiveLocked(Generation, RequestClock, RequestBudgetMs);
      except
        on E: EConnectTransport do raise;
        on E: Exception do raise EConnectTransport.Create(CozyText_Transport_CONNECT_FAILED_0e77cb75,
          CozyText_Transport_Authenticated_TLS_pin_update_was_rejected_360a10f1);
      end;
      { Pin-plan commit and JSON transfer belong to this same admitted generation.
        No rejection-capable deadline check follows the trust-state mutation. }
      FGate.Leave; Admitted := False;
      Result := Candidate; Candidate := nil;
    finally FStateLock.Release; end;
  finally
    Candidate.Free;
    WipeText(PlanJSON);
    if Admitted then FGate.Leave;
  end;
end;

function TConnectTransport.PerformPostJSON(const Operation: string; Body: TJSONObject;
  RequestBudgetMs: Cardinal; Generation: UInt64;
  const RequestClock: TStopwatch; out PeerPin: string): TJSONObject;
var
  Socket: TRelaySocketClient;
  SocketBudget: Int64;
  Frame, Reply: TJSONObject;
  ReplyValue, DecodedValue, VersionValue: TJSONValue;
  Pair: TJSONPair;
  PrimaryPin, SecondaryPin: string;
  AESAlgorithm, AESKey: TCngHandle;
  Nonce, RequestTag, WrappedKey, CipherBytes: TBytes;
  ReplyNonce, ReplyTag, ReplyCipher, AAD: TBytes;
  KeyBytes, PlainBytes, ReplyPlain: TApiSensitiveBuffer;
  Scope: TApiSensitiveScope;
  AuthInfo: TAuthenticatedCipherInfo;
  OAEP: TOaepPaddingInfo;
  Actual: DWORD;
  Id: TGUID;
  RequestID, FrameText, ReplyLine, PlainText, Seen, Name: string;
begin
  { One budget includes admission, preparation, TLS/IO, decrypt, parsing and cleanup. }
  RequireActive(Generation, RequestClock, RequestBudgetMs);
  if (Operation <> CozyText_Transport_challenge_9e384e4b) and (Operation <> CozyText_Transport_execute_b76629f3) and
     (Operation <> CozyText_Transport_bootstrap_b2e494e5) and (Operation <> CozyText_Transport_report_c323c6fc) and
     (Operation <> CozyText_Transport_security_018694b5) and (Operation <> CozyText_Transport_overlay_a9bfd131) and (Operation <> CozyText_Transport_device_88d0d84b) and (Operation <> CozyText_Transport_policy_eca10e22) then
    raise EConnectTransport.Create(CozyText_Transport_CONNECT_OPERATION_INVALID_4592c542, CozyText_Transport_Text_c2c01286);
  if Body = nil then
    raise EConnectTransport.Create(CozyText_Transport_CONNECT_REQUEST_INVALID_1bc92c29, CozyText_Transport_Text_3799ef82);
  Socket := nil;
  KeyBytes := nil; PlainBytes := nil; ReplyPlain := nil; Scope := nil;
  Frame := nil;
  ReplyValue := nil;
  DecodedValue := nil;
  AESAlgorithm := 0;
  AESKey := 0;
  try
    try
      try
        try
          PlainBytes := EncodeRequestEnvelopeOwned(Operation, Body, MaxPlainBytes);
        except
          on E: EArgumentException do
            if E.Message = CozyText_Transport_REQUEST_ENVELOPE_LIMIT_5d964901 then
              raise EConnectTransport.Create(CozyText_Transport_CONNECT_REQUEST_TOO_LARGE_f6b52573, CozyText_Transport_Request_is_too_large_c15ffa1f)
            else raise;
        end;
        if (PlainBytes.Capacity < 1) or (PlainBytes.Capacity > MaxPlainBytes) then
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_REQUEST_TOO_LARGE_f6b52573, CozyText_Transport_Text_bdacb438);
        if WindowsApiCreateGUID(Id) <> 0 then
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_CRYPTO_FAILED_8a140893, CozyText_Transport_Text_d57b3c15);
        { This outer UUID is new for every encrypted attempt. The inner desktop
          requestId belongs to the API's durable, idempotent mutation journal. }
        RequestID := LowerCase(Copy(GUIDToString(Id), 2, 36));
        RequireActive(Generation, RequestClock, RequestBudgetMs);
        KeyBytes := TApiSensitiveBuffer.Create(32);
        Scope := KeyBytes.OpenWrite;
        SetLength(Nonce, 12);
        CheckCng(BCryptGenRandom(0, Scope.Buffer.Write(0, 32), 32, SystemPreferredRng));
        CheckCng(BCryptGenRandom(0, @Nonce[0], Length(Nonce), SystemPreferredRng));
        CheckCng(BCryptOpenAlgorithmProvider(AESAlgorithm, CozyText_Transport_AES_e4de2176, nil, 0));
        CheckCng(BCryptSetProperty(AESAlgorithm, CozyText_Transport_ChainingMode_bc99d0e4,
          PByte(PWideChar(GcmMode)), (Length(GcmMode) + 1) * SizeOf(WideChar), 0));
        { Windows 7+ allocates and owns the key object when this buffer is nil. }
        CheckCng(BCryptGenerateSymmetricKey(AESAlgorithm, AESKey, nil, 0,
          Scope.Buffer.Read(0, 32), 32, 0));
        FillChar(OAEP, SizeOf(OAEP), 0);
        OAEP.Algorithm := CozyText_Transport_SHA256_48c1f8ac;
        SetLength(WrappedKey, 256);
        CheckCng(BCryptEncrypt(FRsaKey, Scope.Buffer.Read(0, 32), 32, @OAEP,
          nil, 0, @WrappedKey[0], Length(WrappedKey), Actual, OaepPaddingFlag));
        if Actual <> 256 then
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_CRYPTO_FAILED_8a140893, CozyText_Transport_Text_0207d94b);
        FreeAndNil(Scope); FreeAndNil(KeyBytes);
        RequireActive(Generation, RequestClock, RequestBudgetMs);
        AAD := TEncoding.UTF8.GetBytes(ProtocolName + #10 + CozyText_Transport_REQUEST_d12fceaa + #10 +
          RequestID + #10 + FProfile.ServerKeyId);
        SetLength(RequestTag, 16);
        SetLength(CipherBytes, PlainBytes.Capacity);
        Scope := PlainBytes.OpenRead;
        {$IFDEF GAME_TRANSPORT_TESTS}
        TestStage(CozyText_Transport_request_plain_50377d2e, Scope.Buffer);
        {$ENDIF}
        InitAuthInfo(AuthInfo, Nonce, AAD, RequestTag);
        CheckCng(BCryptEncrypt(AESKey, Scope.Buffer.Read(0, PlainBytes.Capacity), DWORD(PlainBytes.Capacity), @AuthInfo,
          nil, 0, @CipherBytes[0], Length(CipherBytes), Actual, 0));
        if Actual <> DWORD(PlainBytes.Capacity) then
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_CRYPTO_FAILED_8a140893, CozyText_Transport_Text_1cb97d6e);
        FreeAndNil(Scope); FreeAndNil(PlainBytes);
        FillChar(AuthInfo, SizeOf(AuthInfo), 0);
        RequireActive(Generation, RequestClock, RequestBudgetMs);
        Frame := TJSONObject.Create;
        Frame.AddPair('v', TJSONNumber.Create(1));
        Frame.AddPair(CozyText_Transport_keyId_70570c2b, FProfile.ServerKeyId);
        Frame.AddPair(CozyText_Transport_requestId_d67f3acd, RequestID);
        Frame.AddPair(CozyText_Transport_wrappedKey_f62b2737, Base64Encode(WrappedKey));
        Frame.AddPair(CozyText_Transport_nonce_2bb29dca, Base64Encode(Nonce));
        Frame.AddPair(CozyText_Transport_ciphertext_30a2d71e, Base64Encode(CipherBytes));
        Frame.AddPair(CozyText_Transport_tag_1d13256a, Base64Encode(RequestTag));
        FrameText := Frame.ToJSON;
        { Only serialized ciphertext is needed during I/O. Release Base64 JSON
          values and duplicate encoded byte arrays before waiting on the peer. }
        FreeAndNil(Frame);
        WipeBytes(WrappedKey); WipeBytes(CipherBytes); WipeBytes(RequestTag);
        if TEncoding.UTF8.GetByteCount(FrameText) > MaxFrameBytes then
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_REQUEST_TOO_LARGE_f6b52573, CozyText_Transport_Text_02e008de);
        SocketBudget := RequestBudgetMs;
        Dec(SocketBudget, RequestClock.ElapsedMilliseconds);
        if SocketBudget <= 0 then
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_TIMEOUT_b3f71146, CozyText_Transport_Text_116e93af);
        {$IFDEF GAME_TRANSPORT_TESTS}
        if Assigned(FTestExchange) then ReplyLine := FTestExchange(FrameText, PeerPin)
        else
        {$ENDIF}
        begin
          Socket := TRelaySocketClient.Create(Cardinal(SocketBudget), MaxResponseFrameBytes,
            function: Boolean begin Result := IsCancelled(Generation); end);
          FProfile.SelectTlsPins(PrimaryPin,SecondaryPin);
          if not Socket.ConnectTLS(FProfile.Host, FProfile.Port,
            FProfile.TlsServerName, PrimaryPin, SecondaryPin) then
            raise EConnectTransport.Create(CozyText_Transport_CONNECT_UNAVAILABLE_b1c0cb85,
              CozyText_Transport_Text_ea42d423);
          if not Socket.SendLine(FrameText) then
            raise EConnectTransport.Create(CozyText_Transport_CONNECT_SEND_FAILED_a7f20ad5,
              CozyText_Transport_Text_a5938463);
          WipeText(FrameText);
          if not Socket.ReceiveLine(ReplyLine) then
            raise EConnectTransport.Create(CozyText_Transport_CONNECT_RECEIVE_FAILED_6e6fb52f,
              CozyText_Transport_Text_f56d9902);
          PeerPin := Socket.PeerCertificateSha256;
          Socket.Close;
        end;
        WipeText(FrameText);
        RequireActive(Generation, RequestClock, RequestBudgetMs);
        if TEncoding.UTF8.GetByteCount(ReplyLine) > MaxResponseFrameBytes then InvalidResponse;
        ValidateFlatObject(ReplyLine);
        ReplyValue := ParseProtocolObject(ReplyLine, MaxResponseFrameBytes);
        WipeText(ReplyLine);
        if not (ReplyValue is TJSONObject) then InvalidResponse;
        Reply := TJSONObject(ReplyValue);
        if Reply.Count <> 5 then InvalidResponse;
        Seen := '|';
        for Pair in Reply do
        begin
          Name := Pair.JsonString.Value;
          if (Name <> 'v') and (Name <> CozyText_Transport_requestId_d67f3acd) and (Name <> CozyText_Transport_nonce_2bb29dca) and
             (Name <> CozyText_Transport_ciphertext_30a2d71e) and (Name <> CozyText_Transport_tag_1d13256a) then InvalidResponse;
          if Pos('|' + Name + '|', Seen) > 0 then InvalidResponse;
          Seen := Seen + Name + '|';
        end;
        VersionValue := Reply.GetValue('v');
        if not (VersionValue is TJSONNumber) then InvalidResponse;
        if VersionValue.Value <> '1' then InvalidResponse;
        if RequiredString(Reply, CozyText_Transport_requestId_d67f3acd) <> RequestID then InvalidResponse;
        ReplyNonce := Base64Decode(RequiredString(Reply, CozyText_Transport_nonce_2bb29dca), 12, 12);
        ReplyTag := Base64Decode(RequiredString(Reply, CozyText_Transport_tag_1d13256a), 16, 16);
        ReplyCipher := Base64Decode(RequiredString(Reply, CozyText_Transport_ciphertext_30a2d71e), 2, MaxResponsePlainBytes);
        if CompareMem(@Nonce[0], @ReplyNonce[0], 12) then InvalidResponse;
        { All required response fields are decoded; the Base64 JSON tree and
          request nonce no longer need to survive decryption or JSON parsing. }
        FreeAndNil(ReplyValue);
        WipeBytes(Nonce); WipeBytes(AAD);
        AAD := TEncoding.UTF8.GetBytes(ProtocolName + #10 + CozyText_Transport_RESPONSE_7c348372 + #10 +
          RequestID + #10 + FProfile.ServerKeyId);
        RequireActive(Generation, RequestClock, RequestBudgetMs);
        ReplyPlain := TApiSensitiveBuffer.Create(Length(ReplyCipher));
        Scope := ReplyPlain.OpenWrite;
        {$IFDEF GAME_TRANSPORT_TESTS}
        TestStage(CozyText_Transport_before_decrypt_1bf9eebc, TApiBuffer.Borrow(nil, 0, False));
        {$ENDIF}
        RequireActive(Generation, RequestClock, RequestBudgetMs);
        InitAuthInfo(AuthInfo, ReplyNonce, AAD, ReplyTag);
        { Never parse plaintext or grant authorization unless CNG verifies the
          complete GCM tag for this request, direction and pinned server key. }
        if BCryptDecrypt(AESKey, @ReplyCipher[0], Length(ReplyCipher), @AuthInfo,
          nil, 0, Scope.Buffer.Write(0, ReplyPlain.Capacity), DWORD(ReplyPlain.Capacity), Actual, 0) <> 0 then
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_AUTHENTICATION_FAILED_a99efd74,
            CozyText_Transport_Text_8edfbce9);
        if (Actual <> DWORD(ReplyPlain.Capacity)) or (Actual > MaxResponsePlainBytes) then
          InvalidResponse;
        { The request key is no longer needed after authenticated decryption.
          Keep its handle only if destruction fails, so finally can retry. }
        CheckCng(BCryptDestroyKey(AESKey)); AESKey := 0;
        FillChar(AuthInfo, SizeOf(AuthInfo), 0);
        WipeBytes(ReplyCipher); WipeBytes(ReplyTag); WipeBytes(ReplyNonce); WipeBytes(AAD);
        {$IFDEF GAME_TRANSPORT_TESTS}
        TestStage(CozyText_Transport_authenticated_plain_90443b15, Scope.Buffer);
        {$ENDIF}
        RequireActive(Generation, RequestClock, RequestBudgetMs);
        PlainText := DecodeUTF8(Scope.Buffer);
        FreeAndNil(Scope); FreeAndNil(ReplyPlain);
        try
          DecodedValue := ParseProtocolObject(PlainText, MaxResponsePlainBytes);
        finally WipeText(PlainText); end;
        {$IFDEF GAME_TRANSPORT_TESTS}
        TestStage(CozyText_Transport_parsed_json_f607f5aa, TApiBuffer.Borrow(nil, 0, False));
        {$ENDIF}
        if not (DecodedValue is TJSONObject) then InvalidResponse;
        RequireActive(Generation, RequestClock, RequestBudgetMs);
      except
        on E: EConnectTransport do raise;
        on E: Exception do
          raise EConnectTransport.Create(CozyText_Transport_CONNECT_FAILED_0e77cb75,
            CozyText_Transport_Text_c0afdc2c);
      end;
    finally
      Socket.Free;
      Frame.Free;
      ReplyValue.Free;
      if AESKey <> 0 then BCryptDestroyKey(AESKey);
      if AESAlgorithm <> 0 then BCryptCloseAlgorithmProvider(AESAlgorithm, 0);
      Scope.Free;
      KeyBytes.Free;
      PlainBytes.Free;
      ReplyPlain.Free;
      WipeText(PlainText); WipeText(FrameText); WipeText(ReplyLine);
      WipeBytes(Nonce); WipeBytes(RequestTag); WipeBytes(WrappedKey); WipeBytes(CipherBytes);
      WipeBytes(ReplyNonce); WipeBytes(ReplyTag); WipeBytes(ReplyCipher); WipeBytes(AAD);
      FillChar(AuthInfo, SizeOf(AuthInfo), 0); FillChar(OAEP, SizeOf(OAEP), 0);
    end;
  except DecodedValue.Free; raise; end;
  { Publish only after cleanup has succeeded; PostJSON retains ownership until
    its locked generation/deadline/pin commit. }
  Result := TJSONObject(DecodedValue);
end;

initialization
  { API binding only; original startup actions follow unchanged. }
  BindApiPointer(ApiSlot_MultiByteToWideChar, RequireProcAddressHash64(CozyText_Transport_kernel32_dll_321762c1, HASH_MultiByteToWideChar));
  BindApiPointer(ApiSlot_socket, RequireProcAddressHash64(CozyText_Transport_ws2_32_dll_9a035509, HASH_socket));
  BindApiPointer(ApiSlot_BCryptOpenAlgorithmProvider, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptOpenAlgorithmProvider));
  BindApiPointer(ApiSlot_BCryptCloseAlgorithmProvider, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptCloseAlgorithmProvider));
  BindApiPointer(ApiSlot_BCryptSetProperty, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptSetProperty));
  BindApiPointer(ApiSlot_BCryptImportKeyPair, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptImportKeyPair));
  BindApiPointer(ApiSlot_BCryptGenerateSymmetricKey, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptGenerateSymmetricKey));
  BindApiPointer(ApiSlot_BCryptDestroyKey, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptDestroyKey));
  BindApiPointer(ApiSlot_BCryptGenRandom, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptGenRandom));
  BindApiPointer(ApiSlot_BCryptEncrypt, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptEncrypt));
  BindApiPointer(ApiSlot_BCryptDecrypt, RequireProcAddressHash64(CozyText_Transport_bcrypt_dll_8e6256e8, HASH_BCryptDecrypt));

end.
