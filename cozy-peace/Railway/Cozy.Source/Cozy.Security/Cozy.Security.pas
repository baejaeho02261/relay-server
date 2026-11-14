unit Cozy.Security;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Security,

  System.SysUtils, Cozy.Lifetime, Cozy.Api.Contracts;

type
  EDeviceSecurity = class(Exception);
{$IFDEF GAME_DEVICE_SECURITY_TESTS}
  { Observation only; the real CNG calls are never replaced. A callback may
    inspect the scoped view synchronously, block for a probe, or raise. }
  TDeviceSecurityTestObserver = reference to procedure(const Stage: string;
    const View: TApiBuffer);
{$ENDIF}

  { Each A/B/O process owns an independent unnamed, non-exportable signing
    key. Only public keys and one-use parent delegations cross the IPC boundary. }
  TDeviceSecurity = class
  private
    FGate: TGameCallGate;
    FProvider: NativeUInt;
    FKey: NativeUInt;
    FLock: TObject;
    FPublicKeyBlob: string;
    FDeviceID: string;
    FMachineID: string;
    FParentDeviceID, FHandoffNonce, FDelegationSignature: string;
    FHandoffRole, FHandoffClaimHash: string;
    FHandoffAccepted: Boolean;
{$IFDEF GAME_DEVICE_SECURITY_TESTS}
    FTestObserver: TDeviceSecurityTestObserver;
    procedure ObserveTestStage(const Stage: string; const View: TApiBuffer);
{$ENDIF}
    procedure RequireOpen;
    function SignSpanUnlocked(const Text: TApiBuffer): string;
    function SignUnlocked(const Text: string): string;
    function ReadField(Index: Integer): string;
    function GetPublicKeyBlob: string;
    function GetDeviceID: string;
    function GetMachineID: string;
    function GetParentDeviceID: string;
    function GetHandoffNonce: string;
    function GetDelegationSignature: string;
    procedure OpenProvider;
    procedure ExportPublicKey;
  public
    constructor Create;
{$IFDEF GAME_DEVICE_SECURITY_TESTS}
    { Set while idle and keep the callback alive until all admitted calls join. }
    property TestObserver: TDeviceSecurityTestObserver read FTestObserver write FTestObserver;
    function TestIsClosing: Boolean;
{$ENDIF}
    { Owner stops publishing references before Close/Free. Close drains admitted
      calls, not calls through an already freed object pointer. }
    procedure Close;
    destructor Destroy; override;
    procedure AcceptDelegation(const ParentDeviceID, Role, Claim, Nonce,
      Signature: string);
    function SignHandoffClaim(const Role, Claim: string): string;
    procedure CompleteHandoff;
    function Sign(const Text: string): string;
    property PublicKeyBlob: string read GetPublicKeyBlob;
    property DeviceID: string read GetDeviceID;
    property MachineID: string read GetMachineID;
    property ParentDeviceID: string read GetParentDeviceID;
    property HandoffNonce: string read GetHandoffNonce;
    property DelegationSignature: string read GetDelegationSignature;
  end;

function HandoffCanonical(const Purpose, Role, Claim, ChildKeyID, Nonce: string): string;
function DevicePublicKeyID(const PublicKey: string): string;
procedure WipeBytes(var Bytes: TBytes);
procedure WipeText(var Text: string);
function DeviceSHA256(const Bytes: TBytes): TBytes;

implementation

uses
  Winapi.Windows, System.Classes, System.NetEncoding, Cozy.Integrity,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer,
  Cozy.Hashes;

{$ALIGN 8}

type
  TCngStatus = LongInt;
  TCngHandle = NativeUInt;
  TPKCS1PaddingInfo = TGamePkcs1PaddingInfo;
  TRsaPublicHeader = TGameRsaPublicHeader;

const
  KeyStorageProvider = CozyText_Security_Microsoft_Software_Key_Storage_Provider_538976fd;
  RsaAlgorithm = CozyText_Security_RSA_35359569;
  Sha256Algorithm = CozyText_Security_SHA256_a83f6e23;
  RsaPublicBlobType = CozyText_Security_RSAPUBLICBLOB_54b4e104;
  NCryptSilentFlag = $00000040;
  NCryptPKCS1Flag = $00000002;
  NCryptAllowSigningFlag = $00000002;
  RsaPublicMagic = $31415352;

type
  TResolved_NCryptOpenStorageProvider = function(out Provider: TCngHandle;
  ProviderName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_NCryptOpenStorageProvider: TEncodedApiPointer;
type
  TResolved_NCryptCreatePersistedKey = function(Provider: TCngHandle; out Key: TCngHandle;
  Algorithm, KeyName: PWideChar; LegacyKeySpec, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_NCryptCreatePersistedKey: TEncodedApiPointer;
type
  TResolved_NCryptSetProperty = function(Handle: TCngHandle; Name: PWideChar;
  Input: PByte; InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_NCryptSetProperty: TEncodedApiPointer;
type
  TResolved_NCryptFinalizeKey = function(Key: TCngHandle; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_NCryptFinalizeKey: TEncodedApiPointer;
type
  TResolved_NCryptExportKey = function(Key, ExportKey: TCngHandle; BlobType: PWideChar;
  Parameters: Pointer; Output: PByte; OutputSize: DWORD;
  out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_NCryptExportKey: TEncodedApiPointer;
type
  TResolved_NCryptSignHash = function(Key: TCngHandle; Padding: Pointer;
  Hash: PByte; HashSize: DWORD; Signature: PByte; SignatureSize: DWORD;
  out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_NCryptSignHash: TEncodedApiPointer;
type
  TResolved_NCryptFreeObject = function(Handle: TCngHandle): TCngStatus; stdcall;
var
  ApiSlot_NCryptFreeObject: TEncodedApiPointer;
type
  TResolved_BCryptOpenAlgorithmProvider = function(out Algorithm: TCngHandle;
  AlgorithmName, ImplementationName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptOpenAlgorithmProvider: TEncodedApiPointer;
type
  TResolved_BCryptCreateHash = function(Algorithm: TCngHandle; out Hash: TCngHandle;
  HashObject: PByte; HashObjectSize: DWORD; Secret: PByte;
  SecretSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptCreateHash: TEncodedApiPointer;
type
  TResolved_BCryptHashData = function(Hash: TCngHandle; Input: PByte;
  InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptHashData: TEncodedApiPointer;
type
  TResolved_BCryptFinishHash = function(Hash: TCngHandle; Output: PByte;
  OutputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptFinishHash: TEncodedApiPointer;
type
  TResolved_BCryptDestroyHash = function(Hash: TCngHandle): TCngStatus; stdcall;
var
  ApiSlot_BCryptDestroyHash: TEncodedApiPointer;
type
  TResolved_BCryptCloseAlgorithmProvider = function(Algorithm: TCngHandle;
  Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptCloseAlgorithmProvider: TEncodedApiPointer;

{ POINTER WRAPPERS 1 BEGIN }
function NCryptOpenStorageProvider(out Provider: TCngHandle;
  ProviderName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_NCryptOpenStorageProvider;
begin
  ApiTarget := TResolved_NCryptOpenStorageProvider(DecodeApiPointer(ApiSlot_NCryptOpenStorageProvider));
  Result := ApiTarget(Provider, ProviderName, Flags);
end;

function NCryptCreatePersistedKey(Provider: TCngHandle; out Key: TCngHandle;
  Algorithm, KeyName: PWideChar; LegacyKeySpec, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_NCryptCreatePersistedKey;
begin
  ApiTarget := TResolved_NCryptCreatePersistedKey(DecodeApiPointer(ApiSlot_NCryptCreatePersistedKey));
  Result := ApiTarget(Provider, Key, Algorithm, KeyName, LegacyKeySpec, Flags);
end;

function NCryptSetProperty(Handle: TCngHandle; Name: PWideChar;
  Input: PByte; InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_NCryptSetProperty;
begin
  ApiTarget := TResolved_NCryptSetProperty(DecodeApiPointer(ApiSlot_NCryptSetProperty));
  Result := ApiTarget(Handle, Name, Input, InputSize, Flags);
end;

function NCryptFinalizeKey(Key: TCngHandle; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_NCryptFinalizeKey;
begin
  ApiTarget := TResolved_NCryptFinalizeKey(DecodeApiPointer(ApiSlot_NCryptFinalizeKey));
  Result := ApiTarget(Key, Flags);
end;

function NCryptExportKey(Key, ExportKey: TCngHandle; BlobType: PWideChar;
  Parameters: Pointer; Output: PByte; OutputSize: DWORD;
  out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_NCryptExportKey;
begin
  ApiTarget := TResolved_NCryptExportKey(DecodeApiPointer(ApiSlot_NCryptExportKey));
  Result := ApiTarget(Key, ExportKey, BlobType, Parameters, Output, OutputSize, ActualSize, Flags);
end;

function NCryptSignHash(Key: TCngHandle; Padding: Pointer;
  Hash: PByte; HashSize: DWORD; Signature: PByte; SignatureSize: DWORD;
  out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_NCryptSignHash;
begin
  ApiTarget := TResolved_NCryptSignHash(DecodeApiPointer(ApiSlot_NCryptSignHash));
  Result := ApiTarget(Key, Padding, Hash, HashSize, Signature, SignatureSize, ActualSize, Flags);
end;

function NCryptFreeObject(Handle: TCngHandle): TCngStatus; stdcall;
var
  ApiTarget: TResolved_NCryptFreeObject;
begin
  ApiTarget := TResolved_NCryptFreeObject(DecodeApiPointer(ApiSlot_NCryptFreeObject));
  Result := ApiTarget(Handle);
end;

function BCryptOpenAlgorithmProvider(out Algorithm: TCngHandle;
  AlgorithmName, ImplementationName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptOpenAlgorithmProvider;
begin
  ApiTarget := TResolved_BCryptOpenAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptOpenAlgorithmProvider));
  Result := ApiTarget(Algorithm, AlgorithmName, ImplementationName, Flags);
end;

function BCryptCreateHash(Algorithm: TCngHandle; out Hash: TCngHandle;
  HashObject: PByte; HashObjectSize: DWORD; Secret: PByte;
  SecretSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptCreateHash;
begin
  ApiTarget := TResolved_BCryptCreateHash(DecodeApiPointer(ApiSlot_BCryptCreateHash));
  Result := ApiTarget(Algorithm, Hash, HashObject, HashObjectSize, Secret, SecretSize, Flags);
end;

function BCryptHashData(Hash: TCngHandle; Input: PByte;
  InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptHashData;
begin
  ApiTarget := TResolved_BCryptHashData(DecodeApiPointer(ApiSlot_BCryptHashData));
  Result := ApiTarget(Hash, Input, InputSize, Flags);
end;

function BCryptFinishHash(Hash: TCngHandle; Output: PByte;
  OutputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptFinishHash;
begin
  ApiTarget := TResolved_BCryptFinishHash(DecodeApiPointer(ApiSlot_BCryptFinishHash));
  Result := ApiTarget(Hash, Output, OutputSize, Flags);
end;

function BCryptDestroyHash(Hash: TCngHandle): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptDestroyHash;
begin
  ApiTarget := TResolved_BCryptDestroyHash(DecodeApiPointer(ApiSlot_BCryptDestroyHash));
  Result := ApiTarget(Hash);
end;

function BCryptCloseAlgorithmProvider(Algorithm: TCngHandle;
  Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptCloseAlgorithmProvider;
begin
  ApiTarget := TResolved_BCryptCloseAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptCloseAlgorithmProvider));
  Result := ApiTarget(Algorithm, Flags);
end;
{ POINTER WRAPPERS 1 END }

procedure CheckStatus(Status: TCngStatus; const Operation: string);
begin
  if Status <> 0 then
    raise EDeviceSecurity.CreateFmt(CozyText_Security_s_0x_s_f913b20a,
      [Operation, IntToHex(DWORD(Status), 8)]);
end;

procedure WipeBytes(var Bytes: TBytes);
begin
  if Length(Bytes) > 0 then FillChar(Bytes[0], Length(Bytes), 0);
  Bytes := nil;
end;

procedure WipeText(var Text: string);
begin
  if Text <> '' then
  begin
    UniqueString(Text);
    FillChar(PChar(Text)^, Length(Text) * SizeOf(Char), 0);
    Text := '';
  end;
end;

function Sha256Owned(const Bytes: TApiBuffer): TApiSensitiveBuffer;
var
  Algorithm, Hash: TCngHandle;
  Count: NativeUInt;
  Digest: TApiSensitiveBuffer;
  Scope: TApiSensitiveScope;
begin
  Count := Bytes.Capacity;
  if UInt64(Count) > UInt64(High(DWORD)) then
    raise EDeviceSecurity.Create(CozyText_Security_DEVICE_HASH_INPUT_TOO_LARGE_eb72b9f9);
  Algorithm := 0; Hash := 0; Digest := nil; Scope := nil;
  try
    try
      CheckStatus(BCryptOpenAlgorithmProvider(Algorithm,
        PWideChar(Sha256Algorithm), nil, 0), CozyText_Security_SHA_256_e827d5f9);
      { Windows 7+ allocates and frees its own hash object when these are nil/0. }
      CheckStatus(BCryptCreateHash(Algorithm, Hash, nil, 0, nil, 0, 0),
        CozyText_Security_SHA_256_75e82dd1);
      if Count > 0 then
        CheckStatus(BCryptHashData(Hash, PByte(Bytes.Read(0, Count)), DWORD(Count), 0),
          CozyText_Security_SHA_256_25af6872);
      Digest := TApiSensitiveBuffer.Create(32);
      Scope := Digest.OpenWrite;
      CheckStatus(BCryptFinishHash(Hash, PByte(Scope.Buffer.Write(0, 32)), 32, 0),
        CozyText_Security_SHA_256_a6171e89);
    finally
      try FreeAndNil(Scope);
      finally
        try if Hash <> 0 then BCryptDestroyHash(Hash);
        finally if Algorithm <> 0 then BCryptCloseAlgorithmProvider(Algorithm, 0); end;
      end;
    end;
    Result := Digest; Digest := nil;
  finally Digest.Free; end;
end;

function Sha256Span(const Bytes: TApiBuffer): TBytes;
var Digest: TApiSensitiveBuffer; Scope: TApiSensitiveScope;
begin
  { Public compatibility helper returns caller-owned bytes. Internal signing
    keeps its digest in the owner and never takes this compatibility copy. }
  Digest := Sha256Owned(Bytes); Scope := nil;
  try
    try
      Scope := Digest.OpenRead;
      SetLength(Result, 32);
      Move(Scope.Buffer.Read(0, 32)^, Result[0], 32);
    except WipeBytes(Result); raise; end;
  finally
    try Scope.Free; finally Digest.Free; end;
  end;
end;

function Sha256(const Bytes: TBytes): TBytes;
begin
  Result := Sha256Span(TApiBuffer.ReadBytes(Bytes));
end;

function DeviceSHA256(const Bytes: TBytes): TBytes;
begin
  Result := Sha256(Bytes);
end;

function Base64(const Bytes: TBytes): string;
var
  Encoding: TBase64Encoding;
begin
  { The shared MIME Base64 encoder may wrap lines at 76 characters. Wire
    signatures and public keys must be one uninterrupted Base64 value. }
  Encoding := TBase64Encoding.Create(0);
  try
    Result := Encoding.EncodeBytesToString(Bytes);
  finally
    Encoding.Free;
  end;
end;

function Hex(const Bytes: TBytes): string;
const
  Digits: string = CozyText_Security_0123456789ABCDEF_5404eb8e;
var
  I: Integer;
begin
  SetLength(Result, Length(Bytes) * 2);
  for I := 0 to High(Bytes) do
  begin
    Result[I * 2 + 1] := Digits[(Bytes[I] shr 4) + 1];
    Result[I * 2 + 2] := Digits[(Bytes[I] and $F) + 1];
  end;
end;

procedure TDeviceSecurity.OpenProvider;
begin
  FGate := TGameCallGate.Create;
  FLock := TObject.Create;
  FMachineID := IntegrityMachineID;
  CheckStatus(NCryptOpenStorageProvider(FProvider,
    PWideChar(KeyStorageProvider), 0), CozyText_Security_Text_1b613c55);
end;

constructor TDeviceSecurity.Create;
var
  KeyBits, Usage: DWORD;
begin
  inherited Create;
  OpenProvider;
  { NULL name is ephemeral; no export permission is enabled. }
  CheckStatus(NCryptCreatePersistedKey(FProvider, FKey,
    PWideChar(RsaAlgorithm), nil, 0, 0), CozyText_Security_Text_d8565d75);
  KeyBits := 2048;
  Usage := NCryptAllowSigningFlag;
  CheckStatus(NCryptSetProperty(FKey, CozyText_Security_Length_8cf71aa9, @KeyBits,
    SizeOf(KeyBits), 0), CozyText_Security_Text_6a50c977);
  CheckStatus(NCryptSetProperty(FKey, CozyText_Security_Key_Usage_b1f7d66a, @Usage,
    SizeOf(Usage), 0), CozyText_Security_Text_dc8043d7);
  CheckStatus(NCryptFinalizeKey(FKey, NCryptSilentFlag), CozyText_Security_Text_02c94e94);
  ExportPublicKey;
end;

destructor TDeviceSecurity.Destroy;
begin
  Close;
{$IFDEF GAME_DEVICE_SECURITY_TESTS}
  FTestObserver := nil;
{$ENDIF}
  WipeText(FPublicKeyBlob);
  WipeText(FDeviceID);
  WipeText(FMachineID);
  WipeText(FParentDeviceID);
  WipeText(FHandoffNonce);
  WipeText(FDelegationSignature);
  WipeText(FHandoffRole);
  WipeText(FHandoffClaimHash);
  if FKey <> 0 then NCryptFreeObject(FKey);
  if FProvider <> 0 then NCryptFreeObject(FProvider);
  FLock.Free;
  FGate.Free;
  inherited Destroy;
end;

procedure TDeviceSecurity.ExportPublicKey;
var
  Size, Actual: DWORD;
  Bytes, Digest: TBytes;
  Header: TRsaPublicHeader;
  Output: TApiBuffer;
begin
  Size := 0;
  try
    CheckStatus(NCryptExportKey(FKey, 0, PWideChar(RsaPublicBlobType),
      nil, nil, 0, Size, NCryptSilentFlag), CozyText_Security_Text_c1d0333b);
    if (Size < SizeOf(Header) + 257) or (Size > 1024) then
      raise EDeviceSecurity.Create(CozyText_Security_Text_ab06b760);
    SetLength(Bytes, Integer(Size));
    Output := TApiBuffer.WriteBytes(Bytes);
    Actual := 0;
    CheckStatus(NCryptExportKey(FKey, 0, PWideChar(RsaPublicBlobType),
      nil, PByte(Output.Write(0, Size)), Size, Actual, NCryptSilentFlag), CozyText_Security_Text_8d117129);
    Output.Completed(Size, Actual);
    if Actual <> Size then
      raise EDeviceSecurity.Create(CozyText_Security_Text_2418f270);
    Move(Bytes[0], Header, SizeOf(Header));
    if (Header.Magic <> RsaPublicMagic) or (Header.BitLength <> 2048) or
      (Header.ModulusBytes <> 256) or (Header.PublicExponentBytes = 0) or
      (Header.PublicExponentBytes > 8) or (Header.Prime1Bytes <> 0) or
      (Header.Prime2Bytes <> 0) or
      (Size <> DWORD(SizeOf(Header)) + Header.PublicExponentBytes + Header.ModulusBytes) then
      raise EDeviceSecurity.Create(CozyText_Security_Text_faeaff1b);
    FPublicKeyBlob := Base64(Bytes);
    Digest := Sha256(Bytes);
    FDeviceID := Hex(Digest);
  finally
    WipeBytes(Bytes); WipeBytes(Digest); FillChar(Header, SizeOf(Header), 0);
  end;
end;

function Base64Span(const Bytes: TApiBuffer): string;
const Alphabet: string = CozyText_Security_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv_f1f45af2;
var Count, I, OutIndex: Integer; A, B, C: Byte;
begin
  { Signatures are at most 256 bytes. Emit directly to the required public
    string, without a second dynamic array containing the signature. }
  if Bytes.Capacity > 1024 then raise EDeviceSecurity.Create(CozyText_Security_DEVICE_BASE64_TOO_LARGE_719ba37c);
  Count := Integer(Bytes.Capacity);
  SetLength(Result, ((Count + 2) div 3) * 4);
  I := 0; OutIndex := 1;
  while I < Count do
  begin
    A := PByte(Bytes.Read(I, 1))^; B := 0; C := 0;
    if I + 1 < Count then B := PByte(Bytes.Read(I + 1, 1))^;
    if I + 2 < Count then C := PByte(Bytes.Read(I + 2, 1))^;
    Result[OutIndex] := Alphabet[(A shr 2) + 1];
    Result[OutIndex + 1] := Alphabet[(((A and 3) shl 4) or (B shr 4)) + 1];
    if I + 1 < Count then
      Result[OutIndex + 2] := Alphabet[(((B and 15) shl 2) or (C shr 6)) + 1]
    else Result[OutIndex + 2] := '=';
    if I + 2 < Count then Result[OutIndex + 3] := Alphabet[(C and 63) + 1]
    else Result[OutIndex + 3] := '=';
    Inc(I, 3); Inc(OutIndex, 4);
  end;
end;

procedure TDeviceSecurity.RequireOpen;
begin
  if FGate.IsClosing then raise EInvalidOpException.Create(CozyText_Security_OBJECT_CLOSING_d0c2ed32);
end;

{$IFDEF GAME_DEVICE_SECURITY_TESTS}
function TDeviceSecurity.TestIsClosing: Boolean;
begin Result := FGate.IsClosing; end;

procedure TDeviceSecurity.ObserveTestStage(const Stage: string; const View: TApiBuffer);
begin
  if Assigned(FTestObserver) then FTestObserver(Stage, View);
end;
{$ENDIF}

function TDeviceSecurity.SignSpanUnlocked(const Text: TApiBuffer): string;
var
  Digest, Signature: TApiSensitiveBuffer;
  DigestScope, SignatureScope: TApiSensitiveScope;
  Padding: TPKCS1PaddingInfo;
  Size, Actual: DWORD;
  Encoded: string;
begin
  Digest := nil; Signature := nil; DigestScope := nil; SignatureScope := nil;
  try
    try
      RequireOpen;
{$IFDEF GAME_DEVICE_SECURITY_TESTS}
      ObserveTestStage(CozyText_Security_sign_input_e5ed50c1, Text);
{$ENDIF}
      RequireOpen;
      Digest := Sha256Owned(Text);
      DigestScope := Digest.OpenRead;
{$IFDEF GAME_DEVICE_SECURITY_TESTS}
      ObserveTestStage(CozyText_Security_sign_digest_b3d8d720, DigestScope.Buffer);
{$ENDIF}
      RequireOpen;
      Padding.pszAlgId := PWideChar(Sha256Algorithm);
      Size := 0;
      CheckStatus(NCryptSignHash(FKey, @Padding, PByte(DigestScope.Buffer.Read(0, 32)),
        32, nil, 0, Size, NCryptPKCS1Flag or NCryptSilentFlag), CozyText_Security_Text_e3ba2847);
      if Size <> 256 then
        raise EDeviceSecurity.Create(CozyText_Security_Text_f1ef77c9);
      RequireOpen;
      Signature := TApiSensitiveBuffer.Create(Size);
      SignatureScope := Signature.OpenWrite;
      RequireCngBuffers(DigestScope.Buffer, SignatureScope.Buffer, 32, Size, False);
      Actual := 0;
      CheckStatus(NCryptSignHash(FKey, @Padding, PByte(DigestScope.Buffer.Read(0, 32)),
        32, PByte(SignatureScope.Buffer.Write(0, Size)), Size, Actual,
        NCryptPKCS1Flag or NCryptSilentFlag), CozyText_Security_Text_124d1e4e);
      SignatureScope.Buffer.Completed(Size, Actual);
      if Actual <> Size then
        raise EDeviceSecurity.Create(CozyText_Security_Text_9bb7ab80);
{$IFDEF GAME_DEVICE_SECURITY_TESTS}
      ObserveTestStage(CozyText_Security_sign_signature_a1118132, SignatureScope.Buffer);
{$ENDIF}
      RequireOpen;
      Encoded := Base64Span(SignatureScope.Buffer);
    finally
      { A callback may retain a view but never its scope: all retained views
        are revoked before owned allocations are wiped. One cleanup exception
        cannot skip the remaining owners. Native CNG calls stay synchronous. }
      try SignatureScope.Free;
      finally
        try DigestScope.Free;
        finally
          try Signature.Free; finally Digest.Free; end;
        end;
      end;
    end;
    RequireOpen;
    Result := Encoded; Encoded := '';
  finally WipeText(Encoded); end;
end;

function TDeviceSecurity.SignUnlocked(const Text: string): string;
var Plain: TApiSensitiveBuffer; PlainScope: TApiSensitiveScope;
begin
  if Length(Text) > 1024 * 1024 then
    raise EDeviceSecurity.Create(CozyText_Security_Text_13fb7914);
  Plain := nil; PlainScope := nil;
  try
    RequireOpen;
    Plain := TApiSensitiveBuffer.CreateUtf8(Text);
    PlainScope := Plain.OpenRead;
    Result := SignSpanUnlocked(PlainScope.Buffer);
  finally
    try PlainScope.Free; finally Plain.Free; end;
  end;
end;

function IsUpperHex64(const Value: string): Boolean;
var C: Char;
begin
  Result := Length(Value) = 64;
  if not Result then Exit;
  for C in Value do
    if not CharInSet(C, ['0'..'9', 'A'..'F']) then Exit(False);
end;

function DevicePublicKeyID(const PublicKey: string): string;
var Bytes, Digest: TBytes; Header: TRsaPublicHeader; Encoding: TBase64Encoding;
begin
  if (Length(PublicKey) < 376) or (Length(PublicKey) > 384) then
    raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_PUBLIC_KEY_INVALID_a14478dc);
  Encoding := TBase64Encoding.Create(0);
  try
    Bytes := Encoding.DecodeStringToBytes(PublicKey);
    if (Length(Bytes) < 281) or (Length(Bytes) > 288) or
      (Encoding.EncodeBytesToString(Bytes) <> PublicKey) then
      raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_PUBLIC_KEY_INVALID_a14478dc);
    Move(Bytes[0], Header, SizeOf(Header));
    if (Header.Magic <> RsaPublicMagic) or (Header.BitLength <> 2048) or
      (Header.ModulusBytes <> 256) or (Header.PublicExponentBytes < 1) or
      (Header.PublicExponentBytes > 8) or (Header.Prime1Bytes <> 0) or
      (Header.Prime2Bytes <> 0) or
      (SizeOf(Header) + Header.PublicExponentBytes + Header.ModulusBytes <> DWORD(Length(Bytes))) then
      raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_PUBLIC_KEY_INVALID_a14478dc);
    Digest := Sha256(Bytes);
    Result := Hex(Digest);
  finally
    WipeBytes(Bytes); WipeBytes(Digest); Encoding.Free;
  end;
end;

procedure ValidateHandoff(const Purpose, Role, Claim, ChildKeyID, Nonce: string);
begin
  if ((Purpose <> CozyText_Security_DELEGATION_756578d3) and (Purpose <> CozyText_Security_CLAIM_82bd8309)) or
    ((Role <> 'B') and (Role <> 'O')) or (Claim = '') or
    (Length(Claim) > 16384) or not IsUpperHex64(ChildKeyID) or not IsUpperHex64(Nonce) then
    raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_DELEGATION_INVALID_eaaea118);
end;

function HandoffClaimHash(const Claim: string): string;
var Plain: TApiSensitiveBuffer; Scope: TApiSensitiveScope; Hash: TSHA512Hasher;
begin
  Plain := nil; Scope := nil; Hash := nil;
  try
    Plain := TApiSensitiveBuffer.CreateUtf8(Claim);
    Scope := Plain.OpenRead;
    Hash := TSHA512Hasher.Create;
    if Plain.Capacity <> 0 then Hash.Update(Scope.Buffer.Read(0, Plain.Capacity)^, Plain.Capacity);
    Result := Hash.FinishHex;
  finally
    try Hash.Free;
    finally try Scope.Free; finally Plain.Free; end; end;
  end;
end;

function HandoffCanonicalOwned(const Purpose, Role, ClaimHash, ChildKeyID,
  Nonce: string): TApiSensitiveBuffer;
var Owner: TApiSensitiveBuffer; Scope: TApiSensitiveScope; Offset: NativeUInt;
  procedure AppendASCII(const Part: string);
  var I: Integer;
  begin
    for I := 1 to Length(Part) do
    begin
      if Ord(Part[I]) > 127 then raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_CANONICAL_INVALID_b49f9a7c);
      PByte(Scope.Buffer.Write(Offset, 1))^ := Byte(Ord(Part[I])); Inc(Offset);
    end;
  end;
begin
  { Callers validate the individual fields first. All canonical fields are
    ASCII (the original claim contributes only its SHA-512 digest). }
  Owner := nil; Scope := nil;
  try
    Owner := TApiSensitiveBuffer.Create(Length(CozyText_Security_GAME_HANDOFF_31644f6f) + Length(Purpose) +
      Length(CozyText_Security_V3_c65e5274) + 4 + Length(Role) + Length(ClaimHash) + Length(ChildKeyID) + Length(Nonce));
    Scope := Owner.OpenWrite; Offset := 0;
    AppendASCII(CozyText_Security_GAME_HANDOFF_31644f6f); AppendASCII(Purpose); AppendASCII(CozyText_Security_V3_c65e5274); AppendASCII(#10);
    AppendASCII(Role); AppendASCII(#10); AppendASCII(ClaimHash); AppendASCII(#10);
    AppendASCII(ChildKeyID); AppendASCII(#10); AppendASCII(Nonce);
    if Offset <> Owner.Capacity then raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_CANONICAL_INVALID_b49f9a7c);
    FreeAndNil(Scope);
    Result := Owner; Owner := nil;
  finally try Scope.Free; finally Owner.Free; end; end;
end;

function HandoffCanonical(const Purpose, Role, Claim, ChildKeyID, Nonce: string): string;
var ClaimHash: string;
begin
  { Public compatibility API: returned text belongs to the caller. The direct
    child-signing path below creates no whole Unicode canonical string. }
  ValidateHandoff(Purpose, Role, Claim, ChildKeyID, Nonce);
  ClaimHash := HandoffClaimHash(Claim);
  try
    Result := CozyText_Security_GAME_HANDOFF_31644f6f + Purpose + CozyText_Security_V3_c65e5274 + #10 + Role + #10 +
      ClaimHash + #10 + ChildKeyID + #10 + Nonce;
  finally WipeText(ClaimHash); end;
end;

procedure TDeviceSecurity.AcceptDelegation(const ParentDeviceID, Role, Claim,
  Nonce, Signature: string);
var ClaimHash: string;
begin
  FGate.Enter;
  try
  TMonitor.Enter(FLock);
  try
    RequireOpen;
    if FHandoffAccepted or not IsUpperHex64(ParentDeviceID) or
      (ParentDeviceID = FDeviceID) or (Length(Signature) <> 344) then
      raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_DELEGATION_INVALID_eaaea118);
    ValidateHandoff(CozyText_Security_DELEGATION_756578d3, Role, Claim, FDeviceID, Nonce);
    ClaimHash := HandoffClaimHash(Claim);
    RequireOpen;
    FParentDeviceID := ParentDeviceID;
    FHandoffRole := Role;
    FHandoffClaimHash := ClaimHash;
    FHandoffNonce := Nonce;
    FDelegationSignature := Signature;
    FHandoffAccepted := True;
  finally
    { On success the field owns this intentional live binding. On failure
      there is no field alias and the temporary digest is wiped. }
    if FHandoffAccepted then ClaimHash := '' else WipeText(ClaimHash);
    TMonitor.Exit(FLock);
  end;
  finally FGate.Leave; end;
end;

function TDeviceSecurity.SignHandoffClaim(const Role, Claim: string): string;
var ClaimHash: string; Canonical: TApiSensitiveBuffer; Scope: TApiSensitiveScope;
begin
  FGate.Enter;
  try
  TMonitor.Enter(FLock);
  try
    Canonical := nil; Scope := nil;
    try
      RequireOpen;
      if (Role <> FHandoffRole) or (FHandoffNonce = '') then
        raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_CLAIM_BINDING_INVALID_d299ddd7);
      ValidateHandoff(CozyText_Security_CLAIM_82bd8309, Role, Claim, FDeviceID, FHandoffNonce);
      ClaimHash := HandoffClaimHash(Claim);
      if ClaimHash <> FHandoffClaimHash then
        raise EDeviceSecurity.Create(CozyText_Security_HANDOFF_CLAIM_BINDING_INVALID_d299ddd7);
      Canonical := HandoffCanonicalOwned(CozyText_Security_CLAIM_82bd8309, Role, ClaimHash, FDeviceID, FHandoffNonce);
      Scope := Canonical.OpenRead;
      Result := SignSpanUnlocked(Scope.Buffer);
    finally
      try Scope.Free;
      finally try Canonical.Free; finally WipeText(ClaimHash); end; end;
    end;
  finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TDeviceSecurity.CompleteHandoff;
begin
  FGate.Enter;
  try
  TMonitor.Enter(FLock);
  try
    WipeText(FParentDeviceID); WipeText(FHandoffNonce);
    WipeText(FDelegationSignature); WipeText(FHandoffRole); WipeText(FHandoffClaimHash);
  finally
    TMonitor.Exit(FLock);
  end;
  finally FGate.Leave; end;
end;

procedure TDeviceSecurity.Close;
begin
  if FGate <> nil then FGate.CloseAndWait;
end;

function TDeviceSecurity.Sign(const Text: string): string;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try Result := SignUnlocked(Text); finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TDeviceSecurity.ReadField(Index: Integer): string;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      case Index of
        0: Result := FPublicKeyBlob;
        1: Result := FDeviceID;
        2: Result := FMachineID;
        3: Result := FParentDeviceID;
        4: Result := FHandoffNonce;
        5: Result := FDelegationSignature;
      else raise EDeviceSecurity.Create(CozyText_Security_SECURITY_FIELD_INVALID_b597bac4);
      end;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TDeviceSecurity.GetPublicKeyBlob: string;
begin Result := ReadField(0); end;

function TDeviceSecurity.GetDeviceID: string;
begin Result := ReadField(1); end;

function TDeviceSecurity.GetMachineID: string;
begin Result := ReadField(2); end;

function TDeviceSecurity.GetParentDeviceID: string;
begin Result := ReadField(3); end;

function TDeviceSecurity.GetHandoffNonce: string;
begin Result := ReadField(4); end;

function TDeviceSecurity.GetDelegationSignature: string;
begin Result := ReadField(5); end;

initialization
  { API binding only; original startup actions follow unchanged. }
  BindApiPointer(ApiSlot_NCryptOpenStorageProvider, RequireProcAddressHash64(CozyText_Security_ncrypt_dll_96f4320f, HASH_NCryptOpenStorageProvider));
  BindApiPointer(ApiSlot_NCryptCreatePersistedKey, RequireProcAddressHash64(CozyText_Security_ncrypt_dll_96f4320f, HASH_NCryptCreatePersistedKey));
  BindApiPointer(ApiSlot_NCryptSetProperty, RequireProcAddressHash64(CozyText_Security_ncrypt_dll_96f4320f, HASH_NCryptSetProperty));
  BindApiPointer(ApiSlot_NCryptFinalizeKey, RequireProcAddressHash64(CozyText_Security_ncrypt_dll_96f4320f, HASH_NCryptFinalizeKey));
  BindApiPointer(ApiSlot_NCryptExportKey, RequireProcAddressHash64(CozyText_Security_ncrypt_dll_96f4320f, HASH_NCryptExportKey));
  BindApiPointer(ApiSlot_NCryptSignHash, RequireProcAddressHash64(CozyText_Security_ncrypt_dll_96f4320f, HASH_NCryptSignHash));
  BindApiPointer(ApiSlot_NCryptFreeObject, RequireProcAddressHash64(CozyText_Security_ncrypt_dll_96f4320f, HASH_NCryptFreeObject));
  BindApiPointer(ApiSlot_BCryptOpenAlgorithmProvider, RequireProcAddressHash64(CozyText_Security_bcrypt_dll_5d33225d, HASH_BCryptOpenAlgorithmProvider));
  BindApiPointer(ApiSlot_BCryptCreateHash, RequireProcAddressHash64(CozyText_Security_bcrypt_dll_5d33225d, HASH_BCryptCreateHash));
  BindApiPointer(ApiSlot_BCryptHashData, RequireProcAddressHash64(CozyText_Security_bcrypt_dll_5d33225d, HASH_BCryptHashData));
  BindApiPointer(ApiSlot_BCryptFinishHash, RequireProcAddressHash64(CozyText_Security_bcrypt_dll_5d33225d, HASH_BCryptFinishHash));
  BindApiPointer(ApiSlot_BCryptDestroyHash, RequireProcAddressHash64(CozyText_Security_bcrypt_dll_5d33225d, HASH_BCryptDestroyHash));
  BindApiPointer(ApiSlot_BCryptCloseAlgorithmProvider, RequireProcAddressHash64(CozyText_Security_bcrypt_dll_5d33225d, HASH_BCryptCloseAlgorithmProvider));

end.
