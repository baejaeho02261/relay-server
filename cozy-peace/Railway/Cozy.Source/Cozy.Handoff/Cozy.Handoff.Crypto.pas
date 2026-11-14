unit Cozy.Handoff.Crypto;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$ALIGN 8}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff,
 System.SysUtils, System.SyncObjs, Cozy.Lifetime;

type
  { One ephemeral RSA wrapping key per launch. The key is never exported;
    the atomic single-use decrypt gate is consumed even for malformed envelopes.
    Owner must join every caller before destroying this object. Inputs are
    borrowed/immutable until return; the returned plaintext array belongs to
    the caller and must be wiped after consumption. The optional cancellation
    callback is synchronous and must not Close/Free this admitted cipher. }
  THandoffCipher = class
  private
    FGate: TGameCallGate;
    FAlgorithm, FKey: NativeUInt;
    FConsumed: Integer;
    procedure RequireActive(const IsCancelled: TFunc<Boolean>);
  public
    constructor Create;
    procedure Close;
    destructor Destroy; override;
    function PublicBlob: TBytes;
    function Decrypt(const Envelope, AuthenticatedTranscript: TBytes;
      const IsCancelled: TFunc<Boolean> = nil): TBytes;
    class function Encrypt(const PublicBlob, Plain,
      AuthenticatedTranscript: TBytes;
      const IsCancelled: TFunc<Boolean> = nil): TBytes; static;
  end;

{ Bounded single-shot authenticated decryption using the same existing CNG
  bindings as process handoff. No plaintext escapes before tag verification. }
function HandoffDecryptAes256Gcm(const Secret, Nonce, Tag, AAD,
  Cipher: TBytes; MaximumPlainBytes: Integer;
  const IsCancelled: TFunc<Boolean> = nil): TBytes;
function HandoffRandomNonce: string;

implementation

uses Winapi.Windows, Cozy.WinApi, Cozy.Security, Cozy.Api.Pointer,
  Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Handoff.Kdf, Cozy.Api.Contracts;

type
  TCngHandle = NativeUInt;
  TCngStatus = LongInt;
  TOaepPaddingInfo = TGameOaepPaddingInfo;
  TAuthenticatedCipherInfo = TGameAuthenticatedCipherInfo;
  TEnvelopeHeader = packed record
    Magic: UInt64;
    Version, CipherBytes: DWORD;
    Nonce: array[0..11] of Byte;
    WrappedKey: array[0..255] of Byte;
    Tag: array[0..15] of Byte;
  end;
  TRsaPublicHeader = TGameRsaPublicHeader;

const
  EnvelopeMagic: UInt64 = $33564F444E414847;
  EnvelopeVersion = 3;
  MaxPlain = 65536;
  OaepPaddingFlag = 4;
  SystemPreferredRng = 2;
  GcmMode = CozyText_Handoff_Crypto_ChainingModeGCM_c260fccf;
  HandoffProtocolMarker: AnsiString = CozyText_Handoff_Crypto_GAME_HANDOFF_V3_069e73ba;

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

type
  TResolved_BCryptGenerateKeyPair = function(Algorithm: TCngHandle; out Key: TCngHandle; Bits, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptGenerateKeyPair: TEncodedApiPointer;

type
  TResolved_BCryptFinalizeKeyPair = function(Key: TCngHandle; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptFinalizeKeyPair: TEncodedApiPointer;

type
  TResolved_BCryptExportKey = function(Key, ExportKey: TCngHandle; BlobType: PWideChar; Output: PByte; OutputSize: DWORD; out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptExportKey: TEncodedApiPointer;

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

function BCryptGenerateKeyPair(Algorithm: TCngHandle; out Key: TCngHandle; Bits, Flags: DWORD): TCngStatus; stdcall;
var ApiTarget: TResolved_BCryptGenerateKeyPair;
begin
  ApiTarget := TResolved_BCryptGenerateKeyPair(DecodeApiPointer(ApiSlot_BCryptGenerateKeyPair));
  Result := ApiTarget(Algorithm, Key, Bits, Flags);
end;

function BCryptFinalizeKeyPair(Key: TCngHandle; Flags: DWORD): TCngStatus; stdcall;
var ApiTarget: TResolved_BCryptFinalizeKeyPair;
begin
  ApiTarget := TResolved_BCryptFinalizeKeyPair(DecodeApiPointer(ApiSlot_BCryptFinalizeKeyPair));
  Result := ApiTarget(Key, Flags);
end;

function BCryptExportKey(Key, ExportKey: TCngHandle; BlobType: PWideChar; Output: PByte; OutputSize: DWORD; out ActualSize: DWORD; Flags: DWORD): TCngStatus; stdcall;
var ApiTarget: TResolved_BCryptExportKey;
begin
  ApiTarget := TResolved_BCryptExportKey(DecodeApiPointer(ApiSlot_BCryptExportKey));
  Result := ApiTarget(Key, ExportKey, BlobType, Output, OutputSize, ActualSize, Flags);
end;

procedure Check(Status: TCngStatus);
begin
  if Status <> 0 then raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_FAILED_ec741754);
end;

procedure ValidateInput(const Plain, AAD: TBytes);
begin
  if (Length(Plain) = 0) or (Length(Plain) > MaxPlain) or
    (Length(AAD) = 0) or (Length(AAD) > 8192) then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_SIZE_INVALID_3e917e7c);
end;

procedure ValidatePublic(const Blob: TBytes);
var Header: TRsaPublicHeader;
begin
  if (Length(Blob) < 281) or (Length(Blob) > 288) then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_KEY_INVALID_14e8e72e);
  Move(Blob[0], Header, SizeOf(Header));
  if (Header.Magic <> $31415352) or (Header.BitLength <> 2048) or
    (Header.ModulusBytes <> 256) or (Header.Prime1Bytes <> 0) or
    (Header.Prime2Bytes <> 0) or (Header.PublicExponentBytes < 1) or
    (Header.PublicExponentBytes > 8) or
    (DWORD(Length(Blob)) <> SizeOf(Header) + Header.PublicExponentBytes + 256) then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_KEY_INVALID_14e8e72e);
end;

procedure InitOaep(out Padding: TOaepPaddingInfo);
begin
  FillChar(Padding, SizeOf(Padding), 0);
  Padding.Algorithm := CozyText_Handoff_Crypto_SHA256_66e684b3;
  Padding.LabelBytes := PByte(PAnsiChar(HandoffProtocolMarker));
  Padding.LabelSize := Length(HandoffProtocolMarker);
end;

procedure InitAuth(out Info: TAuthenticatedCipherInfo;
  var Header: TEnvelopeHeader; const AAD: TBytes);
begin
  FillChar(Info, SizeOf(Info), 0);
  Info.Size := SizeOf(Info); Info.Version := 1;
  Info.Nonce := @Header.Nonce[0]; Info.NonceSize := SizeOf(Header.Nonce);
  Info.Tag := @Header.Tag[0]; Info.TagSize := SizeOf(Header.Tag);
  Info.AuthData := @AAD[0]; Info.AuthDataSize := Length(AAD);
end;

{ The callback is synchronous and may be called more than once. Its owner
  stays alive until return; it must not call Close/Free on this admitted cipher.
  CNG calls cannot be forcibly interrupted: cancellation is checked between
  calls and again before any plaintext result is published. }
procedure CheckCancellation(const IsCancelled: TFunc<Boolean>);
begin
  if Assigned(IsCancelled) and IsCancelled() then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_CANCELLED_3b14ba85);
end;

procedure THandoffCipher.RequireActive(const IsCancelled: TFunc<Boolean>);
begin
  CheckCancellation(IsCancelled);
  if FGate.IsClosing then raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_CANCELLED_3b14ba85);
end;

function OwnBytes(const Bytes: TBytes): TApiSensitiveBuffer;
var Scope: TApiSensitiveScope;
begin
  Result := TApiSensitiveBuffer.Create(Length(Bytes));
  try
    Scope := Result.OpenWrite;
    try
      if Length(Bytes) <> 0 then
        Move(Bytes[0], Scope.Buffer.Write(0, Length(Bytes))^, Length(Bytes));
    finally Scope.Free; end;
  except
    Result.Free; raise;
  end;
end;

function PublishPlain(Owner: TApiSensitiveBuffer; Count: Integer): TBytes;
var Scope: TApiSensitiveScope;
begin
  Result := nil;
  { Caller invokes this only after tag, actual-length and cancellation checks.
    This is the single outgoing caller-owned copy; the owner is wiped below. }
  Scope := Owner.OpenRead;
  try
    try
      SetLength(Result, Count);
      if Count <> 0 then Move(Scope.Buffer.Read(0, Count)^, Result[0], Count);
    except WipeBytes(Result); raise; end;
  finally Scope.Free; end;
end;

procedure OpenAes(const Secret: TApiBuffer; out Algorithm, Key: TCngHandle);
begin
  Algorithm := 0; Key := 0;
  Secret.Read(0, 32);
  Check(BCryptOpenAlgorithmProvider(Algorithm, CozyText_Handoff_Crypto_AES_fc846d7d, nil, 0));
  Check(BCryptSetProperty(Algorithm, CozyText_Handoff_Crypto_ChainingMode_b7a55120, PByte(PWideChar(GcmMode)),
    (Length(GcmMode) + 1) * SizeOf(WideChar), 0));
  Check(BCryptGenerateSymmetricKey(Algorithm, Key, nil, 0,
    Secret.Read(0, 32), 32, 0));
end;

constructor THandoffCipher.Create;
begin
  inherited Create;
  FGate := TGameCallGate.Create;
  if not Win64ApiLayoutValid or (SizeOf(TEnvelopeHeader) <> 300) then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_ABI_INVALID_08de973d);
  Check(BCryptOpenAlgorithmProvider(FAlgorithm, CozyText_Handoff_Crypto_RSA_f7d17c25, nil, 0));
  Check(BCryptGenerateKeyPair(FAlgorithm, FKey, 2048, 0));
  Check(BCryptFinalizeKeyPair(FKey, 0));
end;

destructor THandoffCipher.Destroy;
begin
  Close;
  if FKey <> 0 then BCryptDestroyKey(FKey);
  if FAlgorithm <> 0 then BCryptCloseAlgorithmProvider(FAlgorithm, 0);
  FGate.Free;
  inherited Destroy;
end;

function THandoffCipher.PublicBlob: TBytes;
var Size, Actual: DWORD;
begin
  FGate.Enter;
  try
  Check(BCryptExportKey(FKey, 0, CozyText_Handoff_Crypto_RSAPUBLICBLOB_1d6cf82c, nil, 0, Size, 0));
  if (Size < 281) or (Size > 288) then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_KEY_INVALID_14e8e72e);
  SetLength(Result, Size);
  try
    Check(BCryptExportKey(FKey, 0, CozyText_Handoff_Crypto_RSAPUBLICBLOB_1d6cf82c, @Result[0], Size, Actual, 0));
    if Actual <> Size then raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_KEY_INVALID_14e8e72e);
    ValidatePublic(Result);
  except
    WipeBytes(Result); raise;
  end;
  finally FGate.Leave; end;
end;

class function THandoffCipher.Encrypt(const PublicBlob, Plain,
  AuthenticatedTranscript: TBytes; const IsCancelled: TFunc<Boolean>): TBytes;
var RsaAlgorithm, RsaKey, AesAlgorithm, AesKey: TCngHandle;
  Secret, Seed: TApiSensitiveBuffer; Scope: TApiSensitiveScope;
  Header: TEnvelopeHeader; Padding: TOaepPaddingInfo;
  Info: TAuthenticatedCipherInfo; Actual: DWORD;
begin
  Result := nil; RsaAlgorithm := 0; RsaKey := 0; AesAlgorithm := 0; AesKey := 0;
  Secret := nil; Seed := nil;
  ValidateInput(Plain, AuthenticatedTranscript); ValidatePublic(PublicBlob);
  FillChar(Header, SizeOf(Header), 0); FillChar(Info, SizeOf(Info), 0);
  try
    try
      CheckCancellation(IsCancelled);
      Seed := TApiSensitiveBuffer.Create(32);
      Scope := Seed.OpenWrite;
      try Check(BCryptGenRandom(0, Scope.Buffer.Write(0, 32), 32, SystemPreferredRng));
      finally Scope.Free; end;
      Scope := Seed.OpenRead;
      try Secret := DeriveHandoffContentKeyOwned(Scope.Buffer, AuthenticatedTranscript);
      finally Scope.Free; end;
      FreeAndNil(Seed);
      CheckCancellation(IsCancelled);
      Check(BCryptGenRandom(0, @Header.Nonce[0], SizeOf(Header.Nonce), SystemPreferredRng));
      Check(BCryptOpenAlgorithmProvider(RsaAlgorithm, CozyText_Handoff_Crypto_RSA_f7d17c25, nil, 0));
      Check(BCryptImportKeyPair(RsaAlgorithm, 0, CozyText_Handoff_Crypto_RSAPUBLICBLOB_1d6cf82c, RsaKey,
        @PublicBlob[0], Length(PublicBlob), 0));
      InitOaep(Padding);
      Scope := Secret.OpenRead;
      try
        Check(BCryptEncrypt(RsaKey, Scope.Buffer.Read(0, 32), 32, @Padding,
          nil, 0, @Header.WrappedKey[0], SizeOf(Header.WrappedKey), Actual, OaepPaddingFlag));
        if Actual <> SizeOf(Header.WrappedKey) then
          raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_FAILED_ec741754);
        OpenAes(Scope.Buffer, AesAlgorithm, AesKey);
      finally Scope.Free; end;
      FreeAndNil(Secret);
      CheckCancellation(IsCancelled);
      Header.Magic := EnvelopeMagic; Header.Version := EnvelopeVersion;
      Header.CipherBytes := Length(Plain);
      InitAuth(Info, Header, AuthenticatedTranscript);
      SetLength(Result, SizeOf(Header) + Length(Plain));
      { Plain belongs to the synchronous caller; do not create or erase aliases
        of its array. A/B/O caller wipes the one input after this call. }
      Check(BCryptEncrypt(AesKey, @Plain[0], Length(Plain), @Info, nil, 0,
        @Result[SizeOf(Header)], Length(Plain), Actual, 0));
      if Actual <> DWORD(Length(Plain)) then raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_FAILED_ec741754);
      CheckCancellation(IsCancelled);
      Move(Header, Result[0], SizeOf(Header));
    except
      WipeBytes(Result); raise;
    end;
  finally
    Secret.Free; Seed.Free;
    FillChar(Header, SizeOf(Header), 0); FillChar(Info, SizeOf(Info), 0);
    FillChar(Padding, SizeOf(Padding), 0);
    if AesKey <> 0 then BCryptDestroyKey(AesKey);
    if AesAlgorithm <> 0 then BCryptCloseAlgorithmProvider(AesAlgorithm, 0);
    if RsaKey <> 0 then BCryptDestroyKey(RsaKey);
    if RsaAlgorithm <> 0 then BCryptCloseAlgorithmProvider(RsaAlgorithm, 0);
  end;
end;

function THandoffCipher.Decrypt(const Envelope, AuthenticatedTranscript: TBytes;
  const IsCancelled: TFunc<Boolean>): TBytes;
var AesAlgorithm, AesKey: TCngHandle;
  Secret, Plain: TApiSensitiveBuffer; Scope: TApiSensitiveScope;
  Header: TEnvelopeHeader; Padding: TOaepPaddingInfo;
  Info: TAuthenticatedCipherInfo; Actual: DWORD;
begin
  Result := nil;
  FGate.Enter;
  try
    { A malformed or cancelled first attempt also permanently consumes this
      wrapping key; an admitted competing call cannot retry after failure. }
    if TInterlocked.CompareExchange(FConsumed, 1, 0) <> 0 then
      raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_ALREADY_CONSUMED_971ef676);
    RequireActive(IsCancelled);
    if (Length(Envelope) <= SizeOf(Header)) or
      (Length(Envelope) > MaxPlain + SizeOf(Header)) or
      (Length(AuthenticatedTranscript) = 0) or (Length(AuthenticatedTranscript) > 8192) then
      raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_SIZE_INVALID_3e917e7c);
    AesAlgorithm := 0; AesKey := 0; Secret := nil; Plain := nil;
    FillChar(Header, SizeOf(Header), 0); FillChar(Info, SizeOf(Info), 0);
    FillChar(Padding, SizeOf(Padding), 0);
    try
      try
        Move(Envelope[0], Header, SizeOf(Header));
        if (Header.Magic <> EnvelopeMagic) or (Header.Version <> EnvelopeVersion) or
          (Header.CipherBytes <> DWORD(Length(Envelope) - SizeOf(Header))) then
          raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_HEADER_INVALID_0e24d39c);
        { RSA may write up to its modulus size. The complete allocation is
          dedicated and wiped, including bytes beyond the32-byte content key. }
        Secret := TApiSensitiveBuffer.Create(256); InitOaep(Padding);
        Scope := Secret.OpenWrite;
        try
          Check(BCryptDecrypt(FKey, @Header.WrappedKey[0], SizeOf(Header.WrappedKey),
            @Padding, nil, 0, Scope.Buffer.Write(0, 256), 256, Actual, OaepPaddingFlag));
          if Actual <> 32 then raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_KEY_INVALID_14e8e72e);
          OpenAes(Scope.Buffer, AesAlgorithm, AesKey);
        finally Scope.Free; end;
        FreeAndNil(Secret);
        RequireActive(IsCancelled);
        InitAuth(Info, Header, AuthenticatedTranscript);
        Plain := TApiSensitiveBuffer.Create(Header.CipherBytes);
        Scope := Plain.OpenWrite;
        try
          Check(BCryptDecrypt(AesKey, @Envelope[SizeOf(Header)], Header.CipherBytes,
            @Info, nil, 0, Scope.Buffer.Write(0, Header.CipherBytes), Header.CipherBytes, Actual, 0));
          if Actual <> Header.CipherBytes then raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_FAILED_ec741754);
        finally Scope.Free; end;
        RequireActive(IsCancelled);
        Result := PublishPlain(Plain, Header.CipherBytes);
        RequireActive(IsCancelled);
      except
        WipeBytes(Result); raise;
      end;
    finally
      Secret.Free; Plain.Free;
      FillChar(Header, SizeOf(Header), 0); FillChar(Info, SizeOf(Info), 0);
      FillChar(Padding, SizeOf(Padding), 0);
      if AesKey <> 0 then BCryptDestroyKey(AesKey);
      if AesAlgorithm <> 0 then BCryptCloseAlgorithmProvider(AesAlgorithm, 0);
    end;
  finally FGate.Leave; end;
end;

function HandoffDecryptAes256Gcm(const Secret, Nonce, Tag, AAD,
  Cipher: TBytes; MaximumPlainBytes: Integer;
  const IsCancelled: TFunc<Boolean>): TBytes;
var Algorithm, Key: TCngHandle; Info: TAuthenticatedCipherInfo;
  KeyCopy, NonceCopy, TagCopy, AuthCopy, Plain: TApiSensitiveBuffer;
  KeyScope, NonceScope, TagScope, AuthScope, PlainScope: TApiSensitiveScope;
  Actual: DWORD;
begin
  Result := nil;
  if (Length(Secret) <> 32) or (Length(Nonce) <> 12) or
    (Length(Tag) <> 16) or (Length(AAD) < 1) or (Length(AAD) > 8192) or
    (MaximumPlainBytes < 1) or (MaximumPlainBytes > MaxPlain) or
    (Length(Cipher) < 1) or (Length(Cipher) > MaximumPlainBytes) then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_PROTECTION_CIPHER_INPUT_INVALID_8007aa94);
  if not Win64ApiLayoutValid then
    raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_ABI_INVALID_08de973d);
  Algorithm := 0; Key := 0;
  KeyCopy := nil; NonceCopy := nil; TagCopy := nil; AuthCopy := nil; Plain := nil;
  KeyScope := nil; NonceScope := nil; TagScope := nil; AuthScope := nil; PlainScope := nil;
  FillChar(Info, SizeOf(Info), 0);
  try
    try
      CheckCancellation(IsCancelled);
      KeyCopy := OwnBytes(Secret);
      KeyScope := KeyCopy.OpenRead;
      OpenAes(KeyScope.Buffer, Algorithm, Key);
      FreeAndNil(KeyScope); FreeAndNil(KeyCopy);
      NonceCopy := OwnBytes(Nonce); TagCopy := OwnBytes(Tag); AuthCopy := OwnBytes(AAD);
      NonceScope := NonceCopy.OpenRead; TagScope := TagCopy.OpenRead; AuthScope := AuthCopy.OpenRead;
      CheckCancellation(IsCancelled);
      { Same88-byte Win64 single-shot CNG structure, with scoped owner pointers. }
      Info.Size := SizeOf(Info); Info.Version := 1;
      Info.Nonce := NonceScope.Buffer.Read(0, 12); Info.NonceSize := 12;
      Info.Tag := TagScope.Buffer.Read(0, 16); Info.TagSize := 16;
      Info.AuthData := AuthScope.Buffer.Read(0, Length(AAD)); Info.AuthDataSize := Length(AAD);
      Plain := TApiSensitiveBuffer.Create(Length(Cipher)); PlainScope := Plain.OpenWrite;
      Actual := 0;
      Check(BCryptDecrypt(Key, @Cipher[0], Length(Cipher), @Info, nil, 0,
        PlainScope.Buffer.Write(0, Length(Cipher)), Length(Cipher), Actual, 0));
      if Actual <> DWORD(Length(Cipher)) then
        raise EDeviceSecurity.Create(CozyText_Handoff_Crypto_HANDOFF_CIPHER_FAILED_ec741754);
      FreeAndNil(PlainScope);
      CheckCancellation(IsCancelled);
      Result := PublishPlain(Plain, Length(Cipher));
      CheckCancellation(IsCancelled);
    except WipeBytes(Result); raise; end;
  finally
    KeyScope.Free; NonceScope.Free; TagScope.Free; AuthScope.Free; PlainScope.Free;
    KeyCopy.Free; NonceCopy.Free; TagCopy.Free; AuthCopy.Free; Plain.Free;
    FillChar(Info, SizeOf(Info), 0);
    if Key <> 0 then BCryptDestroyKey(Key);
    if Algorithm <> 0 then BCryptCloseAlgorithmProvider(Algorithm, 0);
  end;
end;

procedure THandoffCipher.Close;
begin
  if FGate <> nil then FGate.CloseAndWait;
end;

function HandoffRandomNonce: string;
const Digits: string = CozyText_Handoff_Crypto_0123456789ABCDEF_03b40e34;
var Bytes: TBytes; I: Integer;
begin
  SetLength(Bytes, 32);
  try
    Check(BCryptGenRandom(0, @Bytes[0], Length(Bytes), SystemPreferredRng));
    SetLength(Result, 64);
    for I := 0 to 31 do
    begin
      Result[I * 2 + 1] := Digits[(Bytes[I] shr 4) + 1];
      Result[I * 2 + 2] := Digits[(Bytes[I] and $F) + 1];
    end;
  finally WipeBytes(Bytes); end;
end;

initialization
  BindApiPointer(ApiSlot_BCryptOpenAlgorithmProvider, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptOpenAlgorithmProvider));
  BindApiPointer(ApiSlot_BCryptCloseAlgorithmProvider, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptCloseAlgorithmProvider));
  BindApiPointer(ApiSlot_BCryptSetProperty, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptSetProperty));
  BindApiPointer(ApiSlot_BCryptImportKeyPair, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptImportKeyPair));
  BindApiPointer(ApiSlot_BCryptGenerateSymmetricKey, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptGenerateSymmetricKey));
  BindApiPointer(ApiSlot_BCryptDestroyKey, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptDestroyKey));
  BindApiPointer(ApiSlot_BCryptGenRandom, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptGenRandom));
  BindApiPointer(ApiSlot_BCryptEncrypt, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptEncrypt));
  BindApiPointer(ApiSlot_BCryptDecrypt, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptDecrypt));
  BindApiPointer(ApiSlot_BCryptGenerateKeyPair, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptGenerateKeyPair));
  BindApiPointer(ApiSlot_BCryptFinalizeKeyPair, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptFinalizeKeyPair));
  BindApiPointer(ApiSlot_BCryptExportKey, RequireProcAddressHash64(CozyText_Handoff_Crypto_bcrypt_dll_b261e2e6, HASH_BCryptExportKey));

end.
