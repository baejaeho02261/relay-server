unit Cozy.IssuedA;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}{$J-}{$ALIGN 8}
{$IFDEF GAME_APPLICATION_BUILD}
  {$IFDEF GAME_ISSUED_A_TESTS}
    {$MESSAGE FATAL 'Issuer verification test trust is forbidden in application builds.'}
  {$ENDIF}
{$ENDIF}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Application,

  Winapi.Windows, System.SysUtils
{$IFDEF GAME_ISSUED_A_TESTS}
  , System.Classes
{$ENDIF}
  ;

type
  EIssuedA = class(Exception);

{ Reads from the already pinned regular-file handle and restores its position.
  Authenticates the exact template and public configuration against the public
  key compiled into A. No key from the file trailer establishes trust.
  This application signature is separate from Windows Authenticode. }
function ReadVerifiedIssuedAConfig(Handle: THandle; FileSize: UInt64): TBytes;
{$IFDEF GAME_ISSUED_A_TESTS}
function VerifyIssuedATestStream(Stream: TStream; FileSize: UInt64;
  const Anchor: TBytes): TBytes;
{$ENDIF}

implementation

uses Cozy.Clock,
{$IFNDEF GAME_ISSUED_A_TESTS}
  System.Classes,
{$ENDIF}
  Cozy.Security, Cozy.Hashes.SHA512, Cozy.WinApi,
  Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer;

const
  IssuedHeaderBytes = 184;
  IssuedSignatureBytes = 256;
  IssuedFooterBytes = 13;
  IssuedTailBytes = IssuedHeaderBytes + IssuedSignatureBytes + IssuedFooterBytes;
  IssuedAnchorBytes = 331;
  IssuedTrustResourceID = 311;
  IssuedPublicBlobBytes = 283;
  IssuedTemplateMaximum = 64 * 1024 * 1024;
  IssuedConfigMaximum = 8192;
  IssuedVerificationBudgetMS = 30000;
  IssuedPKCS1Flag = $00000002;
  IssuedDomain: AnsiString = CozyText_IssuedA_COZY_ISSUED_A_V1_669c51cd;
  IssuedFooter: AnsiString = CozyText_IssuedA_COZYA4SIGNED_bb9b7083;
  IssuedAnchorMagic: AnsiString = CozyText_IssuedA_COZYAISSUERKEY1_1e39b711;

type
  TCngHandle = NativeUInt;
  TCngStatus = LongInt;
  TResolved_BCryptOpenAlgorithmProvider = function(out Algorithm: TCngHandle;
    AlgorithmName, ImplementationName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
  TResolved_BCryptImportKeyPair = function(Algorithm, ImportKey: TCngHandle;
    BlobType: PWideChar; out Key: TCngHandle; Input: PByte;
    InputSize, Flags: DWORD): TCngStatus; stdcall;
  TResolved_BCryptVerifySignature = function(Key: TCngHandle; Padding: Pointer;
    Hash: PByte; HashSize: DWORD; Signature: PByte;
    SignatureSize, Flags: DWORD): TCngStatus; stdcall;
  TResolved_BCryptDestroyKey = function(Key: TCngHandle): TCngStatus; stdcall;
  TResolved_BCryptCloseAlgorithmProvider = function(Algorithm: TCngHandle;
    Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptOpenAlgorithmProvider, ApiSlot_BCryptImportKeyPair, ApiSlot_BCryptVerifySignature, ApiSlot_BCryptDestroyKey, ApiSlot_BCryptCloseAlgorithmProvider: TEncodedApiPointer;

procedure Invalid;
begin
  raise EIssuedA.Create(CozyText_IssuedA_ISSUED_A_SIGNATURE_INVALID_29768089);
end;


procedure CheckDeadline(Started: UInt64);
begin
  if CozyTick - Started >= IssuedVerificationBudgetMS then
    raise EIssuedA.Create(CozyText_IssuedA_ISSUED_A_VERIFICATION_DEADLINE_f6f73248);
end;

function U32(const Data: TBytes; Offset: Integer): Cardinal;
begin
  if (Offset < 0) or (Offset > Length(Data) - 4) then Invalid;
  Result := Cardinal(Data[Offset]) or (Cardinal(Data[Offset + 1]) shl 8) or
    (Cardinal(Data[Offset + 2]) shl 16) or (Cardinal(Data[Offset + 3]) shl 24);
end;

function SameBytes(const Left: TBytes; LeftOffset: Integer;
  const Right: TBytes; RightOffset, Count: Integer): Boolean;
var I: Integer; Difference: Byte;
begin
  Result := False;
  if (Count < 0) or (LeftOffset < 0) or (RightOffset < 0) or
    (Count > Length(Left)) or (Count > Length(Right)) or
    (LeftOffset > Length(Left) - Count) or
    (RightOffset > Length(Right) - Count) then Exit;
  Difference := 0;
  for I := 0 to Count - 1 do
    Difference := Difference or (Left[LeftOffset + I] xor Right[RightOffset + I]);
  Result := Difference = 0;
end;

function ASCIIEquals(const Data: TBytes; Offset: Integer;
  const Expected: AnsiString): Boolean;
var I: Integer;
begin
  Result := False;
  if (Offset < 0) or (Length(Expected) > Length(Data)) or
    (Offset > Length(Data) - Length(Expected)) then Exit;
  for I := 1 to Length(Expected) do
    if Data[Offset + I - 1] <> Byte(Expected[I]) then Exit;
  Result := True;
end;

function ReadExtent(Stream: TStream; Offset: UInt64; Count: Integer;
  Total: UInt64): TBytes;
begin
  Result := nil;
  if (Count < 1) or (Offset > Total) or (UInt64(Count) > Total - Offset) or
    (Offset > UInt64(High(Int64))) then Invalid;
  Stream.Position := Int64(Offset);
  SetLength(Result, Count);
  try
    Stream.ReadBuffer(Result[0], Count);
  except
    WipeBytes(Result);
    raise;
  end;
end;

function HashExtent(Stream: TStream; Count: Cardinal; Started: UInt64): TBytes;
var Hasher: TSHA512Hasher; Buffer: TBytes; Remaining, Part: Cardinal;
begin
  Result := nil;
  Hasher := TSHA512Hasher.Create;
  try
    SetLength(Buffer, 65536);
    Stream.Position := 0;
    Remaining := Count;
    while Remaining <> 0 do
    begin
      CheckDeadline(Started);
      Part := Remaining;
      if Part > Cardinal(Length(Buffer)) then Part := Cardinal(Length(Buffer));
      Stream.ReadBuffer(Buffer[0], Integer(Part));
      Hasher.Update(Buffer[0], Part);
      Dec(Remaining, Part);
    end;
    CheckDeadline(Started);
    Result := Hasher.FinishBytes;
  finally
    WipeBytes(Buffer);
    Hasher.Free;
  end;
end;

procedure VerifyHeader(const Header, Signature, Anchor: TBytes);
var Blob, KeyID, Digest: TBytes; Algorithm, Key: TCngHandle;
  Padding: TGamePkcs1PaddingInfo;
  OpenAlgorithm: TResolved_BCryptOpenAlgorithmProvider;
  ImportKey: TResolved_BCryptImportKeyPair;
  VerifySignature: TResolved_BCryptVerifySignature;
  DestroyKey: TResolved_BCryptDestroyKey;
  CloseAlgorithm: TResolved_BCryptCloseAlgorithmProvider;
begin
  Algorithm := 0;
  Key := 0;
  if (Length(Anchor) <> IssuedAnchorBytes) or
    not ASCIIEquals(Anchor, 0, IssuedAnchorMagic) or
    (Length(Header) <> IssuedHeaderBytes) or
    (Length(Signature) <> IssuedSignatureBytes) then Invalid;
  Blob := Copy(Anchor, 48, IssuedPublicBlobBytes);
  try
    { BCRYPT_RSAKEY_BLOB header DWORDs are little-endian, exponent/modulus
      are big-endian. Only RSA-2048, exponent 65537 is this format's contract. }
    if (U32(Blob, 0) <> $31415352) or (U32(Blob, 4) <> 2048) or
      (U32(Blob, 8) <> 3) or (U32(Blob, 12) <> 256) or
      (U32(Blob, 16) <> 0) or (U32(Blob, 20) <> 0) or
      (Blob[24] <> 1) or (Blob[25] <> 0) or (Blob[26] <> 1) or
      ((Blob[27] and $80) = 0) or ((Blob[282] and 1) = 0) then Invalid;
    KeyID := DeviceSHA256(Blob);
    if not SameBytes(KeyID, 0, Anchor, 16, 32) or
      not SameBytes(KeyID, 0, Header, 24, 32) then Invalid;
    Digest := DeviceSHA256(Header);
    if Length(Digest) <> 32 then Invalid;
    OpenAlgorithm := TResolved_BCryptOpenAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptOpenAlgorithmProvider));
    ImportKey := TResolved_BCryptImportKeyPair(DecodeApiPointer(ApiSlot_BCryptImportKeyPair));
    VerifySignature := TResolved_BCryptVerifySignature(DecodeApiPointer(ApiSlot_BCryptVerifySignature));
    DestroyKey := TResolved_BCryptDestroyKey(DecodeApiPointer(ApiSlot_BCryptDestroyKey));
    CloseAlgorithm := TResolved_BCryptCloseAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptCloseAlgorithmProvider));
    try
      if OpenAlgorithm(Algorithm, CozyText_IssuedA_RSA_ec1683d6, nil, 0) < 0 then Invalid;
      if ImportKey(Algorithm, 0, CozyText_IssuedA_RSAPUBLICBLOB_4c90646b, Key, @Blob[0], Length(Blob), 0) < 0 then Invalid;
      Padding.pszAlgId := CozyText_IssuedA_SHA256_452fedff;
      { CNG consumes the RSA signature in the standard unsigned big-endian
        representation produced by Node/OpenSSL. Do not reverse these bytes. }
      if VerifySignature(Key, @Padding, @Digest[0], Length(Digest),
        @Signature[0], Length(Signature), IssuedPKCS1Flag) < 0 then Invalid;
    finally
      if Key <> 0 then DestroyKey(Key);
      if Algorithm <> 0 then CloseAlgorithm(Algorithm, 0);
    end;
  finally
    WipeBytes(Blob);
    WipeBytes(KeyID);
    WipeBytes(Digest);
  end;
end;

function VerifyStream(Stream: TStream; FileSize: UInt64;
  const Anchor: TBytes): TBytes;
var Tail, Header, Signature, Config, TemplateHash, ConfigHash: TBytes;
  SavedPosition: Int64; TemplateBytes, ConfigBytes: Cardinal;
  Started: UInt64; Hasher: TSHA512Hasher;
begin
  Result := nil;
  if Stream = nil then Invalid;
  Started := CozyTick;
  SavedPosition := Stream.Position;
  try
    if (FileSize <= IssuedTailBytes) or
      (FileSize > UInt64(IssuedTemplateMaximum)) or
      (Stream.Size < 0) or (UInt64(Stream.Size) <> FileSize) then Invalid;
    Tail := ReadExtent(Stream, FileSize - IssuedTailBytes, IssuedTailBytes, FileSize);
    if not ASCIIEquals(Tail, 0, IssuedDomain) or
      not ASCIIEquals(Tail, IssuedHeaderBytes + IssuedSignatureBytes, IssuedFooter) then Invalid;
    TemplateBytes := U32(Tail, 16);
    ConfigBytes := U32(Tail, 20);
    if (TemplateBytes < 512) or (TemplateBytes > IssuedTemplateMaximum) or
      (ConfigBytes < 16) or (ConfigBytes > IssuedConfigMaximum) or
      (UInt64(TemplateBytes) + ConfigBytes + IssuedTailBytes <> FileSize) then Invalid;
    Header := Copy(Tail, 0, IssuedHeaderBytes);
    Signature := Copy(Tail, IssuedHeaderBytes, IssuedSignatureBytes);
    VerifyHeader(Header, Signature, Anchor);
    CheckDeadline(Started);
    TemplateHash := HashExtent(Stream, TemplateBytes, Started);
    if not SameBytes(TemplateHash, 0, Header, 56, 64) then Invalid;
    Config := ReadExtent(Stream, TemplateBytes, Integer(ConfigBytes), FileSize);
    Hasher := TSHA512Hasher.Create;
    try
      Hasher.Update(Config[0], Length(Config));
      ConfigHash := Hasher.FinishBytes;
    finally
      Hasher.Free;
    end;
    if not SameBytes(ConfigHash, 0, Header, 120, 64) then Invalid;
    CheckDeadline(Started);
    if (Stream.Size < 0) or (UInt64(Stream.Size) <> FileSize) then Invalid;
    { Ownership transfers only after every byte range and the signature pass. }
    Result := Config;
    Config := nil;
  finally
    WipeBytes(Tail); WipeBytes(Header); WipeBytes(Signature); WipeBytes(Config);
    WipeBytes(TemplateHash); WipeBytes(ConfigHash);
    try
      Stream.Position := SavedPosition;
    except
      WipeBytes(Result);
      raise;
    end;
  end;
end;

function ReadVerifiedIssuedAConfig(Handle: THandle; FileSize: UInt64): TBytes;
var Stream: THandleStream; Trust: TResourceStream; Anchor: TBytes;
begin
  Result := nil;
  if (Handle = 0) or (Handle = INVALID_HANDLE_VALUE) then Invalid;
  Stream := nil; Trust := nil; Anchor := nil;
  try
    { The linked RCDATA is backed by the read-only PE resource section.
      Delphi can place typed constant arrays in writable data even with J-.
      Validate the exact resource size before allocating or copying bytes. }
    Trust := TResourceStream.CreateFromID(HInstance, IssuedTrustResourceID, RT_RCDATA);
    if Trust.Size <> IssuedAnchorBytes then Invalid;
    SetLength(Anchor, IssuedAnchorBytes);
    Trust.ReadBuffer(Anchor[0], Length(Anchor));
    Stream := THandleStream.Create(Handle);
    Result := VerifyStream(Stream, FileSize, Anchor);
  finally
    Stream.Free; { THandleStream does not own or close the caller's handle. }
    Trust.Free;
    WipeBytes(Anchor);
  end;
end;

{$IFDEF GAME_ISSUED_A_TESTS}
function VerifyIssuedATestStream(Stream: TStream; FileSize: UInt64;
  const Anchor: TBytes): TBytes;
begin
  Result := VerifyStream(Stream, FileSize, Anchor);
end;
{$ENDIF}

initialization
  BindApiPointer(ApiSlot_BCryptOpenAlgorithmProvider, RequireProcAddressHash64(CozyText_IssuedA_bcrypt_dll_c42e0ffb, HASH_BCryptOpenAlgorithmProvider));
  BindApiPointer(ApiSlot_BCryptImportKeyPair, RequireProcAddressHash64(CozyText_IssuedA_bcrypt_dll_c42e0ffb, HASH_BCryptImportKeyPair));
  BindApiPointer(ApiSlot_BCryptVerifySignature, RequireProcAddressHash64(CozyText_IssuedA_bcrypt_dll_c42e0ffb, HASH_BCryptVerifySignature));
  BindApiPointer(ApiSlot_BCryptDestroyKey, RequireProcAddressHash64(CozyText_IssuedA_bcrypt_dll_c42e0ffb, HASH_BCryptDestroyKey));
  BindApiPointer(ApiSlot_BCryptCloseAlgorithmProvider, RequireProcAddressHash64(CozyText_IssuedA_bcrypt_dll_c42e0ffb, HASH_BCryptCloseAlgorithmProvider));

end.
