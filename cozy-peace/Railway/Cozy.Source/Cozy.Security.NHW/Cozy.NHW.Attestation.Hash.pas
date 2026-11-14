unit Cozy.NHW.Attestation.Hash;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils;

type
  TSHA256Digest = array[0..31] of Byte;
  TSHA512Digest = array[0..63] of Byte;

function HashBytesSHA256(const Data: TBytes; out Digest: TSHA256Digest): Boolean;
function HashBytesSHA512(const Data: TBytes; out Digest: TSHA512Digest): Boolean;
function DigestEqual(const A, B: TSHA256Digest): Boolean;
function DigestIsZero(const D: TSHA256Digest): Boolean;

implementation

uses
  Cozy.NHW.WinPointers;

type
  TBcryptOpenAlgorithmProvider = function(var Alg: Pointer; AlgId,
    ProviderImplementation: PWideChar; Flags: Cardinal): LongInt; stdcall;
  TBcryptGetProperty = function(Handle: Pointer; PropertyName: PWideChar;
    Output: Pointer; OutputBytes: Cardinal; out ResultBytes: Cardinal;
    Flags: Cardinal): LongInt; stdcall;
  TBcryptCreateHash = function(Alg: Pointer; var Hash: Pointer;
    HashObject: Pointer; HashObjectBytes: Cardinal; Secret: Pointer;
    SecretBytes: Cardinal; Flags: Cardinal): LongInt; stdcall;
  TBcryptHashData = function(Hash: Pointer; Input: Pointer;
    InputBytes: Cardinal; Flags: Cardinal): LongInt; stdcall;
  TBcryptFinishHash = function(Hash: Pointer; Output: Pointer;
    OutputBytes: Cardinal; Flags: Cardinal): LongInt; stdcall;
  TBcryptDestroyHash = function(Hash: Pointer): LongInt; stdcall;
  TBcryptCloseAlgorithmProvider = function(Alg: Pointer;
    Flags: Cardinal): LongInt; stdcall;

function HashBytesSHA256(const Data: TBytes; out Digest: TSHA256Digest): Boolean;
var
  B: HMODULE;
  OpenAlg: TBcryptOpenAlgorithmProvider;
  GetProp: TBcryptGetProperty;
  CreateHash: TBcryptCreateHash;
  HashData: TBcryptHashData;
  FinishHash: TBcryptFinishHash;
  DestroyHash: TBcryptDestroyHash;
  CloseAlg: TBcryptCloseAlgorithmProvider;
  Alg, Hash: Pointer;
  ObjectBytes, HashBytes, Returned: Cardinal;
  ObjectBuffer: TBytes;
begin
  Result := False;
  FillChar(Digest, SizeOf(Digest), 0);
  B := WinLoadLibrary('bcrypt.dll');
  if B = 0 then Exit;
  Alg := nil;
  Hash := nil;
  DestroyHash := nil;
  CloseAlg := nil;
  try
    OpenAlg := TBcryptOpenAlgorithmProvider(WinExport(B, 'BCryptOpenAlgorithmProvider'));
    GetProp := TBcryptGetProperty(WinExport(B, 'BCryptGetProperty'));
    CreateHash := TBcryptCreateHash(WinExport(B, 'BCryptCreateHash'));
    HashData := TBcryptHashData(WinExport(B, 'BCryptHashData'));
    FinishHash := TBcryptFinishHash(WinExport(B, 'BCryptFinishHash'));
    DestroyHash := TBcryptDestroyHash(WinExport(B, 'BCryptDestroyHash'));
    CloseAlg := TBcryptCloseAlgorithmProvider(WinExport(B, 'BCryptCloseAlgorithmProvider'));
    if not Assigned(OpenAlg) or not Assigned(GetProp) or
       not Assigned(CreateHash) or not Assigned(HashData) or
       not Assigned(FinishHash) or not Assigned(DestroyHash) or
       not Assigned(CloseAlg) then Exit;

    if OpenAlg(Alg, PWideChar('SHA256'), nil, 0) <> 0 then Exit;
    ObjectBytes := 0;
    Returned := 0;
    if GetProp(Alg, PWideChar('ObjectLength'), @ObjectBytes,
         SizeOf(ObjectBytes), Returned, 0) <> 0 then Exit;
    HashBytes := 0;
    Returned := 0;
    if GetProp(Alg, PWideChar('HashDigestLength'), @HashBytes,
         SizeOf(HashBytes), Returned, 0) <> 0 then Exit;
    if (ObjectBytes = 0) or (ObjectBytes > 1024 * 1024) or
       (HashBytes <> SizeOf(Digest)) then Exit;
    SetLength(ObjectBuffer, ObjectBytes);
    if CreateHash(Alg, Hash, @ObjectBuffer[0], ObjectBytes,
         nil, 0, 0) <> 0 then Exit;
    if Length(Data) <> 0 then
      if HashData(Hash, @Data[0], Cardinal(Length(Data)), 0) <> 0 then Exit;
    if FinishHash(Hash, @Digest[0], SizeOf(Digest), 0) <> 0 then Exit;
    Result := True;
  finally
    if (Hash <> nil) and Assigned(DestroyHash) then DestroyHash(Hash);
    if (Alg <> nil) and Assigned(CloseAlg) then CloseAlg(Alg, 0);
    if Length(ObjectBuffer) <> 0 then
      FillChar(ObjectBuffer[0], Length(ObjectBuffer), 0);
    if not Result then FillChar(Digest, SizeOf(Digest), 0);
    WinFreeLibrary(B);
  end;
end;

function HashBytesSHA512(const Data: TBytes; out Digest: TSHA512Digest): Boolean;
var
  B: HMODULE;
  OpenAlg: TBcryptOpenAlgorithmProvider;
  GetProp: TBcryptGetProperty;
  CreateHash: TBcryptCreateHash;
  HashData: TBcryptHashData;
  FinishHash: TBcryptFinishHash;
  DestroyHash: TBcryptDestroyHash;
  CloseAlg: TBcryptCloseAlgorithmProvider;
  Alg, Hash: Pointer;
  ObjectBytes, HashBytes, Returned: Cardinal;
  ObjectBuffer: TBytes;
begin
  Result := False;
  FillChar(Digest, SizeOf(Digest), 0);
  B := WinLoadLibrary('bcrypt.dll');
  if B = 0 then Exit;
  Alg := nil;
  Hash := nil;
  DestroyHash := nil;
  CloseAlg := nil;
  try
    OpenAlg := TBcryptOpenAlgorithmProvider(WinExport(B, 'BCryptOpenAlgorithmProvider'));
    GetProp := TBcryptGetProperty(WinExport(B, 'BCryptGetProperty'));
    CreateHash := TBcryptCreateHash(WinExport(B, 'BCryptCreateHash'));
    HashData := TBcryptHashData(WinExport(B, 'BCryptHashData'));
    FinishHash := TBcryptFinishHash(WinExport(B, 'BCryptFinishHash'));
    DestroyHash := TBcryptDestroyHash(WinExport(B, 'BCryptDestroyHash'));
    CloseAlg := TBcryptCloseAlgorithmProvider(WinExport(B, 'BCryptCloseAlgorithmProvider'));
    if not Assigned(OpenAlg) or not Assigned(GetProp) or
       not Assigned(CreateHash) or not Assigned(HashData) or
       not Assigned(FinishHash) or not Assigned(DestroyHash) or
       not Assigned(CloseAlg) then Exit;

    if OpenAlg(Alg, PWideChar('SHA512'), nil, 0) <> 0 then Exit;
    ObjectBytes := 0;
    Returned := 0;
    if GetProp(Alg, PWideChar('ObjectLength'), @ObjectBytes,
         SizeOf(ObjectBytes), Returned, 0) <> 0 then Exit;
    HashBytes := 0;
    Returned := 0;
    if GetProp(Alg, PWideChar('HashDigestLength'), @HashBytes,
         SizeOf(HashBytes), Returned, 0) <> 0 then Exit;
    if (ObjectBytes = 0) or (ObjectBytes > 1024 * 1024) or
       (HashBytes <> SizeOf(Digest)) then Exit;
    SetLength(ObjectBuffer, ObjectBytes);
    if CreateHash(Alg, Hash, @ObjectBuffer[0], ObjectBytes,
         nil, 0, 0) <> 0 then Exit;
    if Length(Data) <> 0 then
      if HashData(Hash, @Data[0], Cardinal(Length(Data)), 0) <> 0 then Exit;
    if FinishHash(Hash, @Digest[0], SizeOf(Digest), 0) <> 0 then Exit;
    Result := True;
  finally
    if (Hash <> nil) and Assigned(DestroyHash) then DestroyHash(Hash);
    if (Alg <> nil) and Assigned(CloseAlg) then CloseAlg(Alg, 0);
    if Length(ObjectBuffer) <> 0 then
      FillChar(ObjectBuffer[0], Length(ObjectBuffer), 0);
    if not Result then FillChar(Digest, SizeOf(Digest), 0);
    WinFreeLibrary(B);
  end;
end;

function DigestEqual(const A, B: TSHA256Digest): Boolean;
var I: Integer; Diff: Byte;
begin
  Diff := 0;
  for I := 0 to High(A) do Diff := Diff or (A[I] xor B[I]);
  Result := Diff = 0;
end;

function DigestIsZero(const D: TSHA256Digest): Boolean;
var I: Integer; Acc: Byte;
begin
  Acc := 0;
  for I := 0 to High(D) do Acc := Acc or D[I];
  Result := Acc = 0;
end;

end.
