unit Cozy.NHW.ObserverAuthenticator;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils;

type
  TObserverSessionKey = array[0..31] of Byte;
  TObserverSessionMAC = array[0..31] of Byte;
  TObserverSessionEvidence = packed record
    Sequence: UInt64;
    OwnerPID: Cardinal;
    ObserverPID: Cardinal;
    OwnerCreated: UInt64;
    ObservedCreation: UInt64;
    ObservedTick: UInt64;
    State: Cardinal;
  end;

function NHWCreateSessionKey(out Key: TObserverSessionKey): Boolean;
function NHWSessionMAC(const Key: TObserverSessionKey;
  const Evidence: TObserverSessionEvidence;
  out MAC: TObserverSessionMAC): Boolean;
function NHWVerifySessionMAC(const Key: TObserverSessionKey;
  const Evidence: TObserverSessionEvidence;
  const MAC: TObserverSessionMAC): Boolean;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestObserverAuthenticator10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

function BCryptGenRandom(hAlgorithm: THandle; Buffer: Pointer;
  BufferSize, Flags: Cardinal): LongInt; stdcall;
  external 'bcrypt.dll' name 'BCryptGenRandom';
function BCryptOpenAlgorithmProvider(out Provider: THandle;
  Algorithm, ImplName: PWideChar; Flags: Cardinal): LongInt; stdcall;
  external 'bcrypt.dll' name 'BCryptOpenAlgorithmProvider';
function BCryptCloseAlgorithmProvider(Provider: THandle;
  Flags: Cardinal): LongInt; stdcall;
  external 'bcrypt.dll' name 'BCryptCloseAlgorithmProvider';
function BCryptHash(Provider: THandle; Secret: Pointer;
  SecretSize: Cardinal; Input: Pointer; InputSize: Cardinal;
  Output: Pointer; OutputSize: Cardinal): LongInt; stdcall;
  external 'bcrypt.dll' name 'BCryptHash';

{$IFDEF NHW_NATIVE10O_TESTS}
// Fault injection is absent from the normal executable.
type
  TObserverRandomTest = function(Algorithm: THandle; Buffer: Pointer;
    Bytes, Flags: Cardinal): LongInt; stdcall;
  TObserverOpenTest = function(out Provider: THandle;
    Algorithm, ImplName: PWideChar; Flags: Cardinal): LongInt; stdcall;
  TObserverHashTest = function(Provider: THandle; Secret: Pointer;
    SecretSize: Cardinal; Input: Pointer; InputSize: Cardinal;
    Output: Pointer; OutputSize: Cardinal): LongInt; stdcall;
  TObserverCloseTest = function(Provider: THandle;
    Flags: Cardinal): LongInt; stdcall;
var
  TestRandom: TObserverRandomTest;
  TestOpen: TObserverOpenTest;
  TestHash: TObserverHashTest;
  TestClose: TObserverCloseTest;
{$ENDIF}

// Intentionally non-inline and optimizer-disabled. The RTL/SDK spelling of
// SecureZeroMemory varies; this byte-store routine is compiled as real writes.
// It wipes only buffers we own, not hidden OS/provider/compiler copies.
{$IFOPT O+}
  {$DEFINE NHW_OBSERVER_RESTORE_OPT}
  {$O-}
{$ENDIF}
procedure ObserverWipe(Buffer: Pointer; Bytes: NativeUInt);
var P: PByte;
begin
  P := PByte(Buffer);
  while Bytes <> 0 do
  begin
    P^ := 0;
    Inc(P);
    Dec(Bytes);
  end;
end;
{$IFDEF NHW_OBSERVER_RESTORE_OPT}
  {$O+}
  {$UNDEF NHW_OBSERVER_RESTORE_OPT}
{$ENDIF}

function ObserverRandom(Buffer: Pointer; Bytes: Cardinal): LongInt;
begin
{$IFDEF NHW_NATIVE10O_TESTS}
  if Assigned(TestRandom) then Exit(TestRandom(0, Buffer, Bytes, $2));
{$ENDIF}
  Result := BCryptGenRandom(0, Buffer, Bytes, $2);
end;

function ObserverOpen(out Provider: THandle): LongInt;
begin
{$IFDEF NHW_NATIVE10O_TESTS}
  if Assigned(TestOpen) then
    Exit(TestOpen(Provider, PWideChar('SHA256'), nil, $00000008));
{$ENDIF}
  Result := BCryptOpenAlgorithmProvider(Provider,
    PWideChar('SHA256'), nil, $00000008);
end;

function ObserverHash(Provider: THandle; const Key: TObserverSessionKey;
  const Evidence: TObserverSessionEvidence;
  out Digest: TObserverSessionMAC): LongInt;
begin
{$IFDEF NHW_NATIVE10O_TESTS}
  if Assigned(TestHash) then
    Exit(TestHash(Provider, @Key[0], SizeOf(Key), @Evidence,
      SizeOf(Evidence), @Digest[0], SizeOf(Digest)));
{$ENDIF}
  Result := BCryptHash(Provider, @Key[0], SizeOf(Key), @Evidence,
    SizeOf(Evidence), @Digest[0], SizeOf(Digest));
end;

function ObserverClose(Provider: THandle): LongInt;
begin
{$IFDEF NHW_NATIVE10O_TESTS}
  if Assigned(TestClose) then Exit(TestClose(Provider, 0));
{$ENDIF}
  Result := BCryptCloseAlgorithmProvider(Provider, 0);
end;


procedure ClearSessionKey(var Key: TObserverSessionKey);
begin
  ObserverWipe(@Key[0], SizeOf(Key));
end;

procedure ClearSessionMAC(var MAC: TObserverSessionMAC);
begin
  ObserverWipe(@MAC[0], SizeOf(MAC));
end;

function ConstantTimeMACEqual(const Left, Right: TObserverSessionMAC): Boolean;
var
  I, Difference: Integer;
begin
  Difference := 0;
  for I := Low(Left) to High(Left) do
    Difference := Difference or (Left[I] xor Right[I]);
  Result := Difference = 0;
end;

function ComputeSessionMACCandidate(const Key: TObserverSessionKey;
  const Evidence: TObserverSessionEvidence;
  out Candidate: TObserverSessionMAC): Boolean;
var
  Provider: THandle;
  HashOK, CloseOK: Boolean;
begin
  Result := False;
  Provider := 0;
  FillChar(Candidate, SizeOf(Candidate), 0);
  if ObserverOpen(Provider) <> 0 then Exit;
  if Provider = 0 then Exit;
  try
    HashOK := ObserverHash(Provider, Key, Evidence, Candidate) = 0;
  finally
    CloseOK := ObserverClose(Provider) = 0;
  end;
  Result := HashOK and CloseOK;
end;

function NHWCreateSessionKey(out Key: TObserverSessionKey): Boolean;
var Candidate: TObserverSessionKey;
begin
  FillChar(Key, SizeOf(Key), 0);
  FillChar(Candidate, SizeOf(Candidate), 0);
  Result := False;
  try
    if ObserverRandom(@Candidate[0], SizeOf(Candidate)) <> 0 then Exit;
    Key := Candidate;
    Result := True;
  finally
    ClearSessionKey(Candidate);
    if not Result then ClearSessionKey(Key);
  end;
end;

function NHWSessionMAC(const Key: TObserverSessionKey;
  const Evidence: TObserverSessionEvidence;
  out MAC: TObserverSessionMAC): Boolean;
var
  Candidate: TObserverSessionMAC;
begin
  FillChar(MAC, SizeOf(MAC), 0);
  FillChar(Candidate, SizeOf(Candidate), 0);
  Result := False;
  try
    // Do not publish a partially written digest even if the provider fails.
    if not ComputeSessionMACCandidate(Key, Evidence, Candidate) then Exit;
    MAC := Candidate;
    Result := True;
  finally
    ClearSessionMAC(Candidate);
    if not Result then ClearSessionMAC(MAC);
  end;
end;

function NHWVerifySessionMAC(const Key: TObserverSessionKey;
  const Evidence: TObserverSessionEvidence;
  const MAC: TObserverSessionMAC): Boolean;
var
  Expected: TObserverSessionMAC;
begin
  Result := False;
  FillChar(Expected, SizeOf(Expected), 0);
  try
    if not NHWSessionMAC(Key, Evidence, Expected) then Exit;
    Result := ConstantTimeMACEqual(Expected, MAC);
  finally
    ClearSessionMAC(Expected);
  end;
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.ObserverAuthenticator.inc}
{$ENDIF}

end.
