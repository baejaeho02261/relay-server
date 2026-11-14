unit Cozy.NHW.ServerNonceAttestation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  Cozy.NHW.Attestation.Hash,
  Cozy.NHW.SessionEpochGuard,
  Cozy.NHW.Attestation.SessionPolicy,
  Cozy.NHW.MeasuredBootEvidence,
  Cozy.NHW.KernelTrust.Native,
  Cozy.NHW.SessionTrustLadder;

type
  TServerAttestationEvidence = record
    Epoch: UInt64;
    ServerSequence: UInt64;
    Nonce: TAttestationNonce;
    BootIdentity: TBootIdentity;
    SessionTrust: TKernelSessionTrust;
    ResponseVoteMask: Byte;
    TrustDigest: UInt64;
    DriverDigest: UInt64;
    IntegrityDigest: UInt64;
    MeasuredBoot: TMeasuredBootEvidence;
    BindingDigest: TSHA256Digest;
  end;

  TServerNonceAttestation = class
  private
    FPolicy: TAttestationSessionPolicy;
    FNonce: TAttestationNonce;
    FChallengeTick: UInt64;
    FHasChallenge: Boolean;
    FLegacySequence: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    function BeginChallenge(Epoch: UInt64; const Nonce: TAttestationNonce;
      Tick: UInt64): Boolean;
    function BeginChallengeEx(Epoch, ServerSequence: UInt64;
      const Nonce: TAttestationNonce; Tick: UInt64): Boolean;
    function BuildEvidence(const BootIdentity: TBootIdentity;
      BootIdentityValid: Boolean; SessionTrust: TKernelSessionTrust;
      ResponseVoteMask: Byte; TrustDigest, DriverDigest,
      IntegrityDigest, Tick: UInt64; out Evidence: TServerAttestationEvidence;
      out MeasuredBootLog: TBytes): Boolean;
    function ApplyVerdictEx(Epoch, ServerSequence: UInt64;
      const Nonce: TAttestationNonce; const BindingDigest: TSHA256Digest;
      Accepted: Boolean; Tick: UInt64): Boolean;
    function CurrentEpoch: UInt64;
    function CurrentServerSequence: UInt64;
  end;

implementation

const
  CHALLENGE_TTL_MS = 60000;

procedure AppendBytes(var B: TBytes; const Source; Count: Integer);
var
  OldLen: Integer;
begin
  if Count <= 0 then Exit;
  OldLen := Length(B);
  SetLength(B, OldLen + Count);
  Move(Source, B[OldLen], Count);
end;

procedure AppendU64(var B: TBytes; V: UInt64);
begin
  AppendBytes(B, V, SizeOf(V));
end;

procedure AppendU32(var B: TBytes; V: Cardinal);
begin
  AppendBytes(B, V, SizeOf(V));
end;

procedure AppendByte(var B: TBytes; V: Byte);
begin
  AppendBytes(B, V, SizeOf(V));
end;

constructor TServerNonceAttestation.Create;
begin
  inherited Create;
  FPolicy := TAttestationSessionPolicy.Create;
  Reset;
end;

destructor TServerNonceAttestation.Destroy;
begin
  FillChar(FNonce, SizeOf(FNonce), 0);
  FChallengeTick := 0; FHasChallenge := False; FLegacySequence := 0;
  FPolicy.Free;
  inherited Destroy;
end;

procedure TServerNonceAttestation.Reset;
begin
  FPolicy.Reset;
  FillChar(FNonce, SizeOf(FNonce), 0);
  FChallengeTick := 0;
  FHasChallenge := False;
  FLegacySequence := 0;
end;

function TServerNonceAttestation.BeginChallenge(Epoch: UInt64;
  const Nonce: TAttestationNonce; Tick: UInt64): Boolean;
var
  NextSequence: UInt64;
begin
  if FLegacySequence = High(UInt64) then Exit(False);
  NextSequence := FLegacySequence + 1;
  Result := BeginChallengeEx(Epoch, NextSequence, Nonce, Tick);
  if Result then FLegacySequence := NextSequence;
end;

function TServerNonceAttestation.BeginChallengeEx(Epoch,
  ServerSequence: UInt64; const Nonce: TAttestationNonce;
  Tick: UInt64): Boolean;
begin
  Result := False;
  if Tick = 0 then Exit;
  if not FPolicy.BeginChallenge(Epoch, ServerSequence, Nonce, Tick) then Exit;
  FNonce := Nonce;
  FChallengeTick := Tick;
  FHasChallenge := True;
  Result := True;
end;

function TServerNonceAttestation.BuildEvidence(
  const BootIdentity: TBootIdentity; BootIdentityValid: Boolean;
  SessionTrust: TKernelSessionTrust; ResponseVoteMask: Byte;
  TrustDigest, DriverDigest, IntegrityDigest, Tick: UInt64;
  out Evidence: TServerAttestationEvidence;
  out MeasuredBootLog: TBytes): Boolean;
var
  Data: TBytes;
  MB: TMeasuredBootEvidence;
  AvailableByte: Byte;
begin
  Result := False;
  Evidence := Default(TServerAttestationEvidence);
  MeasuredBootLog := nil;
  if not FHasChallenge or not BootIdentityValid or (Tick = 0) then Exit;
  if (Tick < FChallengeTick) or (Tick - FChallengeTick > CHALLENGE_TTL_MS) then Exit;

  Evidence.Epoch := FPolicy.CurrentEpoch;
  Evidence.ServerSequence := FPolicy.ServerSequence;
  Evidence.Nonce := FNonce;
  Evidence.BootIdentity := BootIdentity;
  Evidence.SessionTrust := SessionTrust;
  Evidence.ResponseVoteMask := ResponseVoteMask;
  Evidence.TrustDigest := TrustDigest;
  Evidence.DriverDigest := DriverDigest;
  Evidence.IntegrityDigest := IntegrityDigest;
  Data := nil;
  try
  CaptureMeasuredBootEvidence(MB, MeasuredBootLog);
  Evidence.MeasuredBoot := MB;

  AppendU64(Data, Evidence.Epoch);
  AppendU64(Data, Evidence.ServerSequence);
  AppendBytes(Data, Evidence.Nonce[0], SizeOf(Evidence.Nonce));
  AppendU64(Data, Evidence.BootIdentity.LowPart);
  AppendU64(Data, Evidence.BootIdentity.HighPart);
  AppendByte(Data, Byte(Ord(Evidence.SessionTrust)));
  AppendByte(Data, Evidence.ResponseVoteMask);
  AppendU64(Data, Evidence.TrustDigest);
  AppendU64(Data, Evidence.DriverDigest);
  AppendU64(Data, Evidence.IntegrityDigest);
  if MB.Available then AvailableByte := 1 else AvailableByte := 0;
  AppendByte(Data, AvailableByte);
  AppendU32(Data, MB.TpmVersion);
  AppendU32(Data, MB.LogSize);
  AppendBytes(Data, MB.LogDigest[0], SizeOf(MB.LogDigest));

  if not HashBytesSHA256(Data, Evidence.BindingDigest) then
  begin
    Evidence := Default(TServerAttestationEvidence);
    if Length(MeasuredBootLog) <> 0 then
      FillChar(MeasuredBootLog[0], Length(MeasuredBootLog), 0);
    MeasuredBootLog := nil;
    Exit;
  end;
  if not FPolicy.CommitEvidence(Evidence.Epoch, Evidence.ServerSequence,
      Evidence.Nonce, Evidence.BindingDigest, Tick) then
  begin
    Evidence := Default(TServerAttestationEvidence);
    if Length(MeasuredBootLog) <> 0 then
      FillChar(MeasuredBootLog[0], Length(MeasuredBootLog), 0);
    MeasuredBootLog := nil;
    Exit;
  end;
  FHasChallenge := False;
  FillChar(FNonce, SizeOf(FNonce), 0);
  FChallengeTick := 0;
  Result := True;
  finally
    if Length(Data) <> 0 then FillChar(Data[0], Length(Data), 0);
    Data := nil;
    FillChar(MB, SizeOf(MB), 0);
    if not Result then
    begin
      FillChar(Evidence, SizeOf(Evidence), 0);
      if Length(MeasuredBootLog) <> 0 then
        FillChar(MeasuredBootLog[0], Length(MeasuredBootLog), 0);
      MeasuredBootLog := nil;
    end;
  end;
end;

function TServerNonceAttestation.ApplyVerdictEx(Epoch,
  ServerSequence: UInt64; const Nonce: TAttestationNonce;
  const BindingDigest: TSHA256Digest; Accepted: Boolean;
  Tick: UInt64): Boolean;
begin
  Result := FPolicy.ApplyVerdict(Epoch, ServerSequence, Nonce,
    BindingDigest, Accepted, Tick);
end;

function TServerNonceAttestation.CurrentEpoch: UInt64;
begin
  Result := FPolicy.CurrentEpoch;
end;

function TServerNonceAttestation.CurrentServerSequence: UInt64;
begin
  Result := FPolicy.ServerSequence;
end;

end.
