unit Cozy.NHW.Attestation.SessionPolicy;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.SessionEpochGuard,
  Cozy.NHW.Attestation.Hash;

type
  TAttestationFlowState = (afsIdle, afsChallengeAccepted,
    afsEvidenceCommitted, afsVerdictApplied);

  TAttestationSessionPolicy = class
  private
    FGuard: TSessionEpochGuard;
    FState: TAttestationFlowState;
    FEpoch: UInt64;
    FServerSequence: UInt64;
    FLastServerSequence: UInt64;
    FChallengeTick: UInt64;
    FEvidenceTick: UInt64;
    FNonce: TAttestationNonce;
    FBindingDigest: TSHA256Digest;
    FLastAccepted: Boolean;
    function BindingDigestEqual(const A, B: TSHA256Digest): Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    function BeginChallenge(Epoch, ServerSequence: UInt64;
      const Nonce: TAttestationNonce; Tick: UInt64): Boolean;
    function CommitEvidence(Epoch, ServerSequence: UInt64;
      const Nonce: TAttestationNonce; const BindingDigest: TSHA256Digest;
      Tick: UInt64): Boolean;
    function ApplyVerdict(Epoch, ServerSequence: UInt64;
      const Nonce: TAttestationNonce; const BindingDigest: TSHA256Digest;
      Accepted: Boolean; Tick: UInt64): Boolean;
    property State: TAttestationFlowState read FState;
    property CurrentEpoch: UInt64 read FEpoch;
    property ServerSequence: UInt64 read FServerSequence;
    property LastServerSequence: UInt64 read FLastServerSequence;
    property LastAccepted: Boolean read FLastAccepted;
  end;

implementation

const
  CHALLENGE_TTL_MS = 60000;
  VERDICT_TTL_MS = 60000;

constructor TAttestationSessionPolicy.Create;
begin
  inherited Create;
  FGuard := TSessionEpochGuard.Create;
  Reset;
end;

destructor TAttestationSessionPolicy.Destroy;
begin
  FillChar(FNonce, SizeOf(FNonce), 0);
  FillChar(FBindingDigest, SizeOf(FBindingDigest), 0);
  FGuard.Free;
  inherited Destroy;
end;

procedure TAttestationSessionPolicy.Reset;
begin
  FGuard.Reset;
  FState := afsIdle;
  FEpoch := 0;
  FServerSequence := 0;
  FLastServerSequence := 0;
  FChallengeTick := 0;
  FEvidenceTick := 0;
  FillChar(FNonce, SizeOf(FNonce), 0);
  FillChar(FBindingDigest, SizeOf(FBindingDigest), 0);
  FLastAccepted := False;
end;

function TAttestationSessionPolicy.BindingDigestEqual(const A,
  B: TSHA256Digest): Boolean;
var
  I: Integer;
  Diff: Byte;
begin
  Diff := 0;
  for I := 0 to High(A) do Diff := Diff or (A[I] xor B[I]);
  Result := Diff = 0;
end;

function TAttestationSessionPolicy.BeginChallenge(Epoch,
  ServerSequence: UInt64; const Nonce: TAttestationNonce;
  Tick: UInt64): Boolean;
begin
  Result := False;
  if (Tick = 0) or (Epoch = 0) or (ServerSequence = 0) then Exit;
  if FState in [afsChallengeAccepted, afsEvidenceCommitted] then Exit;
  if (FLastServerSequence <> 0) and (ServerSequence <= FLastServerSequence) then Exit;
  if not FGuard.AcceptChallenge(Epoch, Nonce) then Exit;

  FEpoch := FGuard.CurrentEpoch;
  FServerSequence := ServerSequence;
  FLastServerSequence := ServerSequence;
  FChallengeTick := Tick;
  FEvidenceTick := 0;
  FNonce := Nonce;
  FillChar(FBindingDigest, SizeOf(FBindingDigest), 0);
  FLastAccepted := False;
  FState := afsChallengeAccepted;
  Result := True;
end;

function TAttestationSessionPolicy.CommitEvidence(Epoch,
  ServerSequence: UInt64; const Nonce: TAttestationNonce;
  const BindingDigest: TSHA256Digest; Tick: UInt64): Boolean;
begin
  Result := False;
  if FState <> afsChallengeAccepted then Exit;
  if (Tick = 0) or (Tick < FChallengeTick) or
     (Tick - FChallengeTick > CHALLENGE_TTL_MS) then Exit;
  if (Epoch <> FEpoch) or (ServerSequence <> FServerSequence) then Exit;
  if not AttestationNonceEqual(Nonce, FNonce) then Exit;

  FBindingDigest := BindingDigest;
  FEvidenceTick := Tick;
  FState := afsEvidenceCommitted;
  Result := True;
end;

function TAttestationSessionPolicy.ApplyVerdict(Epoch,
  ServerSequence: UInt64; const Nonce: TAttestationNonce;
  const BindingDigest: TSHA256Digest; Accepted: Boolean;
  Tick: UInt64): Boolean;
begin
  Result := False;
  if FState <> afsEvidenceCommitted then Exit;
  if (Tick = 0) or (Tick < FEvidenceTick) or
     (Tick - FEvidenceTick > VERDICT_TTL_MS) then Exit;
  if (Epoch <> FEpoch) or (ServerSequence <> FServerSequence) then Exit;
  if not AttestationNonceEqual(Nonce, FNonce) then Exit;
  if not BindingDigestEqual(BindingDigest, FBindingDigest) then Exit;

  FLastAccepted := Accepted;
  { Replays are fenced by terminal state, sequence and the epoch guard.
    The completed one-use transaction no longer needs these raw copies. }
  FillChar(FNonce, SizeOf(FNonce), 0);
  FillChar(FBindingDigest, SizeOf(FBindingDigest), 0);
  FState := afsVerdictApplied;
  Result := True;
end;

end.
