program CozyNHWKernelTrust5FTests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging,
  Cozy.NHW.Attestation.Hash,
  Cozy.NHW.SessionEpochGuard,
  Cozy.NHW.Attestation.SessionPolicy,
  Cozy.NHW.Attestation.Transport,
  Cozy.NHW.ServerNonceAttestation,
  Cozy.NHW.ResponsePath.Dispatch,
  Cozy.NHW.ResponseSink.Local,
  Cozy.NHW.KernelTrust.CorrelationPolicy,
  Cozy.NHW.SessionTrustLadder;

procedure Check(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(Name);
end;

procedure FillNonce(var N: TAttestationNonce; Seed: Byte);
var I: Integer;
begin
  for I := 0 to High(N) do N[I] := Byte(Seed + I + 1);
end;

procedure FillDigest(var D: TSHA256Digest; Seed: Byte);
var I: Integer;
begin
  for I := 0 to High(D) do D[I] := Byte(Seed xor Byte(I + 1));
end;

var
  Challenge, Challenge2: TAttestationChallengeFrame;
  Verdict, Verdict2: TAttestationVerdictFrame;
  Frame: TBytes;
  Policy: TAttestationSessionPolicy;
  Local: TLocalResponseSinkSet;
  E: TResponsePathEvent;
  D: TSHA256Digest;
  Kinds: TDetectionKinds;
  Summary: TKernelCorrelationSummary;
  Evidence, Evidence2: TServerAttestationEvidence;
  BootLog, BootLog2: TBytes;
begin
  Policy := TAttestationSessionPolicy.Create;
  Local := TLocalResponseSinkSet.Create;
  try
    Challenge := Default(TAttestationChallengeFrame);
    Challenge.Epoch := 7;
    Challenge.ServerSequence := 100;
    FillNonce(Challenge.Nonce, 3);
    Check(BuildAttestationChallengeFrame(Challenge, Frame), 'challenge build');
    Check(ParseAttestationChallengeFrame(Frame, Challenge2), 'challenge parse');
    Check((Challenge2.Epoch = 7) and (Challenge2.ServerSequence = 100) and
      AttestationNonceEqual(Challenge.Nonce, Challenge2.Nonce), 'challenge roundtrip');

    FillDigest(D, $A5);
    Check(Policy.BeginChallenge(7, 100, Challenge.Nonce, 1000), 'policy begin');
    Check(Policy.CommitEvidence(7, 100, Challenge.Nonce, D, 1100), 'policy evidence');
    Check(not Policy.CommitEvidence(7, 100, Challenge.Nonce, D, 1200),
      'policy one evidence');
    Check(Policy.ApplyVerdict(7, 100, Challenge.Nonce, D, True, 1300),
      'policy verdict');
    Check(not Policy.ApplyVerdict(7, 100, Challenge.Nonce, D, True, 1400),
      'policy verdict replay');
    Check(not Policy.BeginChallenge(7, 100, Challenge.Nonce, 1500),
      'policy sequence replay');

    Evidence := Default(TServerAttestationEvidence);
    Evidence.Epoch := 7;
    Evidence.ServerSequence := 100;
    Evidence.Nonce := Challenge.Nonce;
    Evidence.BootIdentity.LowPart := 11;
    Evidence.BootIdentity.HighPart := 22;
    Evidence.SessionTrust := kstDegraded;
    Evidence.ResponseVoteMask := 3;
    Evidence.TrustDigest := 101;
    Evidence.DriverDigest := 202;
    Evidence.IntegrityDigest := 303;
    Evidence.MeasuredBoot.Available := True;
    Evidence.MeasuredBoot.TpmVersion := 2;
    SetLength(BootLog, 4);
    BootLog[0] := 1; BootLog[1] := 2; BootLog[2] := 3; BootLog[3] := 4;
    Evidence.MeasuredBoot.LogSize := Length(BootLog);
    FillDigest(Evidence.MeasuredBoot.LogDigest, $22);
    Evidence.BindingDigest := D;
    Check(BuildAttestationEvidenceFrame(Evidence, BootLog, Frame),
      'evidence frame build');
    Check(ParseAttestationEvidenceFrame(Frame, Evidence2, BootLog2),
      'evidence frame parse');
    Check((Evidence2.ServerSequence = 100) and
      (Evidence2.SessionTrust = kstDegraded) and (Length(BootLog2) = 4),
      'evidence roundtrip');

    Verdict := Default(TAttestationVerdictFrame);
    Verdict.Epoch := 7;
    Verdict.ServerSequence := 100;
    Verdict.Nonce := Challenge.Nonce;
    Verdict.BindingDigest := D;
    Verdict.Accepted := True;
    Check(BuildAttestationVerdictFrame(Verdict, Frame), 'verdict build');
    Check(ParseAttestationVerdictFrame(Frame, Verdict2), 'verdict parse');
    Check(Verdict2.Accepted and (Verdict2.ServerSequence = 100) and
      AttestationNonceEqual(Verdict.Nonce, Verdict2.Nonce), 'verdict roundtrip');

    Local.Reset;
    E := Default(TResponsePathEvent);
    E.Channel := rpcTrust; E.Sequence := 1; E.Tick := 1000; E.Digest := 11;
    Local.TrustReceive(E);
    Check(not Local.Quorum(1000), 'local one path');
    E.Channel := rpcDriver; E.Sequence := 1; E.Tick := 1001; E.Digest := 22;
    Local.DriverReceive(E);
    Check(Local.Quorum(1001), 'local two path quorum');
    Local.DriverReceive(E);
    Check(Local.Quorum(1001), 'duplicate does not erase');

    Kinds := [dkVulnerableDriver, dkDriverCrossView, dkKernelMappingEvidence];
    Summary := EvaluateKernelCorrelation(Kinds, kstUntrusted, True);
    Check(Summary.CanInvalidate, 'strong correlation');
    Check(Summary.IndependentFamilies >= 2, 'strong families');
    Kinds := [dkDriverCrossView];
    Summary := EvaluateKernelCorrelation(Kinds, kstUntrusted, True);
    Check(not Summary.CanInvalidate, 'weak correlation blocked');

    Writeln('PASS');
  finally
    Local.Free;
    Policy.Free;
  end;
end.
