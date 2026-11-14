unit Cozy.NHW.AdvancedPrivacyRegressionV100;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

function ValidatePrivacyV100(out Failure: string): Boolean;
{$IFDEF NHW_REFACTOR10AA_TESTS}
function TestPrivacyConstructionAA(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils, Cozy.NHW.Types, Cozy.NHW.Logging,
  Cozy.NHW.EphemeralIdentity, Cozy.NHW.PrecisionTimeline,
  Cozy.NHW.BehaviorFingerprint, Cozy.NHW.SensorConsensus,
  Cozy.NHW.MemoryEvidenceCapsule, Cozy.NHW.AdaptiveAnomaly,
  Cozy.NHW.SensorDisagreement, Cozy.NHW.ObserverAuthenticator,
  Cozy.NHW.PrivacyForensics, Cozy.NHW.HighResolutionClock;

{$IFDEF NHW_REFACTOR10AA_TESTS}
// Local-only failure injection. Absent from the normal executable.
type EPrivacyConstructionProbe = class(Exception);
var
  PrivacyProbeActive: Boolean = False;
  PrivacyProbeFailAt: Integer = 0;
  PrivacyProbeAttempts: Integer = 0;
  PrivacyProbeCreatedMask: Cardinal = 0;
  PrivacyProbeReleasedMask: Cardinal = 0;
  PrivacyProbeDoubleRelease: Boolean = False;

procedure BeforePrivacyConstruction(Index: Integer);
begin
  if not PrivacyProbeActive then Exit;
  Inc(PrivacyProbeAttempts);
  if Index = PrivacyProbeFailAt then
    raise EPrivacyConstructionProbe.Create('privacy construction probe');
end;

procedure PrivacyConstructed(Index: Integer);
begin
  if PrivacyProbeActive then
    PrivacyProbeCreatedMask := PrivacyProbeCreatedMask or (Cardinal(1) shl (Index - 1));
end;

procedure PrivacyReleased(Index: Integer; WasAllocated: Boolean);
var Bit: Cardinal;
begin
  if not PrivacyProbeActive or not WasAllocated then Exit;
  Bit := Cardinal(1) shl (Index - 1);
  if (PrivacyProbeReleasedMask and Bit) <> 0 then PrivacyProbeDoubleRelease := True;
  PrivacyProbeReleasedMask := PrivacyProbeReleasedMask or Bit;
end;
{$ENDIF}

procedure Verify(Value: Boolean; const MessageText: string);
begin
  if not Value then raise Exception.Create(MessageText);
end;

function ValidatePrivacyV100(out Failure: string): Boolean;
var
  Actors: TSessionActorIdentity;
  Precision: TPrecisionTimeline;
  Behavior: TBehaviorFingerprint;
  Consensus: TSensorConsensus;
  Capsule: TMemoryEvidenceCapsule;
  Anomaly: TAdaptiveAnomaly;
  Disagree: TSensorDisagreement;
  Privacy: TPrivacyForensics;
  A, B: UInt64;
  E: TObserverSessionEvidence;
  Key: TObserverSessionKey;
  MAC: TObserverSessionMAC;
  Frame: TMemoryEvidenceFrame;
  P: TPrivateForensicEvent;
  Stamp: Int64;

  procedure TestSessionIdentityAndTimeline;
  begin
    A := Actors.Observe(4100, 100000, 1000);
    Verify(A <> 0, 'v91: random alias');
    Verify(Actors.Observe(4100, 100000, 1200) = A,
      'v91: same PID/creation must share alias');
    B := Actors.Observe(4100, 100100, 1500);
    Verify((B <> 0) and (A <> B), 'v91: PID reuse isolated');
    Verify(Actors.Observe(4100, 0, 2000) = 0,
      'v91: unknown creation rejected');
    Stamp := NHWQpcNow;
    Precision.Observe(A, 1, Stamp, Stamp, 3000);
    Verify(Precision.Count = 1, 'v93: precision ring');
  end;

  procedure TestBehaviorFingerprint;
  begin
    Behavior.Observe(A, ACCESS_VM_READ, False, True, 3000);
    Behavior.Observe(A, ACCESS_VM_WRITE, False, True, 3200);
    Behavior.Observe(A, ACCESS_VM_WRITE or ACCESS_CREATE_THREAD,
      False, True, 3400);
    Verify(Behavior.Score(A, 3500) >= 32,
      'v94: rights-based scoring');
    Verify(Behavior.Score(A, 20000) = 0,
      'v94: stale score expires');
  end;

  procedure TestSensorConsensus;
  begin
    Consensus.Evaluate([dkPECodeIntegrity], True,
      False, True, True, False, 4000);
    Verify(Consensus.Last.Corroborated and
      (Consensus.Last.IndependentCount = 2),
      'v92: independent families');
    Consensus.Evaluate([dkPECodeIntegrity], True,
      False, True, True, True, 4500);
    Verify(not Consensus.Last.Corroborated,
      'v92: ETW loss downgrades confidence');
  end;

  procedure TestEvidenceCapsule;
  begin
    Capsule.Append(5000, 0, 70, False, [dkProcess]);
    Verify(Capsule.Recent(0, Frame) and
      (Frame.ActorAlias = 0), 'v95: do not infer actor');
    Capsule.Prune(66001);
    Verify(Capsule.Count = 0, 'v95: TTL scrubbing');
  end;

  procedure TestAnomalyLearning;
  var
    I: Integer;
  begin
    // Native5J: first observation primes time; eight full intervals warm up.
    for I := 0 to 8 do
      Anomaly.Observe(1, False, True, 1000 + Cardinal(I) * 100);
    Verify(not Anomaly.State.Anomalous,
      'v96: normal warmup');
    Anomaly.Observe(40, False, True, 2000);
    Verify(Anomaly.State.Anomalous,
      'v96: high count after baseline');
    Anomaly.Observe(100, False, False, 2100);
    Verify(not Anomaly.State.Anomalous,
      'v96: incomplete snapshot not learned');
  end;

  procedure TestSensorDisagreement;
  begin
    Disagree.Observe(True, True, True, True, False, True, 2200);
    Verify(Disagree.State.Kind = sdCoverageGap,
      'v97: missing visibility');
    Verify(NHWDisagreementKind(True, True, False, False, False,
      True) = sdUnknown, 'v97: no ETW available');
    Verify(NHWDisagreementKind(True, True, True, False, False,
      True) = sdUncorroborated,
      'v97: absent corroboration is not attack');
  end;

  procedure TestObserverAuthentication;
  begin
    Verify(NHWCreateSessionKey(Key), 'v98: CNG session key');
    E := Default(TObserverSessionEvidence);
    E.Sequence := 2;
    E.OwnerPID := 4100;
    E.ObserverPID := 4200;
    E.OwnerCreated := 100000;
    E.ObservedCreation := 100000;
    E.ObservedTick := 6000;
    E.State := 1;
    Verify(NHWSessionMAC(Key, E, MAC), 'v98: HMAC creation');
    Verify(NHWVerifySessionMAC(Key, E, MAC), 'v98: valid proof');
    E.ObserverPID := 4201;
    Verify(not NHWVerifySessionMAC(Key, E, MAC),
      'v98: modified session rejected');
  end;

  procedure TestPrivateForensics;
  begin
    Verify(NHWRightsCategory(ACCESS_VM_WRITE, False) = 3,
      'v99: rights category');
    Privacy.Observe(A, 7000, 3, True, False);
    Verify(Privacy.Recent(0, P) and (P.ActorAlias = A),
      'v99: alias-only forensic record');
    Privacy.Prune(68001);
    Verify(Privacy.Count = 0, 'v99: privacy TTL');
  end;

begin
  Result := False;
  Failure := '';
  Actors := nil;
  Precision := nil;
  Behavior := nil;
  Consensus := nil;
  Capsule := nil;
  Anomaly := nil;
  Disagree := nil;
  Privacy := nil;
  try
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(1);
{$ENDIF}
    Actors := TSessionActorIdentity.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(1);
{$ENDIF}
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(2);
{$ENDIF}
    Precision := TPrecisionTimeline.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(2);
{$ENDIF}
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(3);
{$ENDIF}
    Behavior := TBehaviorFingerprint.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(3);
{$ENDIF}
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(4);
{$ENDIF}
    Consensus := TSensorConsensus.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(4);
{$ENDIF}
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(5);
{$ENDIF}
    Capsule := TMemoryEvidenceCapsule.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(5);
{$ENDIF}
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(6);
{$ENDIF}
    Anomaly := TAdaptiveAnomaly.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(6);
{$ENDIF}
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(7);
{$ENDIF}
    Disagree := TSensorDisagreement.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(7);
{$ENDIF}
{$IFDEF NHW_REFACTOR10AA_TESTS}
    BeforePrivacyConstruction(8);
{$ENDIF}
    Privacy := TPrivacyForensics.Create;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyConstructed(8);
    // Ninth boundary proves cleanup after all eight successful creations.
    BeforePrivacyConstruction(9);
{$ENDIF}
    try
      TestSessionIdentityAndTimeline;
      TestBehaviorFingerprint;
      TestSensorConsensus;
      TestEvidenceCapsule;
      TestAnomalyLearning;
      TestSensorDisagreement;
      TestObserverAuthentication;
      TestPrivateForensics;
      Result := True;
    except
      on X: Exception do Failure := X.Message;
    end;
  finally
    Privacy.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(8, Privacy <> nil);
{$ENDIF}
    Disagree.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(7, Disagree <> nil);
{$ENDIF}
    Anomaly.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(6, Anomaly <> nil);
{$ENDIF}
    Capsule.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(5, Capsule <> nil);
{$ENDIF}
    Consensus.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(4, Consensus <> nil);
{$ENDIF}
    Behavior.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(3, Behavior <> nil);
{$ENDIF}
    Precision.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(2, Precision <> nil);
{$ENDIF}
    Actors.Free;
{$IFDEF NHW_REFACTOR10AA_TESTS}
    PrivacyReleased(1, Actors <> nil);
{$ENDIF}
    FillChar(Key, SizeOf(Key), 0);
  end;
end;

{$IFDEF NHW_REFACTOR10AA_TESTS}
{$I Cozy.NHW.Refactor10AA.PrivacyConstruction.inc}
{$ENDIF}

end.
