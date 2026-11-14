unit Cozy.NHW.AdvancedRegression;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

function ValidateV70RiskStateCases(out Failure: string; out Checks: Integer): Boolean;

function ValidateV70Regression(out Failure: string;
  out OptionalLiveChecks: Integer): Boolean;

implementation

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.Logging, Cozy.NHW.WinPointers, Cozy.NHW.RegressionLab,
  Cozy.NHW.StableIdentity, Cozy.NHW.ProcessSnapshot, Cozy.NHW.LoaderCrossView,
  Cozy.NHW.FileAttestation, Cozy.NHW.ControlFlowAttestation,
  Cozy.NHW.SnapshotETWReconcile, Cozy.NHW.DualObserver,
  Cozy.NHW.ForensicHashChain, Cozy.NHW.RiskConfidence;

function ValidateV70RiskStateCases(out Failure: string; out Checks: Integer): Boolean;
var
  Risk: TRiskConfidenceMonitor;
  D: TDetectionKinds;
  Families: TRiskFamilies;
  Score: Integer;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0; Risk := nil;
  try
    try
      Risk := TRiskConfidenceMonitor.Create;
      D := [];
      Families := Risk.Evaluate([dkPrivateThread, dkPECodeIntegrity], True,
        False, False, True, 1000, Score, D, False);
      Check(not (dkRiskConfidence in D), 'gap rejects risk conclusion');
      Check(rfTelemetryGap in Families, 'gap is disclosed');
      Check(Score = 51, 'original score weighting with visibility penalty');
      D := [];
      Risk.Evaluate([dkPrivateThread, dkPECodeIntegrity], True,
        False, False, True, 1000, Score, D);
      Check(D = [], 'same tick cannot repair a failed observation');
      D := [];
      Risk.Evaluate([dkPrivateThread, dkPECodeIntegrity], True,
        False, False, True, 1001, Score, D);
      Check(dkRiskConfidence in D, 'new valid sample can report');
      Check(Score = 76, 'original positive score preserved');
      D := [];
      Risk.Evaluate([dkPrivateThread, dkPECodeIntegrity], True,
        False, False, True, 900, Score, D);
      Check(D = [], 'reverse-time report rejected');
      D := [];
      Risk.Evaluate([dkPrivateThread, dkPECodeIntegrity], True,
        False, False, True, 901, Score, D);
      Check(D = [], 'clock rollback does not bypass report cooldown');
      D := [];
      Risk.Evaluate([dkPrivateThread, dkPECodeIntegrity], True,
        False, False, True, 60900, Score, D);
      Check(dkRiskConfidence in D, 'rebased cooldown ends at 60 seconds');
      D := [];
      Risk.Evaluate([dkPrivateThread, dkPECodeIntegrity], True,
        False, False, True, 0, Score, D);
      Check(D = [], 'zero tick cannot report');
      Check(Score = 51, 'invalid clock contributes uncertainty');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally Risk.Free; end;
end;

function ValidateV70Regression(out Failure: string;
  out OptionalLiveChecks: Integer): Boolean;
var
  Live, RiskStateChecks: Integer;
  RiskStateFailure: string;
  A, B: TForensicSnapshot;
  View: TLoaderViewCounts;
  FA, FB: TAttestedFileIdentity;
  Chain: TForensicHashChain;
  Kinds: TDetectionKinds;
  Risk: TRiskConfidenceMonitor;
  Family: TRiskFamilies;
  Score: Integer;
  NextKinds: TDetectionKinds;
  procedure Check(Condition: Boolean; const MessageText: string);
  begin
    if not Condition then raise Exception.Create(MessageText);
  end;

  procedure TestPriorRegression;
  begin
    Check(ValidateV60Regression(Failure, Live),
      'v60 regression: ' + Failure);
    Inc(OptionalLiveChecks, Live);
  end;

  procedure TestProcessAndSnapshotIdentity;
  begin
    Check(SameProcessIdentity(456, 101, 456, 101),
      'v67 stable PID+creation');
    Check(not SameProcessIdentity(456, 101, 456, 102),
      'v67 reused PID cannot alias');
    Check(not SameProcessIdentity(456, 0, 456, 0),
      'v67 missing creation time is unknown');
    A := Default(TForensicSnapshot);
    A.Captured := True;
    A.ThreadCount := 4;
    A.HandleCount := 10;
    B := A;
    B.ThreadCount := 5;
    Check(SnapshotCountDelta(A, B, True), 'v61 PSS delta');
    Check(not SnapshotCountDelta(A, B, False), 'v61 no independent evidence');
  end;

  procedure TestLoaderAndFileAttestation;
  begin
    View := Default(TLoaderViewCounts);
    View.Valid := True;
    View.PSAPICount := 25;
    View.ToolhelpCount := 24;
    View.Missing := 1;
    Check(LoaderViewCandidate(View, 3, True), 'v62 corroborated mismatch');
    Check(not LoaderViewCandidate(View, 1, True), 'v62 transient mismatch');
    FA := Default(TAttestedFileIdentity);
    FA.Valid := True;
    FA.Base := $180000000;
    FA.PathFileID := 111;
    FA.MappedNameHash := 222;
    FA.PEImageSize := $4000;
    FB := FA;
    FB.PathFileID := 112;
    Check(AttestationCandidate(FA, FB, 2, True), 'v63 ID shift');
    Check(not AttestationCandidate(FA, FB, 2, False), 'v63 no correlation');
  end;

  procedure TestCallbackReconcileAndObserver;
  begin
    Check(CallbackAttestationCandidate($40000, $50000, True,
      2, True), 'v64 modified callback provenance');
    Check(not CallbackAttestationCandidate($40000, $50000, False,
      2, True), 'v64 legitimate image callback');
    Check(ReconcileCandidate(True, True, True, 2500),
      'v65 established thread/ETW gap');
    Check(not ReconcileCandidate(True, False, True, 5000),
      'v65 trace unavailable is not attack');
    Check(ObserverIdentityMatches(1234, 98765, 1234, 98765),
      'v66 independent identity');
    Check(not ObserverIdentityMatches(1234, 98765, 1234, 98766),
      'v66 independent mismatch');
  end;

  procedure TestRiskConfidenceState;
  begin
    Check(IndependentFamilyCount([rfExternal, rfThread, rfMemory,
      rfTelemetryGap]) = 3, 'v69 independent families');
    Check(ComputeEvidenceConfidence([rfExternal, rfThread,
      rfMemory]) = 76, 'v69 confidence score');
    Check(ComputeEvidenceConfidence([rfExternal, rfThread,
      rfMemory, rfTelemetryGap]) < 76, 'v69 visibility penalty');
    Risk := TRiskConfidenceMonitor.Create;
    Kinds := [dkPrivateThread, dkPECodeIntegrity];
    NextKinds := Kinds;
    Family := Risk.Evaluate(Kinds, True, False, False,
      True, 1000, Score, NextKinds);
    Kinds := NextKinds;
    Check((rfExternal in Family) and (rfThread in Family) and
      (rfMemory in Family) and (dkRiskConfidence in Kinds),
      'v69 independent family gate');
    Kinds := [dkPECodeIntegrity];
    NextKinds := Kinds;
    Risk.Evaluate(Kinds, False, False, False, True,
      1100, Score, NextKinds);
    Kinds := NextKinds;
    Check(not (dkRiskConfidence in Kinds), 'v69 single signal rejection');
    Check(ValidateV70RiskStateCases(RiskStateFailure, RiskStateChecks),
      'v69 state cases: ' + RiskStateFailure);
    Check(RiskStateChecks > 0, 'v69 state checks executed');
  end;

  procedure TestLiveHashChain;
  var
    I: Integer;
  begin
    // Real SHA-256 uses CNG in memory. An unavailable API is UNKNOWN.
    ResolveWinPointers;
    if HashingAvailable then
    begin
      Chain := TForensicHashChain.Create;
      for I := 1 to 300 do
        Check(Chain.Append(UInt64(I), 1234,
          [dkProcess, dkPrivateThread], Byte(76), False),
          'v68 append should succeed');
      Check(Chain.Count = 256, 'v68 bounded RAM ring');
      Check(Chain.Verify, 'v68 linked SHA-256 digest verification');
      Inc(OptionalLiveChecks);
    end;
  end;

  procedure TestLiveLoaderView;
  begin
    // Optional read-only module view smoke. A denied API is UNKNOWN.
    if CaptureLoaderCrossView(View) and View.Valid then
      Inc(OptionalLiveChecks);
  end;

begin
  Result := False;
  Failure := '';
  OptionalLiveChecks := 0;
  Chain := nil;
  Risk := nil;
  try
    try
    TestPriorRegression;
    TestProcessAndSnapshotIdentity;
    TestLoaderAndFileAttestation;
    TestCallbackReconcileAndObserver;
    TestRiskConfidenceState;
    TestLiveHashChain;
    TestLiveLoaderView;
    Result := True;
    except
      on E: Exception do
      begin
        Failure := E.Message;
        OptionalLiveChecks := 0;
      end;
    end;
  finally
    Chain.Free;
    Risk.Free;
  end;
end;

end.
