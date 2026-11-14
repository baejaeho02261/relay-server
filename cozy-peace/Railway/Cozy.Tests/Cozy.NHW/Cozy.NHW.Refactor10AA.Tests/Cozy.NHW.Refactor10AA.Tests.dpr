program CozyNHW_Refactor10AA_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only.'}
{$ENDIF}
{$IFNDEF NHW_REFACTOR10AA_TESTS}
  {$MESSAGE FATAL 'Build Cozy.NHW.Refactor10AA.Tests.dproj with its fixture defines.'}
{$ENDIF}

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.Logging, Cozy.NHW.WinPointers,
  Cozy.NHW.ControlFlowAttestation, Cozy.NHW.IndirectTargets, Cozy.NHW.UnwindConsistency,
  Cozy.NHW.CausalGraph, Cozy.NHW.NetworkGuard, Cozy.NHW.SensorRecovery, Cozy.NHW.AdaptiveAnomaly,
  Cozy.NHW.AdvancedPrivacyRegressionV100, Cozy.NHW.AdvancedRegression, Cozy.NHW.RegressionLab;

type TFixture = function(out Failure: string; out Checks: Integer): Boolean;
var
  DirectChecks, FixtureChecks, Groups, LiveChecks: Integer;

procedure Check(Value: Boolean; const Why: string);
begin
  Inc(DirectChecks);
  if not Value then raise Exception.Create(Why);
end;

procedure Existing(const Name: string; Test: TFixture);
var Detail: string; Count: Integer;
begin
  Detail := ''; Count := 0;
  if not Test(Detail, Count) then raise Exception.Create(Name + ': ' + Detail);
  Check(Count > 0, Name + ': fixture performed no checks');
  Inc(FixtureChecks, Count);
end;

procedure Done(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure ControlFlowGroup;
begin
  Existing('control flow observation failures and candidate continuity', TestControlFlowHardening);
  Check(CallbackAttestationCandidate($1000, $2000, True, 2, True), 'callback: confirmed private change');
  Check(not CallbackAttestationCandidate($1000, $2000, True, 1, True), 'callback: single sample');
  Check(not CallbackAttestationCandidate($1000, $1000, True, 2, True), 'callback: same target');
  Check(not CallbackAttestationCandidate(0, $2000, True, 2, True), 'callback: unregistered');
  Check(not CallbackAttestationCandidate($1000, $2000, False, 2, True), 'callback: image target');
  Check(not CallbackAttestationCandidate($1000, $2000, True, 2, False), 'callback: no corroboration');
  Done('ControlFlowAttestation');
end;

procedure IndirectTargetGroup;
begin
  Existing('indirect address relationships and epoch boundaries', TestIndirectTargetsHardening);
  Check(IndirectTargetCandidate(True, True, 2, True, True), 'indirect: confirmed relation');
  Check(not IndirectTargetCandidate(False, True, 2, True, True), 'indirect: original not image');
  Check(not IndirectTargetCandidate(True, False, 2, True, True), 'indirect: current not private');
  Check(not IndirectTargetCandidate(True, True, 1, True, True), 'indirect: one observation');
  Check(not IndirectTargetCandidate(True, True, 2, False, True), 'indirect: no corroboration');
  Check(not IndirectTargetCandidate(True, True, 2, True, False), 'indirect: unstable epoch');
  Done('IndirectTargets');
end;

procedure UnwindGroup;
begin
  Existing('unwind capture failure, evidence expiry and exceptions', TestUnwindHardening);
  Check(UnwindStructuralCandidate(10, 11, 2, True), 'unwind: changed confirmed digest');
  Check(not UnwindStructuralCandidate(10, 10, 2, True), 'unwind: unchanged digest');
  Check(not UnwindStructuralCandidate(10, 11, 1, True), 'unwind: pending');
  Check(not UnwindStructuralCandidate(10, 11, 2, False), 'unwind: no independent evidence');
  Done('UnwindConsistency');
end;

procedure CausalGroup;
var G: TCausalAttackGraph; D: TDetectionKinds; S: TCorrelatedSequence;
begin
  G := TCausalAttackGraph.Create;
  try
    D := [];
    G.Examine(True, False, True, True, 700, 1, True, [], 1000, D);
    Check(D = [], 'causal: access alone');
    G.Examine(True, False, True, True, 700, 1, False, [dkPECodeIntegrity], 1100, D);
    Check(D = [], 'causal: memory still awaits thread');
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 1200, D);
    Check(dkCausalSequence in D, 'causal: ordered evidence confirmed');
    S := G.LastSequence;
    Check((S.TargetPID = 700) and (S.Epoch = 1), 'causal: target and epoch retained');
    Check((S.AccessTick = 1000) and (S.MemoryTick = 1100) and (S.ThreadTick = 1200), 'causal: exact timestamps');
    Check((S.ActorPID = 0) and S.ConfirmedTemporalOrder, 'causal: no invented actor');
    D := [];
    G.Examine(True, False, True, True, 700, 1, True, [], 1200, D);
    Check(D = [], 'causal: duplicate timestamp ignored');
    G.Examine(True, False, True, True, 700, 1, True, [], 1300, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPECodeIntegrity], 1400, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 1500, D);
    Check(D = [], 'causal: report cooldown retained');
    Check(G.LastSequence.ThreadTick = 1200, 'causal: unreported sequence does not replace history');
    G.Reset; D := [];
    G.Examine(True, False, True, True, 700, 1, True, [], 2000, D);
    G.ObservationGap;
    G.Examine(True, False, True, True, 700, 1, False, [dkPECodeIntegrity], 2100, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 2200, D);
    Check(D = [], 'causal: gap severs prior access');
    G.Examine(True, False, True, True, 700, 1, True, [], 2300, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPECodeIntegrity], 2400, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 2400, D);
    Check(D = [], 'causal: memory and thread cannot share a tick');
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 2500, D);
    Check(dkCausalSequence in D, 'causal: new ordered sample reports');
    G.Reset; D := [];
    G.Examine(True, False, True, True, 700, 1, True, [], 3000, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPECodeIntegrity], 3100, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 3050, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 3200, D);
    Check(D = [], 'causal: rollback invalidates pending sequence');
    G.Reset; D := [dkProcess];
    G.Examine(True, False, True, True, 0, 1, True, [], 4000, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPECodeIntegrity], 4100, D);
    G.Examine(True, False, True, True, 700, 1, False, [dkPrivateThread], 4200, D);
    Check(D = [dkProcess], 'causal: unknown PID not accepted and caller flags preserved');
    G.Reset; D := [];
    G.Examine(True, False, True, True, 700, 1, True, [], 5000, D);
    G.Examine(True, False, True, True, 700, 2, False, [dkPECodeIntegrity], 5100, D);
    G.Examine(True, False, True, True, 700, 2, False, [dkPrivateThread], 5200, D);
    Check(D = [], 'causal: epoch change disconnects old access');
    Check(CausalSequenceCandidate(1, 2, 20001, True, True), 'causal: inclusive 20 second window');
    Check(not CausalSequenceCandidate(1, 2, 20002, True, True), 'causal: expired window');
    Check(not CausalSequenceCandidate(1, 2, 3, False, True), 'causal: invalid identity');
    Check(not CausalSequenceCandidate(1, 2, 3, True, False), 'causal: unreliable visibility');
  finally G.Free; end;
  Done('CausalGraph');
end;

procedure NetworkGroup;
begin
  Existing('network snapshot failures and all list cleanup boundaries', TestNetworkGuard5L);
  Done('NetworkGuard');
end;

procedure RecoveryGroup;
var R: TSensorCoverageRecovery; D: TDetectionKinds;
begin
  Existing('counter decrease, overflow and warning windows', TestRecovery5J);
  R := TSensorCoverageRecovery.Create;
  try
    D := [];
    R.Observe(True, False, 10, 0, 500, 1000, D);
    Check((R.LastCounterStatus = dcsBaseline) and (R.ReportedLoss = 0), 'recovery: initial count is baseline');
    Check(D = [], 'recovery: baseline no warning');
    R.Observe(True, False, 13, 0, 500, 1001, D);
    Check((R.LastCounterStatus = dcsAdvanced) and (R.ReportedLoss = 3), 'recovery: only delta counted');
    Check(dkObservationUncertain in D, 'recovery: advanced count warns');
    Check(R.Degraded(1002), 'recovery: visibility degradation interval');
    D := []; R.Observe(True, False, 13, 0, 500, 1002, D);
    Check((R.LastCounterStatus = dcsStable) and (D = []), 'recovery: stable counter');
    R.Observe(True, False, 1, 0, 500, 1003, D);
    Check((R.LastCounterStatus = dcsDecreaseUnknown) and (R.ReportedLoss = 3), 'recovery: decrease not invented loss');
    Check(D = [], 'recovery: repeated warning cooldown');
    R.Observe(False, False, 0, 0, 500, 1004, D);
    Check(R.LastCounterStatus = dcsUnavailable, 'recovery: disabled trace');
    R.Observe(True, False, 100, 0, 500, 1005, D);
    Check((R.LastCounterStatus = dcsBaseline) and (R.ReportedLoss = 3), 'recovery: new baseline after unavailable');
    R.Reset;
    Check((R.ReportedLoss = 0) and not R.Degraded(1006), 'recovery: reset');
  finally R.Free; end;
  Done('SensorRecovery');
end;

procedure AnomalyGroup;
var A: TAdaptiveAnomaly; I: Integer;
begin
  Existing('elapsed-time normalized learning and gap contracts', TestAnomaly5J);
  A := TAdaptiveAnomaly.Create;
  try
    A.Observe(1, False, True, 1000);
    Check(not A.State.SampleValid, 'anomaly: first observation only anchors');
    for I := 1 to 8 do A.Observe(1, False, True, UInt64(1000 + I * 1000));
    Check(A.State.ValidSamples = 8, 'anomaly: eight valid intervals');
    Check((A.State.MeanX8 = 8) and not A.State.Anomalous, 'anomaly: one edge per second');
    A.Observe(40, False, True, 10000);
    Check(A.State.Anomalous and (A.State.AnomalyCount = 1), 'anomaly: burst classified');
    Check((A.State.ValidSamples = 8) and (A.State.MeanX8 = 8), 'anomaly: burst excluded from learning');
    A.Observe(100, False, False, 11000);
    Check(not A.State.SampleValid and not A.State.Anomalous, 'anomaly: failed observation');
    A.Observe(1, False, True, 12000);
    Check(not A.State.SampleValid, 'anomaly: recovery first anchor');
    A.Observe(1, False, True, 13000);
    Check(A.State.SampleValid and (A.State.ValidSamples = 9), 'anomaly: recovery valid interval');
    A.Observe(1, False, True, 13000);
    Check(not A.State.SampleValid, 'anomaly: duplicate cannot train');
    A.Reset;
    Check((A.State.ValidSamples = 0) and (A.State.AnomalyCount = 0), 'anomaly: reset');
  finally A.Free; end;
  Done('AdaptiveAnomaly');
end;

procedure PrivacyGroup;
var Detail: string;
begin
  Existing('privacy partial construction release paths', TestPrivacyConstructionAA);
  Detail := '';
  if not ValidatePrivacyV100(Detail) then raise Exception.Create('privacy suite: ' + Detail);
  Check(True, 'privacy: complete suite after injection is disabled');
  Done('AdvancedPrivacyRegressionV100');
end;

procedure AdvancedRegressionGroup;
var Detail: string; Count: Integer;
begin
  Existing('V70 actual risk monitor discontinuity cases', ValidateV70RiskStateCases);
  Detail := ''; Count := 0;
  if not ValidateV70Regression(Detail, Count) then raise Exception.Create('V70 suite: ' + Detail);
  Check(Count >= 0, 'V70: optional live count is nonnegative');
  Inc(LiveChecks, Count);
  Done('AdvancedRegression');
end;

procedure RegressionLabGroup;
var Detail: string; Count: Integer;
begin
  Existing('full section identity compatibility cases', TestRegressionLab10Q);
  Detail := ''; Count := 0;
  if not ValidateV60Regression(Detail, Count) then raise Exception.Create('V60 suite: ' + Detail);
  Check(Count >= 0, 'V60: optional live count is nonnegative');
  Inc(LiveChecks, Count);
  Done('RegressionLab');
end;

begin
  DirectChecks := 0; FixtureChecks := 0; Groups := 0; LiveChecks := 0;
  try
    ResolveWinPointers;
    ControlFlowGroup;
    IndirectTargetGroup;
    UnwindGroup;
    CausalGroup;
    NetworkGroup;
    RecoveryGroup;
    AnomalyGroup;
    PrivacyGroup;
    AdvancedRegressionGroup;
    RegressionLabGroup;
    Check(Groups = 10, 'all ten groups completed');
    Writeln('PASS: Refactor10AA groups=', Groups, ' direct_checks=', DirectChecks,
      ' fixture_checks=', FixtureChecks, ' optional_live_checks=', LiveChecks);
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
