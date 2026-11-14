program CozyNHW_Refactor10Z_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE10Q_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10Z.Tests.dproj with its fixture defines.'}
{$ENDIF}

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.Types, Cozy.NHW.Logging, Cozy.NHW.WinPointers,
  Cozy.NHW.Capture, Cozy.NHW.BehaviorFingerprint, Cozy.NHW.EphemeralIdentity,
  Cozy.NHW.TemporalHandleGraph, Cozy.NHW.WaitChainRules, Cozy.NHW.WCTNative,
  Cozy.NHW.IncidentReconstruction, Cozy.NHW.StabilityRegression,
  Cozy.NHW.AdvancedRealtimeRegression, Cozy.NHW.ReplayValidation,
  Cozy.NHW.AdvancedRegressionV80;

type
  TFixture = function(out Failure: string; out Checks: Integer): Boolean;
var
  ContractChecks, FixtureChecks, Groups, OptionalChecks: Integer;

procedure Check(Value: Boolean; const Name: string);
begin
  Inc(ContractChecks);
  if not Value then raise Exception.Create(Name);
end;

procedure Existing(const Name: string; Test: TFixture);
var Detail: string; Count: Integer;
begin
  Detail := ''; Count := 0;
  if not Test(Detail, Count) then raise Exception.Create(Name + ': ' + Detail);
  Inc(FixtureChecks, Count);
end;

procedure Done(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure TestCapture;
begin
  // Fixture replaces only its own native input hooks and restores them.
  Existing('capture attempt/time budgets and continuation', TestCapture5L);
  Done('Capture: refresh, inspect, apply signals');
end;

procedure TestBehavior;
var B: TBehaviorFingerprint;
begin
  Existing('actor slots, expiry and rights lanes', TestBehavior5I);
  B := TBehaviorFingerprint.Create;
  try
    Check(B.Score(7, 1000) = 0, 'behavior: empty actor');
    B.Observe(0, ACCESS_VM_READ, False, True, 1000);
    Check(B.Score(0, 1000) = 0, 'behavior: zero alias ignored');
    B.Observe(7, ACCESS_VM_READ, False, False, 1000);
    Check(B.Score(7, 1000) = 0, 'behavior: existing edge not counted');
    B.Observe(7, ACCESS_VM_READ, False, True, 1000);
    B.Observe(7, ACCESS_VM_READ, False, True, 1001);
    Check(B.Score(7, 1001) = 18, 'behavior: two read edges');
    B.Observe(7, ACCESS_VM_WRITE, False, True, 1002);
    Check(B.Score(7, 1002) = 36, 'behavior: same-lane escalation');
    B.Observe(7, THREAD_SET_CONTEXT_RIGHT, True, True, 1003);
    Check(B.Score(7, 1003) = 46, 'behavior: independent thread lane');
    Check(B.Score(7, 16004) = 0, 'behavior: score visibility window');
    B.Reset;
    Check(B.Score(7, 1003) = 0, 'behavior: reset');
  finally B.Free; end;
  Done('BehaviorFingerprint: select, compare, update');
end;

procedure TestIdentity;
var A: TSessionActorIdentity; First, Second: UInt64;
begin
  Existing('alias time order and replacement policy', TestEphemeralIdentity10Q);
  A := TSessionActorIdentity.Create;
  try
    Check(A.Observe(4, 1, 1000) = 0, 'alias: reserved PID');
    Check(A.Observe(700, 0, 1000) = 0, 'alias: unknown creation');
    Check(A.Observe(700, 1, 0) = 0, 'alias: zero time');
    First := A.Observe(700, 1, 1000);
    Check(First <> 0, 'alias: local CNG generation succeeded');
    Check(A.Observe(700, 1, 2000) = First, 'alias: stable existing actor');
    Check(A.Observe(700, 1, 1500) = First, 'alias: old known event resolves');
    Check(A.Observe(701, 1, 1500) = 0, 'alias: old unknown event cannot insert');
    Second := A.Observe(700, 2, 2100);
    Check((Second <> 0) and (Second <> First), 'alias: creation epoch separated');
    Check(A.Existing(700, 1) = First, 'alias: earlier epoch retained while cached');
    A.Reset;
    Check(A.Existing(700, 1) = 0, 'alias: reset');
  finally A.Free; end;
  Done('EphemeralIdentity: choose slot, create unique alias, commit');
end;

procedure TestTemporal;
var G: TTemporalHandleGraph; H: TTargetHolder; D: TDetectionKinds;
begin
  Existing('access sequence time and baseline boundaries', TestTemporalHandleHardening);
  G := TTemporalHandleGraph.Create;
  try
    H := Default(TTargetHolder); H.PID := 700; H.CreateTime := 1;
    H.RightsUnion := ACCESS_QUERY_INFORMATION; D := [];
    G.Observe(H, False, 100, D);
    H.RightsUnion := ACCESS_VM_WRITE; G.Observe(H, False, 200, D);
    Check(D = [], 'temporal: first high observation not enough');
    G.Observe(H, False, 200, D);
    Check(D = [], 'temporal: duplicate does not confirm');
    G.Observe(H, False, 300, D);
    Check(dkTemporalHandleGraph in D, 'temporal: repeated ordered escalation');
    D := []; H.RightsUnion := ACCESS_QUERY_INFORMATION;
    G.Observe(H, False, 400, D);
    H.RightsUnion := ACCESS_VM_WRITE; G.Observe(H, False, 500, D);
    Check(D = [], 'temporal: new sequence does not reuse old counts');
    G.Reset; D := [dkCrossAccess];
    H.CreateTime := 0; G.Observe(H, False, 600, D);
    Check(D = [dkCrossAccess], 'temporal: unknown actor preserves caller flags');
  finally G.Free; end;
  Done('TemporalHandleGraph: access class, state, report');
end;

procedure TestWaitChain;
var N: array[0..2] of TWaitChainNode; T: PWaitThreadNode; F: TWaitFacts;
begin
  Existing('WCT root, chain and failure outputs', TestWaitChainRules10O);
  FillChar(N, SizeOf(N), 0);
  N[0].ObjectType := WCT_OBJECT_THREAD; N[0].ObjectStatus := WCT_STATUS_BLOCKED;
  T := PWaitThreadNode(@N[0].Payload[0]); T^.ProcessId := 700; T^.ThreadId := 701;
  N[1].ObjectType := WCT_OBJECT_CRITICAL_SECTION; N[1].ObjectStatus := 3;
  N[2].ObjectType := WCT_OBJECT_THREAD; N[2].ObjectStatus := 2;
  T := PWaitThreadNode(@N[2].Payload[0]); T^.ProcessId := 800; T^.ThreadId := 801;
  Check(ClassifyWait(@N[0], 3, 700, 701, True, F), 'wait: complete external owner');
  Check(F.Blocked and F.Cycle and F.CriticalSection and F.HasOwner,
    'wait: complete facts');
  Check(F.ExternalOwner and not F.SameProcessOwner and (F.OwnerPID = 800),
    'wait: external owner identity');
  Check(not ClassifyWait(@N[0], 3, 700, 999, True, F), 'wait: mismatching root');
  Check(not F.HasOwner and not F.Cycle and (F.OwnerPID = 0), 'wait: failure publishes no candidate');
  N[2].ObjectStatus := 9;
  Check(not ClassifyWait(@N[0], 3, 700, 701, True, F), 'wait: terminal error node');
  Check(not F.Blocked and not F.CriticalSection, 'wait: partial root facts discarded');
  Check(not ClassifyWait(nil, 3, 700, 701, True, F), 'wait: nil buffer');
  Done('WaitChainRules: bounded copy, root validation, node classification');
end;

procedure TestIncidents;
var R: TIncidentReconstruction; D: TDetectionKinds; F: TInMemoryIncident; J: Integer;
begin
  R := TIncidentReconstruction.Create;
  try
    D := [];
    R.RecordFrame(700, 1, 1000, [], False, True, 90, D);
    Check(R.Count = 0, 'incident: empty visibility creates nothing');
    R.RecordFrame(700, 1, 1100, [dkProcess], True, True, 78, D);
    Check((R.Count = 1) and (D = []), 'incident: first family only');
    R.RecordFrame(700, 1, 1200, [dkPECodeIntegrity, dkPrivateThread], False, True, 78, D);
    Check(dkIncidentReconstruction in D, 'incident: corroborated merged event');
    Check(R.Recent(0, F) and (F.Observations = 2) and (F.ActorPID = 0),
      'incident: observations merge without invented actor');
    D := []; R.RecordFrame(700, 1, 1300, [dkPECodeIntegrity], False, True, 90, D);
    Check(D = [], 'incident: already reported item not repeated');
    Check(R.Recent(0, F) and (F.HighestScore = 90), 'incident: score accumulation');
    R.RecordFrame(700, 2, 1400, [dkProcess], True, True, 1000, D);
    Check(R.Count = 2, 'incident: distinct epoch separate');
    Check(R.Recent(0, F) and (F.HighestScore = 100), 'incident: score cap');
    R.Prune(100000);
    Check(R.Count = 0, 'incident: expired ring removed');
    Check(not R.Recent(0, F), 'incident: empty retrieval');
    for J := 1 to 100 do
      R.RecordFrame(700, Cardinal(J), UInt64(200000 + J), [dkProcess], True, True, 10, D);
    Check(R.Count = 64, 'incident: bounded ring under epoch churn');
    Check(R.Recent(0, F) and (F.Epoch = 100), 'incident: newest retained');
    Check(not R.Recent(64, F), 'incident: index boundary');
  finally R.Free; end;
  Done('IncidentReconstruction: select, accumulate, report, store');
end;

procedure TestStability;
var Detail: string; Count, Live: Integer;
begin
  Detail := ''; Count := 0; Live := 0;
  Check(ValidateStabilization(Detail, Count, Live), 'stability areas: ' + Detail);
  Inc(FixtureChecks, Count); Inc(OptionalChecks, Live);
  Check(Count > 0, 'stability: checks executed');
  Done('StabilityRegression: bounds, faults, budgets, RAM, concurrent ring');
end;

procedure TestRealtime;
begin
  // Existing fixture includes ten constructor-failure injection boundaries,
  // followed by the complete realtime suite with the failure hooks reset.
  Existing('realtime phases and construction failures', TestAdvancedRealtimeRegression10P);
  Done('AdvancedRealtimeRegression: queue, fusion, scheduling, recovery, metrics');
end;

procedure TestReplay;
var Detail: string;
begin
  Existing('replay failure-output and constructor contracts', TestReplayValidation10P);
  Detail := '';
  Check(ValidateReplayRules(Detail), 'replay phase suite: ' + Detail);
  Done('ReplayValidation: pure rules, cadence, graph, history, replay');
end;

procedure TestV80;
var Detail: string; Live: Integer;
begin
  Existing('V80 discontinuity state objects', TestAdvancedRegressionV8010Q);
  Detail := ''; Live := 0;
  Check(ValidateV80Regression(Detail, Live), 'V80 phase suite: ' + Detail);
  Inc(OptionalChecks, Live);
  Done('AdvancedRegressionV80: epochs, execution, causal order, trust, incidents');
end;

begin
  ContractChecks := 0; FixtureChecks := 0; Groups := 0; OptionalChecks := 0;
  try
    ResolveWinPointers;
    TestCapture;
    TestBehavior;
    TestIdentity;
    TestTemporal;
    TestWaitChain;
    TestIncidents;
    TestStability;
    TestRealtime;
    TestReplay;
    TestV80;
    Check(Groups = 10, 'all ten groups completed');
    Writeln('PASS: Refactor10Z groups=', Groups, ' contract_checks=', ContractChecks,
      ' inherited_checks=', FixtureChecks, ' optional_live_checks=', OptionalChecks);
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
