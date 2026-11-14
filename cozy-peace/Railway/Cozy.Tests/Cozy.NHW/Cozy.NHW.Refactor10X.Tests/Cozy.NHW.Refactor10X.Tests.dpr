program CozyNHW_Refactor10X_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5D_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE5D_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5E_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE5E_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5G_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE5G_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5H_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE5H_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5J_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE5J_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5K_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE5K_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE10M_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE10M_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE10N_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10X.Tests.dproj: NHW_NATIVE10N_TESTS is required.'}
{$ENDIF}

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.Types, Cozy.NHW.Logging, Cozy.NHW.ETWTypes, Cozy.NHW.Lifecycle,
  Cozy.NHW.SelfGuard, Cozy.NHW.ImageCOWIntegrity, Cozy.NHW.HandleSharingEvidence,
  Cozy.NHW.ThreadTimeline, Cozy.NHW.ThreadExecutionProvenance, Cozy.NHW.ETWFusion,
  Cozy.NHW.SnapshotETWReconcile, Cozy.NHW.IPC, Cozy.NHW.ExecutableLifecycle,
  Cozy.NHW.ProcessSnapshot;

type
  TFixture = function(out Failure: string; out Checks: Integer): Boolean;
var
  ContractChecks, FixtureChecks, Groups: Integer;

procedure Check(Condition: Boolean; const Name: string);
begin
  Inc(ContractChecks);
  if not Condition then raise Exception.Create(Name);
end;

procedure Existing(const Name: string; Test: TFixture);
var Failure: string; Count: Integer;
begin
  Failure := ''; Count := 0;
  if not Test(Failure, Count) then
    raise Exception.Create(Name + ': ' + Failure);
  Inc(FixtureChecks, Count);
end;

procedure Done(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure TestSelf;
var M: TSelfGuardMonitor; D: TDetectionKinds;
begin
  Existing('identity, PID/TID reuse and failed reads', TestSelfGuard5K);
  M := TSelfGuardMonitor.Create;
  try
    D := [dkCrossAccess];
    M.Examine(nil, nil, False, True, 100, False, 0, D);
    Check(D = [dkCrossAccess], 'self: unavailable baseline preserves incoming signals');
    M.Reset(False);
    M.Examine(nil, nil, True, True, 200, False, 0, D);
    Check(D = [dkCrossAccess], 'self: nil snapshot is not a confirmed new thread');
  finally M.Free; end;
  Done('SelfGuard: retire absent identities and observe live identities');
end;

procedure TestCOW;
begin
  Existing('rotating page budget and query failures', TestImageCOWHardening);
  Check(IsConfirmedCOW(True, False, 2, True), 'COW: confirmed private copy with code evidence');
  Check(not IsConfirmedCOW(False, False, 2, True), 'COW: prior shared evidence required');
  Check(not IsConfirmedCOW(True, True, 2, True), 'COW: still shared is not a private copy');
  Check(not IsConfirmedCOW(True, False, 1, True), 'COW: single sample is insufficient');
  Check(not IsConfirmedCOW(True, False, 2, False), 'COW: code corroboration required');
  Done('ImageCOWIntegrity: inventory, page observations and rotating work');
end;

procedure TestSharing;
var A, B: TSharingHandle;
begin
  Existing('allocation failure, partial snapshot and publication', TestSharing5J);
  A := Default(TSharingHandle);
  A.PID := 100; A.Created := 1; A.ObjectIdentity := $100000;
  A.HandleValue := $80; A.AccessMask := ACCESS_VM_WRITE;
  B := A; B.PID := 200; B.Created := 2; B.HandleValue := $88;
  Check(NHWPotentialSharedHandle(A, B, True), 'sharing: distinct observed owners');
  Check(not NHWPotentialSharedHandle(A, B, False), 'sharing: prior owner must remain present');
  B.PID := A.PID;
  Check(not NHWPotentialSharedHandle(A, B, True), 'sharing: same PID is not cross-owner evidence');
  B.PID := 200; B.Created := 0;
  Check(not NHWPotentialSharedHandle(A, B, True), 'sharing: unknown creation identity excluded');
  B.Created := 2; B.AccessMask := 0;
  Check(not NHWPotentialSharedHandle(A, B, True), 'sharing: sensitive rights overlap required');
  Done('HandleSharingEvidence: build, index, correlate and commit');
end;

procedure TestTimeline;
var M: TThreadTimeline; Entry: TThreadTimelineEvent; D: TDetectionKinds;
begin
  Existing('timeline failure, remap and confirmation fixtures', TestThreadTimelineHardening);
  Check(ThreadTimelineCandidate(True, True, 2, True, True, True), 'timeline: complete corroborated input');
  Check(not ThreadTimelineCandidate(False, True, 2, True, True, True), 'timeline: initial threads are not new');
  Check(not ThreadTimelineCandidate(True, True, 1, True, True, True), 'timeline: confirmation threshold');
  Check(not ThreadTimelineCandidate(True, True, 2, True, True, False), 'timeline: stable epoch required');
  M := TThreadTimeline.Create;
  try
    Check(M.Count = 0, 'timeline: empty history');
    Check(not M.Recent(0, Entry), 'timeline: empty read fails');
    D := [dkCrossAccess];
    M.Examine(False, False, False, False, False, nil, [], 100, D);
    Check((M.Count = 0) and (D = [dkCrossAccess]), 'timeline: non-self reset preserves incoming signal');
  finally M.Free; end;
  Done('ThreadTimeline: retire history and apply one thread sample');
end;

procedure TestExecution;
var M: TThreadExecutionProvenance; D: TDetectionKinds;
begin
  Existing('execution query failures, 64-thread budget and remap', TestThreadExecutionHardening);
  Check(ProvenanceConfirmed(True, 2, 100, 12100), 'execution: inclusive confirmation window');
  Check(not ProvenanceConfirmed(True, 2, 100, 12101), 'execution: expired confirmation window');
  Check(not ProvenanceConfirmed(True, 2, 100, 99), 'execution: reversed observation time');
  Check(not ProvenanceConfirmed(True, 1, 100, 200), 'execution: one confirmation is insufficient');
  Check(not ProvenanceConfirmed(False, 2, 100, 200), 'execution: baseline eligibility retained');
  M := TThreadExecutionProvenance.Create;
  try
    D := [dkCrossAccess]; M.Examine(False, nil, False, False, 100, D);
    Check(D = [dkCrossAccess], 'execution: non-self input does not add a finding');
  finally M.Free; end;
  Done('ThreadExecutionProvenance: retire, query and confirm region');
end;

procedure TestFusion;
var M: TETWFusion; D: TDetectionKinds;
begin
  Existing('ETW event direction, loss and complete-snapshot fixtures', TestETWFusion10N);
  M := TETWFusion.Create;
  try
    D := [dkCrossAccess];
    M.Examine(nil, 100, nil, False, False, True, False, 100, D);
    Check(D = [dkCrossAccess], 'fusion: baseline reset preserves caller findings');
    M.Examine(nil, 100, nil, False, False, False, True, 200, D);
    Check(dkTraceGap in D, 'fusion: overflow still reports trace gap');
    Check(not (dkTransientThread in D), 'fusion: no transient thread inferred from loss');
    D := [dkCrossAccess];
    M.Examine(nil, 100, nil, False, False, False, False, 300, D);
    Check(D = [dkCrossAccess], 'fusion: missing snapshot is not thread absence');
  finally M.Free; end;
  Done('ETWFusion: event-specific updates and final activity correlation');
end;

procedure TestReconcile;
var M: TSnapshotETWReconciler; D: TDetectionKinds;
begin
  Existing('event matching, capacity and gap fixtures', TestSnapshotETWHardening);
  Check(ReconcileCandidate(True, True, True, 2500), 'reconcile: inclusive wait threshold');
  Check(not ReconcileCandidate(True, True, True, 2499), 'reconcile: delivery wait retained');
  Check(not ReconcileCandidate(False, True, True, 3000), 'reconcile: valid snapshot required');
  Check(not ReconcileCandidate(True, False, True, 3000), 'reconcile: healthy trace required');
  Check(not ReconcileCandidate(True, True, False, 3000), 'reconcile: independent evidence required');
  M := TSnapshotETWReconciler.Create;
  try
    D := [dkCrossAccess];
    M.Examine(0, nil, False, False, False, False, False, nil, 100, D);
    Check(D = [dkCrossAccess], 'reconcile: invalid inputs publish no mismatch');
  finally M.Free; end;
  Done('SnapshotETWReconcile: cache, changes, matching and reporting');
end;

procedure TestIPC;
var M: TIPCMonitor; D: TDetectionKinds;
begin
  Existing('IPC aggregation and allocation failure fixtures', TestIPC10M);
  M := TIPCMonitor.Create;
  try
    D := [dkCrossAccess]; M.Examine(nil, False, 100, D);
    Check(D = [dkCrossAccess], 'IPC: invalid snapshot preserves signals');
    M.Examine(nil, True, 200, D);
    Check(D = [dkCrossAccess], 'IPC: nil input is not an empty complete snapshot');
    M.Reset; M.Examine(nil, False, 300, D);
    Check(D = [dkCrossAccess], 'IPC: reset does not infer disappearance');
  finally M.Free; end;
  Done('IPC: aggregate, update, retire and expire');
end;

procedure TestExecutable;
begin
  Existing('executable transition, partial sweep and expiry fixtures', TestExecutableLifecycleHardening);
  Check(ClassifyPrivateProtection($04) = epWritable, 'exec: RW class');
  Check(ClassifyPrivateProtection($20) = epExecutable, 'exec: RX class');
  Check(ClassifyPrivateProtection($40) = epRWX, 'exec: RWX class');
  Check(ClassifyPrivateProtection($140) = epOther, 'exec: guard excluded');
  Check(IsExecutableTransition(epWritable, epExecutable), 'exec: RW to RX retained');
  Check(not IsExecutableTransition(epExecutable, epExecutable), 'exec: unchanged RX excluded');
  Check(not IsExecutableTransition(epRWX, epRWX), 'exec: unchanged RWX excluded');
  Done('ExecutableLifecycle: stage candidates, commit and bounded sweep');
end;

procedure TestSnapshot;
var A, B: TForensicSnapshot;
begin
  Existing('PSS cleanup and query failure fixtures', TestProcessSnapshotHardening);
  A := Default(TForensicSnapshot); A.Captured := True;
  A.ThreadCount := 2; A.RegionCount := 10; A.HandleCount := 100; B := A;
  Check(not SnapshotCountDelta(A, B, True), 'PSS: unchanged counts excluded');
  B.HandleCount := 112;
  Check(not SnapshotCountDelta(A, B, True), 'PSS: handle threshold stays exclusive');
  B.HandleCount := 113;
  Check(SnapshotCountDelta(A, B, True), 'PSS: handle count delta retained');
  Check(not SnapshotCountDelta(A, B, False), 'PSS: independent evidence required');
  B.Captured := False;
  Check(not SnapshotCountDelta(A, B, True), 'PSS: incomplete snapshot excluded');
  B := A; Inc(B.ThreadCount);
  Check(SnapshotCountDelta(A, B, True), 'PSS: thread count delta retained');
  Done('ProcessSnapshot: acquire, query and release under original lock');
end;

begin
  try
    ContractChecks := 0; FixtureChecks := 0; Groups := 0;
    TestSelf; TestCOW; TestSharing; TestTimeline; TestExecution;
    TestFusion; TestReconcile; TestIPC; TestExecutable; TestSnapshot;
    if Groups <> 10 then raise Exception.Create('Incomplete group execution');
    Writeln('PASS Refactor10X: ', Groups, ' groups; ', ContractChecks,
      ' contract checks; ', FixtureChecks, ' inherited fixture checks.');
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln('FAIL Refactor10X: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
