program CozyNHW_Refactor10W_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build this project with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5D_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10W.Tests.dproj: NHW_NATIVE5D_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5E_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10W.Tests.dproj: NHW_NATIVE5E_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5F_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10W.Tests.dproj: NHW_NATIVE5F_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5G_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10W.Tests.dproj: NHW_NATIVE5G_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5I_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10W.Tests.dproj: NHW_NATIVE5I_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE10M_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10W.Tests.dproj: NHW_NATIVE10M_TESTS is required.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE10N_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10W.Tests.dproj: NHW_NATIVE10N_TESTS is required.'}
{$ENDIF}

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.Types, Cozy.NHW.Logging, Cozy.NHW.AllocationNative, Cozy.NHW.StackNative,
  Cozy.NHW.ModuleOriginVerification, Cozy.NHW.SectionBackingIdentity,
  Cozy.NHW.LoaderCrossView, Cozy.NHW.ImportRedirection, Cozy.NHW.TLSCallbackIntegrity,
  Cozy.NHW.ThreadOrigin, Cozy.NHW.StackGuard, Cozy.NHW.WriteWatch,
  Cozy.NHW.Behavior, Cozy.NHW.RegionClassifier;

type
  TExistingGroup = function(out Failure: string; out Checks: Integer): Boolean;

var
  NewChecks, ExistingChecks, Groups: Integer;

procedure Check(Value: Boolean; const Name: string);
begin
  Inc(NewChecks);
  if not Value then raise Exception.Create(Name);
end;

procedure Existing(const Name: string; Test: TExistingGroup);
var Failure: string; Count: Integer;
begin
  Failure := ''; Count := 0;
  if not Test(Failure, Count) then
    raise Exception.Create(Name + ': ' + Failure);
  Inc(ExistingChecks, Count);
end;

procedure Done(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure TestModuleOrigin;
begin
  Existing('module inventory and commit fixtures', TestModuleOriginHardening);
  Check(not ModuleOriginCandidate('C:\App\a.dll', '\Device\Disk\a.dll',
    True, False, True), 'same name and no staging path stays benign');
  Check(ModuleOriginCandidate('C:\Temp\a.dll', '\Device\Disk\a.dll',
    True, False, True), 'new unsigned staging candidate retained');
  Check(not ModuleOriginCandidate('C:\Temp\a.dll', '\Device\Disk\a.dll',
    False, False, True), 'unknown signature is not untrusted');
  Check(not ModuleOriginCandidate('C:\Temp\a.dll', '\Device\Disk\a.dll',
    True, True, True), 'trusted signature excluded');
  Check(not ModuleOriginCandidate('C:\Temp\a.dll', '\Device\Disk\a.dll',
    True, False, False), 'accepted baseline excluded');
  Check(not ModuleOriginCandidate('', '\Device\Disk\a.dll',
    True, False, True), 'failed path read excluded');
  Done('ModuleOriginVerification: staged inventory and publish boundary');
end;

procedure TestSectionBacking;
var A, B: TSectionIdentity;
begin
  Existing('backing capture and identity fixtures', TestSectionBackingHardening);
  A := Default(TSectionIdentity); A.Valid := True; A.Base := $100000;
  A.FileIDKind := sfkFileID128; A.VolumeSerial := 7;
  A.FileID128[0] := 1; A.MappedNameHash := 42; B := A;
  Check(not SectionBackingCandidate(A, B, 2, True), 'identical full identity');
  B.FileID128[15] := 1;
  Check(SectionBackingCandidate(A, B, 2, True), 'high file ID byte compared');
  Check(not SectionBackingCandidate(A, B, 1, True), 'confirmation gate retained');
  Check(not SectionBackingCandidate(A, B, 2, False), 'corroboration gate retained');
  B := A; B.VolumeSerial := 8;
  Check(SectionBackingCandidate(A, B, 2, True), 'volume identity compared');
  B.FileIDKind := sfkLegacy64;
  Check(not SectionBackingCandidate(A, B, 2, True), 'precision change not replacement');
  B := A; B.Valid := False;
  Check(not SectionBackingCandidate(A, B, 2, True), 'incomplete capture excluded');
  Done('SectionBackingIdentity: native ID normalization and candidate phases');
end;

procedure TestLoader;
var C: TLoaderViewCounts;
begin
  Existing('Toolhelp, PSAPI and mismatch fixtures', TestLoaderCrossViewHardening);
  C := Default(TLoaderViewCounts); C.Valid := True; C.Missing := 1;
  Check(LoaderViewCandidate(C, 3, True), 'stable mismatch gate retained');
  Check(not LoaderViewCandidate(C, 2, True), 'two samples not enough');
  Check(not LoaderViewCandidate(C, 3, False), 'independent evidence required');
  C.Valid := False;
  Check(not LoaderViewCandidate(C, 3, True), 'invalid view excluded');
  C.Valid := True; C.Missing := 0;
  Check(not LoaderViewCandidate(C, 3, True), 'equal module sets excluded');
  Done('LoaderCrossView: enumeration, recheck and difference calculation');
end;

procedure TestImports;
begin
  Existing('synthetic Import directory and recheck fixtures', TestImportHardening);
  Check(IsImportRedirectionCandidate(0, 1, 2, True), 'new confirmed risk');
  Check(not IsImportRedirectionCandidate(1, 1, 2, True), 'unchanged risk excluded');
  Check(not IsImportRedirectionCandidate(0, 1, 1, True), 'confirmation count retained');
  Check(not IsImportRedirectionCandidate(0, 1, 2, False), 'independent evidence retained');
  Done('ImportRedirection: directory, slot collection and verification');
end;

procedure TestTLS;
begin
  Existing('synthetic TLS directory and slot fixtures', TestTLSHardening);
  Check(TLSCallbackAnomaly(10, 11, 1, 2, True), 'changed private callback gate');
  Check(not TLSCallbackAnomaly(10, 10, 1, 2, True), 'unchanged digest excluded');
  Check(not TLSCallbackAnomaly(10, 11, 0, 2, True), 'private callback evidence required');
  Check(not TLSCallbackAnomaly(10, 11, 1, 1, True), 'stable observation count retained');
  Check(not TLSCallbackAnomaly(10, 11, 1, 2, False), 'external corroboration retained');
  Done('TLSCallbackIntegrity: directory, callback walk and reread');
end;

procedure TestOrigins;
var G: TThreadOriginMonitor; D: TDetectionKinds;
begin
  Existing('thread selection and lifecycle fixtures', TestThreadOrigin10M);
  G := TThreadOriginMonitor.Create;
  try
    D := [dkCrossAccess];
    G.Examine(0, nil, False, nil, 100, False, False, D);
    Check(G.ObservationFailed, 'missing thread snapshot remains unknown');
    Check(D = [dkCrossAccess], 'unknown input preserves unrelated signals');
    G.Reset;
    Check(not G.ObservationFailed, 'reset clears last-attempt failure');
    G.Examine(0, nil, True, nil, 200, False, False, D);
    Check(G.ObservationFailed, 'nil dictionary invalid even with true flag');
    Check(D = [dkCrossAccess], 'nil input adds no execution evidence');
  finally G.Free; end;
  Done('ThreadOrigin: visible set, per-thread inspection, burst reporting');
end;

procedure TestStacks;
var S: TThreadStackState; C: TNativeStackSnapshot; Signals: TStackSignals;
begin
  Existing('stack gap and confirmation fixtures', TestStackGuard10M);
  S := Default(TThreadStackState); C := Default(TNativeStackSnapshot);
  C.Known := True; C.CreateTime := 1; C.BoundsValid := True; C.HasGuard := True;
  C.StackBase := $90000; C.StackLimit := $80000; C.AllocationBase := $70000;
  C.ReservedBytes := $20000; C.CommittedBytes := $10000;
  S.Snapshot := C; S.WindowTick := 1; S.WindowCommit := C.CommittedBytes;
  Signals := AnalyzeStackTransition(S, C, 100);
  Check(Signals = [], 'unchanged stack has no transition');
  C.Known := False; Signals := AnalyzeStackTransition(S, C, 200);
  Check((Signals = []) and S.ObservationGap, 'failed observation breaks continuity');
  C.Known := True; C.HasGuard := False;
  Signals := AnalyzeStackTransition(S, C, 300);
  Check((Signals = []) and not S.ObservationGap, 'recovery starts but does not finish confirmation');
  Check(S.GuardMissing = 1, 'fresh recovery sample counted once');
  Signals := AnalyzeStackTransition(S, C, 400);
  Check(not (ssGuard in Signals), 'second guard sample remains pending');
  Signals := AnalyzeStackTransition(S, C, 500);
  Check(ssGuard in Signals, 'third comparable guard sample reports');
  Signals := AnalyzeStackTransition(S, C, 600);
  Check(not (ssGuard in Signals), 'same guard incident remains suppressed');
  C.HasGuard := True; AnalyzeStackTransition(S, C, 700);
  Check(not S.GuardReported, 'restored guard rearms suppression');
  Done('StackGuard: recovery, bounds, guard, growth, sample application');
end;

procedure TestWrites;
var G: TWriteWatchMonitor; D: TDetectionKinds;
begin
  Existing('canary copy and episode fixtures', TestWriteWatch5I);
  G := TWriteWatchMonitor.Create;
  try
    Check(G.RegionAddress = 0, 'unarmed monitor exposes no region');
    G.Reset(0); // non-self target: does not allocate the canary
    Check(G.RegionAddress = 0, 'non-self reset stays disabled');
    Check(not G.ObservationFailed, 'reset is not an observation failure');
    D := [dkCrossAccess]; G.Examine(0, 100, D);
    Check(D = [dkCrossAccess], 'disabled monitor preserves incoming detection');
  finally G.Free; end;
  Done('WriteWatch: preparation, episodes and separate reporting rules');
end;

procedure TestBehavior;
var G: TBehaviorMonitor; H: TTargetHolder; D: TDetectionKinds; I: Integer;
  procedure AddOwners(Tick: UInt64; Baseline: Boolean);
  var J: Integer;
  begin
    G.BeginSnapshot(Tick, Baseline, Baseline, True);
    for J := 1 to 3 do
    begin
      H := Default(TTargetHolder); H.PID := Cardinal(100+J);
      H.CreateTime := 1000; H.HandleCount := 1;
      G.Observe(H, True, False, False, Baseline);
    end;
    G.EndSnapshot(D);
  end;
begin
  Existing('owner lifetime and exception fixtures', TestBehavior10N);
  G := TBehaviorMonitor.Create;
  try
    D := []; AddOwners(100, True);
    Check(not (dkCrossAccess in D), 'startup owners are not new cross access');
    G.Reset; D := []; AddOwners(200, False);
    Check(dkCrossAccess in D, 'three independent arrivals still correlate');
    D := []; AddOwners(300, False);
    Check(not (dkCrossAccess in D), 'same arrivals do not repeat cross alert');
    for I := 1 to 4 do
    begin
      D := []; AddOwners(UInt64(300 + I*100), False);
      Check(not (dkAccessBurst in D), 'stable handle counts do not form access burst');
    end;
    G.Reset; D := []; G.BeginSnapshot(1000, False, False, True); G.EndSnapshot(D);
    Check(D = [], 'empty snapshot remains empty');
  finally G.Free; end;
  Done('Behavior: arrival, thread/churn/access/cross rules and expiry');
end;

procedure TestRegions;
var R: TVirtualRegion; A, B: TRegionObservation;
begin
  Existing('region commit and failure fixtures', TestRegionClassifier10N);
  R := Default(TVirtualRegion); R.State := ALLOC_MEM_COMMIT;
  R.RegionType := ALLOC_MEM_PRIVATE; R.Protect := ALLOC_PAGE_EXECUTE_READWRITE;
  Check(ClassifyMemoryRegion(R) = rcPrivateRWX, 'private RWX classification');
  R.Protect := R.Protect or ALLOC_PAGE_GUARD;
  Check(ClassifyMemoryRegion(R) = rcOther, 'guard page remains excluded');
  A := Default(TRegionObservation); A.BaseAddress := $10000;
  A.AllocationBase := $10000; A.Size := $1000; A.Kind := rcPrivateWritable;
  B := A; B.Kind := rcPrivateExecutable;
  Check(SuspiciousPrivateTransition(A, B, True), 'same allocation RW to RX');
  Check(not SuspiciousPrivateTransition(A, B, False), 'unobserved old RX is not transition');
  B.Kind := rcPrivateRWX;
  Check(SuspiciousPrivateTransition(A, B, False), 'new RWX contract retained');
  B.AllocationBase := $20000;
  Check(not SuspiciousPrivateTransition(A, B, True), 'different allocation not old transition');
  Done('RegionClassifier: candidates, complete commit and bounded sweep');
end;

begin
  try
    TestModuleOrigin;
    TestSectionBacking;
    TestLoader;
    TestImports;
    TestTLS;
    TestOrigins;
    TestStacks;
    TestWrites;
    TestBehavior;
    TestRegions;
    Check(Groups = 10, 'all ten groups ran');
    Writeln('PASS: groups=', Groups, '; new checks=', NewChecks,
      '; reused fixture checks=', ExistingChecks);
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
