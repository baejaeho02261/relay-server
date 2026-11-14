program CozyNHW_AdvancedCorrelation_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build tests with Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.SignalCorrelation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SignalCorrelation.pas',
  Cozy.NHW.InjectionEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.InjectionEvidence.pas',
  Cozy.NHW.ETWTypes in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWTypes.pas',
  Cozy.NHW.ETWImageFusion in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWImageFusion.pas',
  Cozy.NHW.RegionClassifier in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RegionClassifier.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas';

procedure Ensure(Condition: Boolean; const TestName: string);
begin
  if not Condition then raise Exception.Create(TestName);
end;

procedure TestSignalCorrelation;
var
  M: TSignalCorrelationMonitor;
  D: TDetectionKinds;
begin
  M := TSignalCorrelationMonitor.Create;
  try
    D := [];
    M.Examine(True, False, 100, D);
    M.Examine(False, True, 200, D);
    Ensure(not (dkMultiSignal in D), 'v37: access alone');
    D := [dkThreadSpawn];
    M.Examine(False, False, 250, D);
    Ensure(dkMultiSignal in D, 'v37: two independent families');
    D := [dkRWX];
    M.Examine(False, False, 300, D);
    Ensure(not (dkMultiSignal in D), 'v37: cooldown');
    M.Reset;
    D := [dkRemoteThread];
    M.Examine(False, False, 20000, D);
    Ensure(not (dkMultiSignal in D), 'v37: no external access');
  finally
    M.Free;
  end;
end;

procedure TestInjectionEvidence;
var
  M: TInjectionEvidenceMonitor;
  D: TDetectionKinds;
begin
  M := TInjectionEvidenceMonitor.Create;
  try
    D := [dkPrivateThread];
    M.Examine(True, False, False, 100, D);
    Ensure(not (dkInjectionEvidence in D), 'v42: thread only');
    D := [];
    M.Examine(True, False, True, 200, D);
    D := [dkPECodeIntegrity];
    M.Examine(True, False, False, 300, D);
    Ensure(dkInjectionEvidence in D, 'v42: three families');
    M.Reset;
    D := [dkPrivateThread];
    M.Examine(False, False, True, 500, D);
    D := [dkPrivateExecRegion];
    M.Examine(False, False, False, 600, D);
    Ensure(not (dkInjectionEvidence in D), 'v42: other PID excluded');
  finally
    M.Free;
  end;
end;

procedure TestETWImageFusion;
var
  M: TETWImageFusionMonitor;
  Events: TKernelEventList;
  Ev: TKernelEvent;
  D: TDetectionKinds;
begin
  M := TETWImageFusionMonitor.Create;
  Events := TKernelEventList.Create;
  try
    Ev := Default(TKernelEvent);
    Ev.Kind := keImageLoad;
    Ev.PID := 999;
    Ev.Tick := 1000;
    Events.Add(Ev);
    D := [];
    M.Examine(Events, 999, False, False, False, 1000, D);
    Ensure(not (dkETWImageFusion in D), 'v40: ordinary image load');
    Events.Clear;
    D := [dkPrivateThread];
    M.Examine(Events, 999, False, False, True, 1100, D);
    Ensure(dkETWImageFusion in D, 'v40: image + rights + origin');
    M.Reset;
    D := [dkPrivateThread];
    M.Examine(Events, 999, False, True, True, 1200, D);
    Ensure(not (dkETWImageFusion in D), 'v40: lost trace');
  finally
    Events.Free;
    M.Free;
  end;
end;

procedure TestRegionRules;
var
  R: TVirtualRegion;
  A, B: TRegionObservation;
begin
  R := Default(TVirtualRegion);
  R.State := ALLOC_MEM_COMMIT;
  R.RegionType := ALLOC_MEM_PRIVATE;
  R.Protect := $04;
  Ensure(ClassifyMemoryRegion(R) = rcPrivateWritable, 'v39: writable');
  A := Default(TRegionObservation);
  A.BaseAddress := $100000;
  A.AllocationBase := $100000;
  A.Size := $1000;
  A.Kind := rcPrivateWritable;
  R.Protect := ALLOC_PAGE_EXECUTE_READ;
  Ensure(ClassifyMemoryRegion(R) = rcPrivateExecutable, 'v39: private RX');
  B := A;
  B.Kind := ClassifyMemoryRegion(R);
  Ensure(SuspiciousPrivateTransition(A, B, True), 'v39: RW -> RX');
  Ensure(not SuspiciousPrivateTransition(B, B, True), 'v39: stable RX');
  R.RegionType := ALLOC_MEM_IMAGE;
  Ensure(ClassifyMemoryRegion(R) = rcImageExecutable, 'v39: image');
  R.RegionType := ALLOC_MEM_MAPPED;
  Ensure(ClassifyMemoryRegion(R) = rcMappedExecutable, 'v39: mapped');
  R.RegionType := ALLOC_MEM_PRIVATE;
  R.Protect := ALLOC_PAGE_EXECUTE_READWRITE;
  B.Kind := ClassifyMemoryRegion(R);
  Ensure(SuspiciousPrivateTransition(A, B, True), 'v39: RW to RWX');
end;

begin
  try
    TestSignalCorrelation;
    TestInjectionEvidence;
    TestETWImageFusion;
    TestRegionRules;
    Writeln('PASS: v37 / v39 / v40 / v42 pure rules');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
