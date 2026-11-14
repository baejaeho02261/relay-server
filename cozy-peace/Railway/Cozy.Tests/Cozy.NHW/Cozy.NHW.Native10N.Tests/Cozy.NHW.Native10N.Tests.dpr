program CozyNHWNative10NTests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.AllocationGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationGuard.pas',
  Cozy.NHW.RegionClassifier in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RegionClassifier.pas',
  Cozy.NHW.ExportNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExportNative.pas',
  Cozy.NHW.ExportGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExportGuard.pas',
  Cozy.NHW.PERules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PERules.pas',
  Cozy.NHW.ETWFusion in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWFusion.pas',
  Cozy.NHW.PathNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PathNative.pas',
  Cozy.NHW.Behavior in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Behavior.pas',
  Cozy.NHW.DualObserver in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.DualObserver.pas',
  Cozy.NHW.Job in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Job.pas';
type TGroup = function(out Failure: string; out Checks: Integer): Boolean;
var Total: Integer;
procedure RunGroup(const Name: string; Test: TGroup);
var Failure: string; Checks: Integer;
begin
  if not Test(Failure, Checks) then raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks); Writeln('PASS: ', Name, ' assertions=', Checks);
end;
begin
  Total := 0;
  try
    RunGroup('AllocationGuard', TestAllocationGuard10N);
    RunGroup('RegionClassifier', TestRegionClassifier10N);
    RunGroup('ExportNative', TestExportNative10N);
    RunGroup('ExportGuard', TestExportGuard10N);
    RunGroup('PERules', TestPERules10N);
    RunGroup('ETWFusion', TestETWFusion10N);
    RunGroup('PathNative', TestPathNative10N);
    RunGroup('Behavior', TestBehavior10N);
    RunGroup('DualObserver', TestDualObserver10N);
    RunGroup('Job', TestJob10N);
    Writeln('PASS: Native10N assertions=', Total);
    Writeln('Synthetic contract tests do not certify Windows concurrency or complete detection.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
