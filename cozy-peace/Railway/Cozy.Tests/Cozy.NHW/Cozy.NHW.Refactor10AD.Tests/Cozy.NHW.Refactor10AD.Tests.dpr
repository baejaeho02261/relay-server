program CozyNHW_Refactor10AD_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}{$MESSAGE FATAL 'Win64 only.'}{$ENDIF}
{$IFNDEF NHW_REFACTOR10AD_TESTS}{$MESSAGE FATAL 'Use Cozy.NHW.Refactor10AD.Tests.dproj.'}{$ENDIF}
uses Winapi.Windows, System.SysUtils,
  Cozy.NHW.EventDrivenWake, Cozy.NHW.ExportGuard, Cozy.NHW.MicroburstAccess,
  Cozy.NHW.NetworkRules, Cozy.NHW.ObserverAttestation, Cozy.NHW.PELoader,
  Cozy.NHW.PathRules, Cozy.NHW.Sampling, Cozy.NHW.SignalCorrelation,
  Cozy.NHW.SelectedRegressionV109;
type TFixture = function(out Failure: string; out Checks: Integer): Boolean;
var DirectChecks, FixtureChecks, Groups: Integer;
procedure Check(V:Boolean; const Why:string); begin Inc(DirectChecks); if not V then raise Exception.Create(Why); end;
procedure Existing(const N:string; T:TFixture); var F:string; C:Integer; begin F:=''; C:=0; if not T(F,C) then raise Exception.Create(N+': '+F); Check(C>0,N+': no checks'); Inc(FixtureChecks,C); Inc(Groups); end;
procedure SelectedRegression; var F:string; begin F:=''; if not ValidateSelectedV109(F) then raise Exception.Create('SelectedV109: '+F); Inc(Groups); end;
begin DirectChecks:=0; FixtureChecks:=0; Groups:=0; try
  Existing('EventDrivenWake',TestEventDrivenWake5K);
  Existing('ExportGuard',TestExportGuard10N);
  Existing('MicroburstAccess',TestMicroburstAccess10P);
  Existing('NetworkRules',TestNetworkRules10O);
  Existing('ObserverAttestation',TestObserverAttestation10Q);
  Existing('PELoader',TestPELoader10M);
  Existing('PathRules',TestPathRules10Q);
  Existing('Sampling',TestSamplingFinal12);
  Existing('SignalCorrelation',TestSignalCorrelation10Q);
  SelectedRegression;
  Check(Groups=10,'group count');
  Writeln('PASS: Refactor10AD groups=',Groups,' direct=',DirectChecks,' fixture=',FixtureChecks);
except on E:Exception do begin Writeln('FAIL: ',E.ClassName,': ',E.Message); Halt(1); end; end; end.
