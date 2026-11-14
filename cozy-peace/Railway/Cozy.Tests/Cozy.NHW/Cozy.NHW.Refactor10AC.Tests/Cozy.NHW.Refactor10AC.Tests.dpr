program CozyNHW_Refactor10AC_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}{$MESSAGE FATAL 'Win64 only.'}{$ENDIF}
{$IFNDEF NHW_REFACTOR10AC_TESTS}{$MESSAGE FATAL 'Use Cozy.NHW.Refactor10AC.Tests.dproj.'}{$ENDIF}
uses Winapi.Windows, System.SysUtils, Cozy.NHW.Logging, Cozy.NHW.AsyncNative, Cozy.NHW.ETWLossHealth,
  Cozy.NHW.ETWImageFusion, Cozy.NHW.MappingNative, Cozy.NHW.ObservationTrust, Cozy.NHW.RiskConfidence,
  Cozy.NHW.InjectionEvidence, Cozy.NHW.WriteWatchNative, Cozy.NHW.CoverageWindow;
type TFixture = function(out Failure: string; out Checks: Integer): Boolean;
var DirectChecks, FixtureChecks, Groups: Integer;
procedure Check(V:Boolean; const Why:string); begin Inc(DirectChecks); if not V then raise Exception.Create(Why); end;
procedure Existing(const N:string; T:TFixture); var F:string; C:Integer; begin F:=''; C:=0; if not T(F,C) then raise Exception.Create(N+': '+F); Check(C>0,N+': no checks'); Inc(FixtureChecks,C); Inc(Groups); end;
procedure DirectContracts; var R:TRiskConfidenceMonitor; S:Integer; K,O:TDetectionKinds; F:TRiskFamilies; begin
  K:=[]; O:=[]; R:=TRiskConfidenceMonitor.Create; try F:=R.Evaluate(K,False,False,False,True,1,S,O,True); Check(F=[],'Risk empty'); Check(S=0,'Risk score'); finally R.Free; end;
  ReportDetections([]); Inc(Groups);
end;
begin DirectChecks:=0; FixtureChecks:=0; Groups:=0; try
  Existing('AsyncNative',TestAsyncNativeHardening); Existing('ETWLoss',TestETWLoss5J);
  Existing('ETWImage',TestETWImage5I); Existing('MappingNative',TestMappingHardening);
  Existing('ObservationTrust',TestObservationTrust10P); Existing('InjectionEvidence',TestInjectionEvidence10Q);
  Existing('WriteWatchNative',TestWriteWatchHardening); Existing('CoverageWindow',TestCoverageWindow10P);
  DirectContracts; Check(Groups=9,'group count'); Writeln('PASS: Refactor10AC groups=',Groups,' direct=',DirectChecks,' fixture=',FixtureChecks);
except on E:Exception do begin Writeln('FAIL: ',E.ClassName,': ',E.Message); Halt(1); end; end; end.
