program CozyNHWNative10OTests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.ETW in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETW.pas',
  Cozy.NHW.NetworkRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NetworkRules.pas',
  Cozy.NHW.ExceptionRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionRules.pas',
  Cozy.NHW.WaitChainRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WaitChainRules.pas',
  Cozy.NHW.FalsePositiveControl in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FalsePositiveControl.pas',
  Cozy.NHW.CaptureRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CaptureRules.pas',
  Cozy.NHW.ObserverAuthenticator in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ObserverAuthenticator.pas',
  Cozy.NHW.FastPipeline in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FastPipeline.pas',
  Cozy.NHW.ResourceController in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ResourceController.pas',
  Cozy.NHW.SensorDisagreement in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SensorDisagreement.pas';
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
    RunGroup('ETW', TestETW10O);
    RunGroup('NetworkRules', TestNetworkRules10O);
    RunGroup('ExceptionRules', TestExceptionRules10O);
    RunGroup('WaitChainRules', TestWaitChainRules10O);
    RunGroup('FalsePositiveControl', TestFalsePositiveControl10O);
    RunGroup('CaptureRules', TestCaptureRules10O);
    RunGroup('ObserverAuthenticator', TestObserverAuthenticator10O);
    RunGroup('FastPipeline', TestFastPipeline10O);
    RunGroup('ResourceController', TestResourceController10O);
    RunGroup('SensorDisagreement', TestSensorDisagreement10O);
    Writeln('PASS: Native10O assertions=', Total);
    Writeln('Synthetic tests do not certify ETW stress, scheduler timing, or full runtime safety.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
