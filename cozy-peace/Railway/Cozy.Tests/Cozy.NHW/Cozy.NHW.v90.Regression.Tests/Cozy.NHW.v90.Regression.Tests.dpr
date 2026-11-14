program CozyNHW_v90_Regression_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build only for Delphi Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.ETWTypes in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWTypes.pas',
  Cozy.NHW.FastEventRing in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FastEventRing.pas',
  Cozy.NHW.HighResolutionClock in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HighResolutionClock.pas',
  Cozy.NHW.EventDrivenWake in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.EventDrivenWake.pas',
  Cozy.NHW.RealtimeFusion in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RealtimeFusion.pas',
  Cozy.NHW.FastPipeline in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FastPipeline.pas',
  Cozy.NHW.MicroburstAccess in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MicroburstAccess.pas',
  Cozy.NHW.TriggeredSnapshot in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.TriggeredSnapshot.pas',
  Cozy.NHW.MemoryDelta in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MemoryDelta.pas',
  Cozy.NHW.SensorRecovery in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SensorRecovery.pas',
  Cozy.NHW.RealtimeBenchmark in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RealtimeBenchmark.pas',
  Cozy.NHW.AdvancedRealtimeRegression in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdvancedRealtimeRegression.pas';

var
  Failure: string;
begin
  try
    if ValidateRealtimeV90(Failure) then
      Writeln('PASS: v81-v90 synthetic regression')
    else
    begin
      Writeln('FAIL: ', Failure);
      ExitCode := 1;
    end;
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
