program CozyNHW_v100_Regression_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build only for Delphi Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
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
  Cozy.NHW.AdvancedRealtimeRegression in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdvancedRealtimeRegression.pas',
  Cozy.NHW.EphemeralIdentity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.EphemeralIdentity.pas',
  Cozy.NHW.PrecisionTimeline in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PrecisionTimeline.pas',
  Cozy.NHW.BehaviorFingerprint in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.BehaviorFingerprint.pas',
  Cozy.NHW.SensorConsensus in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SensorConsensus.pas',
  Cozy.NHW.MemoryEvidenceCapsule in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MemoryEvidenceCapsule.pas',
  Cozy.NHW.AdaptiveAnomaly in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdaptiveAnomaly.pas',
  Cozy.NHW.SensorDisagreement in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SensorDisagreement.pas',
  Cozy.NHW.ObserverAuthenticator in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ObserverAuthenticator.pas',
  Cozy.NHW.PrivacyForensics in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PrivacyForensics.pas',
  Cozy.NHW.AdvancedPrivacyRegressionV100 in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdvancedPrivacyRegressionV100.pas';

var
  Failure: string;
begin
  try
    if ValidateRealtimeV90(Failure) and ValidatePrivacyV100(Failure) then
      Writeln('PASS: v81-v100 synthetic regression')
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
