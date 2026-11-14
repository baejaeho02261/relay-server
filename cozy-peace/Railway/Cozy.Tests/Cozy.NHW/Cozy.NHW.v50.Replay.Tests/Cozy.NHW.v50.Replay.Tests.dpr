program CozyNHW_v50_Replay_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Delphi Win64 test only.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.ReplayValidation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReplayValidation.pas',
  Cozy.NHW.AdaptiveInspector in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdaptiveInspector.pas',
  Cozy.NHW.EvidenceChain in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.EvidenceChain.pas',
  Cozy.NHW.ETWLossHealth in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWLossHealth.pas',
  Cozy.NHW.ImageCOWIntegrity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ImageCOWIntegrity.pas',
  Cozy.NHW.ModuleOriginVerification in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ModuleOriginVerification.pas',
  Cozy.NHW.TemporalHandleGraph in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.TemporalHandleGraph.pas',
  Cozy.NHW.ThreadExecutionProvenance in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadExecutionProvenance.pas';

var
  Failure: string;
begin
  try
    if ValidateReplayRules(Failure) then
      Writeln('PASS: v43-v50 offline rules and replay')
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
