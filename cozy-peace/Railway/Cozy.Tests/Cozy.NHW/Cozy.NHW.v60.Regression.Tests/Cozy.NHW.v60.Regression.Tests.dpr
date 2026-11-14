program CozyNHW_v60_Regression_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Delphi Win64 only.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.ReplayValidation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReplayValidation.pas',
  Cozy.NHW.RegressionLab in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RegressionLab.pas',
  Cozy.NHW.PEView in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PEView.pas',
  Cozy.NHW.ImportRedirection in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ImportRedirection.pas',
  Cozy.NHW.TLSCallbackIntegrity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.TLSCallbackIntegrity.pas',
  Cozy.NHW.UnwindConsistency in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.UnwindConsistency.pas',
  Cozy.NHW.ExecutableLifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExecutableLifecycle.pas',
  Cozy.NHW.SectionBackingIdentity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SectionBackingIdentity.pas',
  Cozy.NHW.ThreadStackProvenance in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadStackProvenance.pas',
  Cozy.NHW.CoverageWindow in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CoverageWindow.pas',
  Cozy.NHW.FalsePositiveControl in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FalsePositiveControl.pas',
  Cozy.NHW.ExplainableEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExplainableEvidence.pas';

var
  Failure: string;
  LiveChecks: Integer;
begin
  try
    if ValidateV60Regression(Failure, LiveChecks) then
      Writeln('PASS: v43-v60 offline regression; optional live checks=',
        LiveChecks)
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
