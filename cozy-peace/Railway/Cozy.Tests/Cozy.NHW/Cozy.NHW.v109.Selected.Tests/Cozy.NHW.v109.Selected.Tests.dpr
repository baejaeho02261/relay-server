program CozyNHW_v109_Selected_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Delphi Win64 required.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.HandleSharingEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HandleSharingEvidence.pas',
  Cozy.NHW.APCStyleEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.APCStyleEvidence.pas',
  Cozy.NHW.SensorTamperHealth in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SensorTamperHealth.pas',
  Cozy.NHW.SelectedRegressionV109 in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelectedRegressionV109.pas';

var Failure: string;
begin
  if ValidateSelectedV109(Failure) then
    Writeln('PASS: v101/v104/v109 synthetic regression')
  else
  begin
    Writeln('FAIL: ', Failure);
    ExitCode := 1;
  end;
end.
