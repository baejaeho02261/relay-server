program CozyNHW_v70_Regression_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64 only.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.AdvancedRegression in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdvancedRegression.pas';

var
  Failure: string;
  OptionalLiveChecks: Integer;
begin
  try
    if ValidateV70Regression(Failure, OptionalLiveChecks) then
      Writeln('PASS: v1-v70 rules; optional live checks=',
        OptionalLiveChecks)
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
