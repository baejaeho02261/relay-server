program CozyNHW_Stability_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Delphi Win64 required.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.StabilityRegression in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.StabilityRegression.pas';

var
  Failure: string;
  PassedChecks, OptionalChecks: Integer;
begin
  if ValidateStabilization(Failure, PassedChecks, OptionalChecks) then
    Writeln('PASS: stabilization assertions=', PassedChecks,
      '; optional live checks=', OptionalChecks)
  else
  begin
    Writeln('FAIL: ', Failure);
    ExitCode := 1;
  end;
end.
