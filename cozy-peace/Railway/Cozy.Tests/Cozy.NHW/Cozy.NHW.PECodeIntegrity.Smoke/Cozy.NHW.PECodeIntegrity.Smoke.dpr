program CozyNHW_PECodeIntegrity_Smoke;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build tests with Win64.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.PECodeIntegrity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PECodeIntegrity.pas';

var
  A, B: TCodeImageDigest;
begin
  try
    ResolveWinPointers;
    if not CaptureExecutableCodeDigest(HInstance, A) then
      raise Exception.Create('PE executable section capture failed');
    if not CaptureExecutableCodeDigest(HInstance, B) then
      raise Exception.Create('PE repeat capture failed');
    if not A.Valid or (A.SectionCount = 0) or
       (A.Value <> B.Value) then
      raise Exception.Create('Unstable code image baseline');
    Writeln('PASS: v38 self PE code baseline');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
