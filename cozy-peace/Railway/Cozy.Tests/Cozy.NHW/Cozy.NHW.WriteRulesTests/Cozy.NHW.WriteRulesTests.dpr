program CozyNHW_WriteRulesTests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 target required'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.WriteRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WriteRules.pas';

procedure Check(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('Write rule test failed');
end;

begin
  Check(WriteCapable(False, ACCESS_VM_WRITE));
  Check(not WriteCapable(True, ACCESS_VM_WRITE));
  Check(not WriteCapable(False, ACCESS_VM_READ));
  Check(NewlyWriteCapable(False, True, False, 0, ACCESS_VM_WRITE));
  Check(not NewlyWriteCapable(False, False, False, ACCESS_VM_WRITE, ACCESS_VM_WRITE));
  Check(RecentWriteObservation(5000, 3500, WRITE_CORRELATION_MS));
  Check(not RecentWriteObservation(5000, 1000, WRITE_CORRELATION_MS));
  Check(CountSetBits($B) = 3);
  Writeln('PASS');
end.
