program CozyNHW_AsyncRules_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.AsyncRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AsyncRules.pas';

procedure Check(Value: Boolean);
begin
  if not Value then raise Exception.Create('Async validation test failed');
end;

begin
  Check(ExpectedCompletion($1234, $1234, $AA55, $AA55, nil));
  Check(not ExpectedCompletion($1235, $1234, $AA55, $AA55, nil));
  Check(not ExpectedCompletion($1234, $1234, $AA56, $AA55, nil));
  Check(not ExpectedCompletion($1234, $1234, $AA55, $AA55, Pointer(1)));
  Check(WorkCountersConsistent(3, 2));
  Check(not WorkCountersConsistent(2, 3));
  Check(InRecentWindow(1200, 1000, 300));
  Check(not InRecentWindow(1400, 1000, 300));
end.
