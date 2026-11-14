program CozyNHW_SelfRules_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.SelfRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfRules.pas';

procedure Check(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('Self rules test failure');
end;

var
  S: TStableFingerprint;
begin
  S := Default(TStableFingerprint);
  Check(not ObserveFingerprint(S, 1, True));  // initial baseline
  Check(not ObserveFingerprint(S, 2, False)); // failed query: ignore
  Check(not ObserveFingerprint(S, 2, True));  // first change
  Check(ObserveFingerprint(S, 2, True));      // confirmed change
  Check(not ObserveFingerprint(S, 2, True));  // suppressed duplicate
  Check(not ObserveFingerprint(S, 1, True));  // normal restoration
  Check(not ObserveFingerprint(S, 3, True));
  Check(ObserveFingerprint(S, 3, True));
  Check(WithinBoundaryWindow(2000, 1000, 1500));
  Check(not WithinBoundaryWindow(4000, 1000, 1500));
  Check(not WithinBoundaryWindow(100, 0, 1500));
  Writeln('PASS');
end.
