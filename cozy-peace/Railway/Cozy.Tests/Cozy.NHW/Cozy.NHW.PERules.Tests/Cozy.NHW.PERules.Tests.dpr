program CozyNHW_PERules_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Only Win64 supported'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.PERules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PERules.pas',
  Cozy.NHW.SelfRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfRules.pas',
  Cozy.NHW.ExceptionRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionRules.pas';
var
  S: TPEWatchCell;
  F: TPEFeature;
begin
  if PERangeInImage($FFF0, $100, $10000) then Halt(1);
  if not PERangeInImage($FF00, $100, $10000) then Halt(2);
  S := Default(TPEWatchCell);
  F := Default(TPEFeature);
  F.Available := True;
  F.Valid := True;
  F.Digest := $100;
  if PEObserve(S,F,True) then Halt(3);
  F.Digest := $200;
  if PEObserve(S,F,False) then Halt(4);
  if not PEObserve(S,F,False) then Halt(5);
  if PEObserve(S,F,False) then Halt(6);
  F.Digest := $100;
  if PEObserve(S,F,False) then Halt(7);
  F.Valid := False;
  if PEObserve(S,F,False) then Halt(8);
  if not PEObserve(S,F,False) then Halt(9);
  Writeln('PASS');
end.
