program CozyNHW_NetworkRules_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Win64 (dcc64).'}
{$ENDIF}
uses
  System.SysUtils,
  System.Classes,
  Cozy.NHW.NetworkRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NetworkRules.pas';
var
  G: TChangeGate;
  L: TStringList;
begin
  G := TChangeGate.Create;
  L := TStringList.Create;
  try
    L.Add('A');
    if G.Observe(L) then Halt(1);  // baseline
    if G.Observe(L) then Halt(2);  // unchanged
    L.Add('B');
    if G.Observe(L) then Halt(3);  // only one new snapshot
    L.Clear;
    L.Add('A');
    if G.Observe(L) then Halt(4);  // transient rejected
    L.Add('B');
    if G.Observe(L) then Halt(5);
    if not G.Observe(L) then Halt(6); // confirmed change
    if G.Observe(L) then Halt(7);     // suppress repeat
  finally
    L.Free;
    G.Free;
  end;
end.
