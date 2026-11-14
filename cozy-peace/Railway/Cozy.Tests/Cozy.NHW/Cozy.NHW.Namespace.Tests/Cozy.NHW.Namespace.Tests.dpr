program CozyNHW_Namespace_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Windows x64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Namespace in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Namespace.pas',
  Cozy.NHW.NamespaceNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NamespaceNative.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas';

procedure Require(Ok: Boolean);
begin
  if not Ok then raise Exception.Create('v18 namespace regression failure');
end;

procedure Put(const Dict: TNamespaceEntries; const Name, Kind, Link: string;
  TargetKnown: Boolean);
var
  E: TNamespaceEntry;
begin
  E := Default(TNamespaceEntry);
  E.Name := Name;
  E.TypeName := Kind;
  E.Target := Link;
  E.TargetKnown := TargetKnown;
  Dict.AddOrSetValue(UpperCase(Name), E);
end;

var
  Before, After: TNamespaceEntries;
  Delta: TDetectionKinds;
  Count: Integer;
begin
  Before := TNamespaceEntries.Create;
  After := TNamespaceEntries.Create;
  try
    Put(Before, 'C:', 'SymbolicLink', '\Device\HarddiskVolume1', True);
    Put(After, 'C:', 'SymbolicLink', '\Device\HarddiskVolume1', True);
    Delta := CompareNamespaceEntries(Before, After, True, Count);
    Require((Delta = []) and (Count = 0));

    Put(After, 'C:', 'SymbolicLink', '\Device\HarddiskVolume2', True);
    Delta := CompareNamespaceEntries(Before, After, True, Count);
    Require((dkSymbolicLink in Delta) and (dkDeviceMap in Delta) and (Count = 1));

    Put(After, 'C:', 'SymbolicLink', '', False);
    Delta := CompareNamespaceEntries(Before, After, True, Count);
    Require((Delta = []) and (Count = 0)); // unknown link target

    Put(After, 'C:', 'Event', '', False);
    Delta := CompareNamespaceEntries(Before, After, True, Count);
    Require((dkObjectType in Delta) and (dkDeviceMap in Delta));

    After.Clear;
    Delta := CompareNamespaceEntries(Before, After, True, Count);
    Require((dkNamespace in Delta) and (dkDeviceMap in Delta) and (Count = 1));

    Before.Clear;
    After.Clear;
    Put(After, 'NHW.TEST', 'Event', '', False);
    Delta := CompareNamespaceEntries(Before, After, False, Count);
    Require((dkNamespace in Delta) and not (dkDeviceMap in Delta));
    ExitCode := 0;
  except
    ExitCode := 1;
  end;
  After.Free;
  Before.Free;
end.
