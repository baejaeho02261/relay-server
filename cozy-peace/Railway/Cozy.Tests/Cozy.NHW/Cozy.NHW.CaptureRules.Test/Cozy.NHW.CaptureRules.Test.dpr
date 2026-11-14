program CozyNHW_CaptureRules_Test;

{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  Cozy.NHW.CaptureRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CaptureRules.pas';

procedure Check(Condition: Boolean);
begin
  if not Condition then Halt(1);
end;

var
  S: TCaptureSignals;
begin
  Check(LibraryKind('wpcap.dll') = [cfPcap]);
  Check(LibraryKind('WinDivert.dll') = [cfWinDivert]);
  Check(LibraryKind('unrelated.dll') = []);
  S := ClassifyCapture('wireshark.exe', 'C:\test\wireshark.exe', [],
    [cfPcap], False);
  Check(S = []); // filename + running driver is insufficient
  S := ClassifyCapture('renamed.exe', 'C:\test\renamed.exe',
    [cfPcap], [cfPcap], False);
  Check(csLibrary in S);
  Check(csDriver in S);
  Check(csCorrelation in S);
  Check(not (csClient in S));
  S := ClassifyCapture('fiddler.exe', 'C:\test\fiddler.exe', [], [], True);
  Check(csProxy in S);
  Check(csClient in S);
  S := ClassifyCapture('fiddler.exe', 'C:\test\fiddler.exe', [], [], False);
  Check(S = []);
  Halt(0);
end.
