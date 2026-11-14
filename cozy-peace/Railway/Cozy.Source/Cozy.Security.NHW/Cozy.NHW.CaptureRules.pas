unit Cozy.NHW.CaptureRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils;

type
  TCaptureFamily = (cfPcap, cfWinDivert, cfProtocol);
  TCaptureFamilies = set of TCaptureFamily;
  TCaptureSignal = (csClient, csLibrary, csDriver, csProxy, csCorrelation);
  TCaptureSignals = set of TCaptureSignal;

function LibraryKind(const BaseName: string): TCaptureFamilies;
function IsCaptureClient(const BaseName: string): Boolean;
function IsProxyClient(const BaseName: string): Boolean;
function IsMicrosoftPktMon(const BaseName, ImagePath: string): Boolean;
function ClassifyCapture(const BaseName, ImagePath: string;
  Libraries: TCaptureFamilies; Drivers: TCaptureFamilies;
  HasTcpListener: Boolean): TCaptureSignals;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestCaptureRules10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Winapi.Windows;

function LibraryKind(const BaseName: string): TCaptureFamilies;
begin
  Result := [];
  if SameText(BaseName, 'wpcap.dll') or SameText(BaseName, 'packet.dll') or
     SameText(BaseName, 'libpcap.dll') or SameText(BaseName, 'airpcap.dll') then
    Include(Result, cfPcap);
  if SameText(BaseName, 'WinDivert.dll') or
     SameText(BaseName, 'WinDivert64.dll') then
    Include(Result, cfWinDivert);
  if SameText(BaseName, 'libwireshark.dll') or
     SameText(BaseName, 'libwiretap.dll') then
    Include(Result, cfProtocol);
end;

function IsCaptureClient(const BaseName: string): Boolean;
begin
  Result := SameText(BaseName, 'wireshark.exe') or
    SameText(BaseName, 'dumpcap.exe') or
    SameText(BaseName, 'tshark.exe') or
    SameText(BaseName, 'windump.exe') or
    SameText(BaseName, 'tcpdump.exe') or
    SameText(BaseName, 'rawcap.exe') or
    SameText(BaseName, 'networkminer.exe') or
    SameText(BaseName, 'pktmon.exe') or
    SameText(BaseName, 'httpdebuggerui.exe');
end;

function IsProxyClient(const BaseName: string): Boolean;
begin
  Result := SameText(BaseName, 'mitmproxy.exe') or
    SameText(BaseName, 'mitmdump.exe') or
    SameText(BaseName, 'mitmweb.exe') or
    SameText(BaseName, 'fiddler.exe') or
    SameText(BaseName, 'fiddlerclassic.exe') or
    SameText(BaseName, 'fiddlereverywhere.exe') or
    SameText(BaseName, 'charles.exe') or
    SameText(BaseName, 'burpsuitecommunity.exe') or
    SameText(BaseName, 'burpsuitepro.exe') or
    SameText(BaseName, 'httptoolkit.exe');
end;

function CaptureSystemDirectory(out Directory: string): Boolean;
var
  Buffer: string;
  N, Capacity: Cardinal;
  Attempt: Integer;
begin
  Result := False;
  Directory := '';
  Capacity := MAX_PATH;
  for Attempt := 1 to 3 do
  begin
    SetLength(Buffer, Integer(Capacity));
    N := GetSystemDirectoryW(PWideChar(Buffer), Capacity);
    if N = 0 then Exit;
    if N < Capacity then
    begin
      SetLength(Buffer, Integer(N));
      Directory := Buffer;
      Exit(True);
    end;
    if N >= 32768 then Exit;
    Capacity := N + 1;
  end;
end;

function CaptureCanonicalDOSPath(const Path: string): string;
var
  P: string;
begin
  Result := '';
  if (Path = '') or (Pos(#0, Path) <> 0) then Exit;
  P := StringReplace(Path, '/', '\', [rfReplaceAll]);
  // Accept only explicit local absolute paths. Do not resolve relative
  // names, CWD, environment variables, dot segments or reparse targets.
  if (Copy(P, 1, 4) = '\\?\') or (Copy(P, 1, 4) = '\??\') then
    Delete(P, 1, 4);
  if Length(P) < 3 then Exit;
  if not CharInSet(P[1], ['A'..'Z', 'a'..'z']) or
     (P[2] <> ':') or (P[3] <> '\') then Exit;
  Result := P;
end;

function CapturePktMonAtDirectory(const BaseName, ImagePath,
  Directory: string): Boolean;
var
  P, D: string;
begin
  Result := False;
  if not SameText(BaseName, 'pktmon.exe') then Exit;
  P := CaptureCanonicalDOSPath(ImagePath);
  D := CaptureCanonicalDOSPath(Directory);
  if (P = '') or (D = '') then Exit;
  Result := SameText(P, IncludeTrailingPathDelimiter(D) + 'pktmon.exe');
end;

function IsMicrosoftPktMon(const BaseName, ImagePath: string): Boolean;
var Directory: string;
begin
  Result := False;
  if not SameText(BaseName, 'pktmon.exe') then Exit;
  if not CaptureSystemDirectory(Directory) then Exit;
  // Exact system-directory location only. This is NOT signature attestation.
  Result := CapturePktMonAtDirectory(BaseName, ImagePath, Directory);
end;

function ClassifyCapture(const BaseName, ImagePath: string;
  Libraries: TCaptureFamilies; Drivers: TCaptureFamilies;
  HasTcpListener: Boolean): TCaptureSignals;
var
  StrongLibrary: Boolean;
  MatchedDriver: Boolean;
begin
  Result := [];
  StrongLibrary := ((cfPcap in Libraries) or (cfWinDivert in Libraries));
  MatchedDriver := ((cfPcap in Libraries) and (cfPcap in Drivers)) or
    ((cfWinDivert in Libraries) and (cfWinDivert in Drivers));
  // A library being mapped is a factual observation, not proof of capturing.
  if Libraries <> [] then Include(Result, csLibrary);
  // Require corroboration for ordinary tool filenames; do not alert solely
  // because somebody named their harmless EXE 'wireshark.exe'.
  if (IsCaptureClient(BaseName) and
      ((Libraries <> []) or IsMicrosoftPktMon(BaseName, ImagePath))) or
      (IsProxyClient(BaseName) and HasTcpListener) then
    Include(Result, csClient);
  if IsProxyClient(BaseName) and HasTcpListener then
    Include(Result, csProxy);
  // Driver installation or running service on its own is NEVER an alert.
  if MatchedDriver then Include(Result, csDriver);
  // Correlation needs BOTH a known capture library and the matching driver.
  if MatchedDriver and StrongLibrary then
    Include(Result, csCorrelation);
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.CaptureRules.inc}
{$ENDIF}

end.
