program Cozy_LicenseUIProbe;
{$APPTYPE GUI}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.License in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.License.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
 System.SysUtils, Cozy.Clock, Cozy.SensitiveText, Cozy.License.Commands,
  Cozy.License.Window;
{$R '..\..\Cozy.Projects\Cozy.Client\Cozy.ClientResources.res'}
var BusyStarted, BusyUntil, NowTick: UInt64;
  Closing, ProbeFailed: Boolean; Attempts: Integer;
begin
  { Manual window-only preview. It never claims A/B/O, opens a server session,
    submits a real license or grants product authorization. Any input is wiped.
    Every three submissions exercise: a short local response, a longer response,
    and a refused enqueue. No artificial minimum delays the response or retry.
    Clicking, typing, pasting and dragging while a mock operation is pending
    must not mutate input or trigger a second submission. Progress represents
    the mock operation and stays below 100 until it actually finishes.
    Check the empty hint disappears on focus and stays hidden while typing. }
  ExitCode := 1; BusyStarted := 0; BusyUntil := 0;
  Closing := False; ProbeFailed := False; Attempts := 0;
  try
    RunLicenseWindow(
      procedure begin end,
      function(var Key: TCozySensitiveText): Boolean
      begin
        FreeAndNil(Key);
        NowTick := CozyTick;
        if Closing or ((BusyUntil <> 0) and (NowTick < BusyUntil)) then
        begin ProbeFailed := True; Exit(False); end;
        Inc(Attempts);
        BusyStarted := NowTick; BusyUntil := 0;
        Result := (Attempts mod 3) <> 0;
        if Result then
        begin
          if (Attempts mod 3) = 1 then BusyUntil := NowTick + 1200
          else BusyUntil := NowTick + 3400;
        end;
      end,
      function: Integer
      begin
        if ProbeFailed then Result := WorkerFailed
        else if Closing then Result := WorkerStopped
        else if (BusyUntil <> 0) and (CozyTick < BusyUntil) then Result := WorkerBusy
        else Result := WorkerIdle;
      end,
      function: Integer
      var Tick: UInt64;
      begin
        Result := 0; Tick := CozyTick;
        if (BusyUntil <= BusyStarted) or (Tick < BusyStarted) then Exit;
        if Tick >= BusyUntil then Exit(99);
        Result := 8 + Integer((Tick-BusyStarted)*84 div (BusyUntil-BusyStarted));
      end,
      procedure begin Closing := True; end,
      procedure begin end);
    if not ProbeFailed then ExitCode := 0;
  except
    ExitCode := 1;
  end;
end.
