program Cozy_OverlayGraphicsProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF GAME_OVERLAY_CONTRACT_TESTS}{$MESSAGE FATAL 'Isolated overlay graphics probe required.'}{$ENDIF}
{$IFDEF GAME_APPLICATION_BUILD}{$MESSAGE FATAL 'Never link the graphics probe into an application build.'}{$ENDIF}
{$IFDEF GAME_IMGUI_FAULT_TESTS}{$MESSAGE FATAL 'The graphics preflight must use the production bridge, not the fault object.'}{$ENDIF}
{ Read-only reuse of the audited public production VERSIONINFO/PerMonitorV2
  manifest resource. The probe never replaces a production resource or EXE. }
{$R '..\..\Cozy.Projects\Cozy.Overlay\Cozy.OverlayResources.res'}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',

{ Cozy central text imports. }
  Cozy.Clock, Winapi.Windows, Winapi.Messages, System.SysUtils,
  Cozy.Api.Pointer, Cozy.Overlay.ImGui, Cozy.Overlay.Renderer,
  Cozy.Overlay.ShutdownGuard;

{ Manual Windows graphics preflight only. The actual production bridge reads
  the same OS-owned Korean font, uses the same native memory admission and
  creates real D3D11 resources. There is no server connection, license key,
  authority callback, Run handler or simulated successful Present.
  PASS requires several seconds after actual visible Presents. It does not
  certify A/B/O authentication, packaging, GPU behavior under game load or
  arbitrary monitor/driver configurations. }
const
  VisibleDurationMs = 3500;
  SoftDeadlineMs = 20000;
  HardDeadlineMs = 25000;
var
  FirstVisibleTick, Started: UInt64;
  VisibleFrames: Cardinal;
  ClosePosted, TimedOut, FailureObserved: Boolean;
  FailureStage: string;
  FailureCode: Integer;

function SafeFailureStage(const Stage: string): string;
begin
  Result := CozyText_OverlayGraphicsProbe_UNKNOWN_a7225ca9;
  if (Stage = CozyText_OverlayGraphicsProbe_BINDING_2f6f2922) or (Stage = CozyText_OverlayGraphicsProbe_FONT_READ_a5ceef9e) or
    (Stage = CozyText_OverlayGraphicsProbe_FONT_DATA_5dd297e3) or (Stage = CozyText_OverlayGraphicsProbe_CREATE_4c9b4535) or
    (Stage = CozyText_OverlayGraphicsProbe_RESIZE_de9d6aba) or
    (Stage = CozyText_OverlayGraphicsProbe_GPU_IDENTITY_a67668be) or (Stage = CozyText_OverlayGraphicsProbe_FLOATING_POINT_186ee301) then
    Result := Stage;
end;

procedure RecordFailure(const Stage: string; NativeCode: Integer);
begin
  FailureObserved := True;
  FailureStage := SafeFailureStage(Stage);
  FailureCode := NativeCode;
end;

function TypedFailureStage(Stage: TOverlayImGuiFailureStage): string;
begin
  case Stage of
    igfsBinding: Result := CozyText_OverlayGraphicsProbe_BINDING_2f6f2922;
    igfsFontRead: Result := CozyText_OverlayGraphicsProbe_FONT_READ_a5ceef9e;
    igfsFontData: Result := CozyText_OverlayGraphicsProbe_FONT_DATA_5dd297e3;
    igfsCreate: Result := CozyText_OverlayGraphicsProbe_CREATE_4c9b4535;
    igfsResize: Result := CozyText_OverlayGraphicsProbe_RESIZE_de9d6aba;
  else Result := CozyText_OverlayGraphicsProbe_UNKNOWN_a7225ca9;
  end;
end;

procedure PrintFailure(const Stage: string; NativeCode: Integer);
begin
  WriteLn(CozyText_OverlayGraphicsProbe_FAIL_811edb21, SafeFailureStage(Stage), CozyText_OverlayGraphicsProbe_0x_bb0fdab2,
    IntToHex(Cardinal(NativeCode), 8));
end;

procedure RunProbe;
var
  Guard: TOverlayShutdownGuard;
  Status: Integer;
  Passed: Boolean;
begin
  Passed := False;
  Started := CozyTick;
  Guard := TOverlayShutdownGuard.Create;
  try
    { This bounds a driver call which never returns; it can terminate only
      this diagnostic process. Such termination cannot produce PASS. }
    Guard.Arm(Started + HardDeadlineMs);
    Guard.Start;
    Status := RunOverlayUI(
      procedure
      var Wnd: HWND;
      begin
        { Renderer invokes Tick only after a successful visible Present. }
        Inc(VisibleFrames);
        if FirstVisibleTick = 0 then FirstVisibleTick := CozyTick;
        if not ClosePosted and
          (CozyTick - FirstVisibleTick >= VisibleDurationMs) then
        begin
          Wnd := HWND(OverlayTestWindow);
          if (Wnd <> 0) and IsWindowVisible(Wnd) then
            ClosePosted := PostMessage(Wnd, WM_CLOSE, 0, 0);
        end;
      end,
      function: Boolean
      begin
        TimedOut := CozyTick - Started >= SoftDeadlineMs;
        Result := TimedOut;
      end,
      nil, nil, nil, nil, nil, nil, nil, nil, nil,
      procedure(Stage: string; NativeCode: Integer)
      begin
        RecordFailure(Stage, NativeCode);
      end);
    Passed := (Status = 0) and not TimedOut and not FailureObserved and
      ClosePosted and (VisibleFrames > 1) and
      (FirstVisibleTick <> 0) and
      (CozyTick - FirstVisibleTick >= VisibleDurationMs);
  finally
    Guard.Cancel;
    Guard.Free;
  end;
  { Report PASS only after the renderer and independent process guard have
    completed their normal ownership cleanup. }
  if Passed then
  begin
    WriteLn(CozyText_OverlayGraphicsProbe_PASS_REAL_WINDOWS_GRAPHICS_visibleFrames_1b290434, VisibleFrames);
    ExitCode := 0;
  end
  else
  begin
    if FailureObserved then PrintFailure(FailureStage, FailureCode)
    else PrintFailure(CozyText_OverlayGraphicsProbe_UNKNOWN_a7225ca9, 0);
    ExitCode := 1;
  end;
end;

begin
  ExitCode := 1;
  try
    if ParamCount <> 0 then
    begin
      PrintFailure(CozyText_OverlayGraphicsProbe_UNKNOWN_a7225ca9, 0);
      Exit;
    end;
    SealApiPointerStorage;
    RunProbe;
  except
    on E: EOverlayImGuiFailure do
    begin
      ExitCode := 1;
      PrintFailure(TypedFailureStage(E.Stage), E.NativeCode);
    end;
    on E: EMathError do
    begin
      ExitCode := 1;
      if FailureObserved then PrintFailure(FailureStage, FailureCode)
      else PrintFailure(CozyText_OverlayGraphicsProbe_FLOATING_POINT_186ee301, 0);
    end;
    on E: Exception do
    begin
      ExitCode := 1;
      if FailureObserved then PrintFailure(FailureStage, FailureCode)
      else PrintFailure(CozyText_OverlayGraphicsProbe_UNKNOWN_a7225ca9, 0);
    end;
  end;
end.
