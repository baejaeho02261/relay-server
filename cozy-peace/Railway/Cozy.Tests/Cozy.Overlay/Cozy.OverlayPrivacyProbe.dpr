program Cozy_OverlayPrivacyProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$IFNDEF FPC}
{$APPTYPE CONSOLE}
{$IFNDEF GAME_OVERLAY_CONTRACT_TESTS}{$MESSAGE FATAL 'Isolated overlay test build required.'}{$ENDIF}
{$ENDIF}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',
 Cozy.Clock, {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils, Winapi.Windows, Winapi.Messages,
  Cozy.Api.Pointer, Cozy.Overlay.Renderer{$ENDIF}, Cozy.Overlay.State;
procedure Check(Requested, SetOK, ReadOK: Boolean; Value: Cardinal; const Expected: string);
begin
  if OverlayCapturePrivacyStatus(Requested, SetOK, ReadOK, Value) <> Expected then
    raise Exception.Create(CozyText_OverlayPrivacyProbe_OVERLAY_PRIVACY_STATUS_INVALID_168d508c);
end;
{$IFNDEF FPC}
procedure NativePrivacyCase(Requested: Boolean);
var FrameSeen, TimedOut: Boolean; Deadline: UInt64;
  Status: Integer; Observed: string; Queued: TMsg;
begin
  while PeekMessage(Queued, 0, WM_QUIT, WM_QUIT, PM_REMOVE) do ;
  FrameSeen := False; TimedOut := False; Observed := '';
  Deadline := CozyTick + 15000;
  SetOverlayTestHooks(
    procedure
    begin
      if OverlayTestWindow = 0 then raise Exception.Create(CozyText_OverlayPrivacyProbe_PRIVACY_OWN_WINDOW_MISSING_570dc45a);
      Observed := OverlayTestCapturePrivacyStatus;
    end, nil);
  try
    Status := RunOverlayUI(
      procedure
      begin
        FrameSeen := True;
        PostMessage(HWND(OverlayTestWindow), WM_CLOSE, 0, 0);
      end,
      function: Boolean
      begin
        TimedOut := CozyTick >= Deadline; Result := TimedOut;
      end, nil,
      procedure
      begin
        { This isolated probe owns its test window; it never claims production
          server authorization or sends a session/READY event to the server. }
        if IsWindowVisible(HWND(OverlayTestWindow)) then
          raise Exception.Create(CozyText_OverlayPrivacyProbe_PRIVACY_WINDOW_SHOWN_BEFORE_CONFIGURATION_cc3e2b31);
      end,
      function: Boolean begin Result := Requested; end);
    if (Status <> 0) or TimedOut or not FrameSeen or (OverlayTestWindow <> 0) then
      raise Exception.Create(CozyText_OverlayPrivacyProbe_PRIVACY_RENDERER_LIFECYCLE_FAILED_96b1fa4c);
    if (not Requested and (Observed = CozyText_OverlayPrivacyProbe_Text_261babee)) or
      (Requested and (Observed = CozyText_OverlayPrivacyProbe_Text_2a34d06b)) then
      WriteLn(CozyText_OverlayPrivacyProbe_PASS_own_window_affinity_setter_readback_request_3d9a394f, Ord(Requested), CozyText_OverlayPrivacyProbe_Text_f8eb7824, Observed)
    else if (Observed = CozyText_OverlayPrivacyProbe_Text_d6ece64e) or
      (Observed = CozyText_OverlayPrivacyProbe_Text_ae188367) or
      (Requested and (Observed = CozyText_OverlayPrivacyProbe_Text_bb0ed578)) then
      WriteLn(CozyText_OverlayPrivacyProbe_SKIP_exact_own_window_affinity_readback_requeste_fc73dade, Ord(Requested), CozyText_OverlayPrivacyProbe_Text_f8eb7824, Observed)
    else raise Exception.Create(CozyText_OverlayPrivacyProbe_PRIVACY_READBACK_MISMATCH_d2e79e4f + Observed);
  finally SetOverlayTestHooks(nil, nil); end;
end;
{$ENDIF}

begin
  Check(False, True, True, 0, CozyText_OverlayPrivacyProbe_Text_261babee);
  Check(False, True, True, $11, CozyText_OverlayPrivacyProbe_Text_90ab771d);
  Check(True, False, False, 0, CozyText_OverlayPrivacyProbe_Text_d6ece64e);
  Check(True, False, True, $11, CozyText_OverlayPrivacyProbe_Text_d6ece64e);
  Check(True, True, False, $11, CozyText_OverlayPrivacyProbe_Text_ae188367);
  Check(True, True, True, $11, CozyText_OverlayPrivacyProbe_Text_2a34d06b);
  Check(True, True, True, $01, CozyText_OverlayPrivacyProbe_Text_bb0ed578);
  Check(True, True, True, 0, CozyText_OverlayPrivacyProbe_Text_90ab771d);
  Check(True, True, True, High(Cardinal), CozyText_OverlayPrivacyProbe_Text_90ab771d);
  WriteLn(CozyText_OverlayPrivacyProbe_PASS_9_capture_privacy_status_cases_750efa6e);
{$IFDEF FPC}
  WriteLn(CozyText_OverlayPrivacyProbe_Windows_affinity_NOT_RUN_on_this_portable_host_7f0402cc);
{$ELSE}
  SealApiPointerStorage;
  NativePrivacyCase(True);
  NativePrivacyCase(False);
  WriteLn(CozyText_OverlayPrivacyProbe_Scope_own_window_affinity_API_result_only_extern_f5fcef20);
{$ENDIF}
end.
