program Cozy_OverlayFirstFrameProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF GAME_OVERLAY_CONTRACT_TESTS}{$MESSAGE FATAL 'Isolated test build required.'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',
 Cozy.Clock, Winapi.Windows, Winapi.Messages, System.SysUtils,
  Cozy.Api.Pointer, Cozy.Overlay.Renderer;
procedure Require(Value: Boolean; const Name: string);
begin if not Value then raise Exception.Create(CozyText_OverlayFirstFrameProbe_OVERLAY_FIRST_FRAME_97b424d0+Name); end;
procedure RunCase(Mode: Integer);
var Invalid, HookSeen, TimedOut, InteractionSeen, AuthorizationSeen, AuthRejected: Boolean;
  ReadyCount, ClosingCount, Status: Integer; Deadline: UInt64;
  ReadyEvent: THandle; Wnd: HWND; Rect: TRect; Queued: TMsg;
begin
  while PeekMessage(Queued,0,WM_QUIT,WM_QUIT,PM_REMOVE) do ;
  Invalid := False; HookSeen := False; TimedOut := False;
  AuthorizationSeen := False; AuthRejected := False;
  InteractionSeen := False; ReadyCount := 0; ClosingCount := 0;
  Deadline := CozyTick + 15000;
  ReadyEvent := CreateEvent(nil, True, False, nil);
  Require(ReadyEvent <> 0, CozyText_OverlayFirstFrameProbe_test_owned_readiness_event_291aee8b);
  try
    SetOverlayTestHooks(
      procedure
      begin
        if Mode = 1 then begin HookSeen := True; Deadline := CozyTick; end;
        if (Mode = 3) and not InteractionSeen then
        begin
          InteractionSeen := True; Wnd := HWND(OverlayTestWindow);
          Require(Wnd <> 0, CozyText_OverlayFirstFrameProbe_owned_real_renderer_HWND_9611e159);
          SendMessage(Wnd, WM_LBUTTONDOWN, MK_LBUTTON, 10 or (10 shl 16));
          SendMessage(Wnd, WM_KILLFOCUS, 0, 0);
          Require(GetCapture <> Wnd, CozyText_OverlayFirstFrameProbe_focus_loss_releases_capture_b2ba9e4c);
          SendMessage(Wnd, WM_SIZE, SIZE_MINIMIZED, 0);
          Require(GetCapture <> Wnd, CozyText_OverlayFirstFrameProbe_minimize_leaves_no_capture_2a9c019a);
          SendMessage(Wnd, WM_SIZE, SIZE_RESTORED, 320 or (160 shl 16));
          GetWindowRect(Wnd, Rect);
          SendMessage(Wnd, $02E0, 144 or (144 shl 16), LPARAM(@Rect));
          Require(GetCapture <> Wnd, CozyText_OverlayFirstFrameProbe_DPI_change_leaves_no_capture_a917aa76);
        end;
      end,
      procedure
      begin
        if Mode = 2 then begin HookSeen := True; Deadline := CozyTick; end;
      end);
    Status := 1;
    try
    Status := RunOverlayUI(
      procedure
      begin
        Require(AuthorizationSeen,CozyText_OverlayFirstFrameProbe_initial_authority_callback_precedes_every_READY_d15c884b);
        Inc(ReadyCount); SetEvent(ReadyEvent);
        PostMessage(HWND(OverlayTestWindow), WM_CLOSE, 0, 0);
      end,
      function: Boolean
      begin
        if CozyTick >= Deadline then begin TimedOut := not HookSeen; Invalid := True; end;
        Result := Invalid;
      end,
      procedure
      begin
        Inc(ClosingCount);
        if Mode = 5 then raise Exception.Create(CozyText_OverlayFirstFrameProbe_EXPECTED_CLOSING_FAILURE_b897b35d);
      end,
      procedure
      begin
        AuthorizationSeen := True;
        Require(not IsWindowVisible(HWND(OverlayTestWindow)), CozyText_OverlayFirstFrameProbe_D3D_preauthorization_window_remains_hidden_10c9b647);
        Require(ReadyCount=0, CozyText_OverlayFirstFrameProbe_hidden_device_initialization_never_acknowledges__d93177b9);
        if Mode=4 then raise Exception.Create(CozyText_OverlayFirstFrameProbe_EXPECTED_AUTHORITY_REJECT_054f8cfd);
      end);
    except on E: Exception do
      if (Mode=4) and (E.Message=CozyText_OverlayFirstFrameProbe_EXPECTED_AUTHORITY_REJECT_054f8cfd) then AuthRejected := True
      else raise;
    end;
    Require(AuthorizationSeen,CozyText_OverlayFirstFrameProbe_actual_hidden_startup_authority_callback_execute_ceacbebc);
    Require(not TimedOut, CozyText_OverlayFirstFrameProbe_real_visible_Present_must_occur_before_timeout_f905095f);
    Require(ClosingCount = 1, CozyText_OverlayFirstFrameProbe_closing_callback_runs_exactly_once_3c48ba71);
    Require(OverlayTestWindow = 0, CozyText_OverlayFirstFrameProbe_no_surviving_renderer_HWND_9b9660fe);
    if Mode=4 then
    begin
      Require(AuthRejected and (ReadyCount=0), CozyText_OverlayFirstFrameProbe_authority_rejection_closes_hidden_graphics_resou_d60c748b);
      Require(WaitForSingleObject(ReadyEvent,0)=WAIT_TIMEOUT, CozyText_OverlayFirstFrameProbe_authority_rejection_never_signals_READY_e9ba0ea7);
    end
    else if Mode = 5 then
    begin
      Require((Status <> 0) and (ReadyCount = 1), CozyText_OverlayFirstFrameProbe_closing_callback_failure_reports_failure_after_c_f0371523);
      Require(WaitForSingleObject(ReadyEvent, 0) = WAIT_OBJECT_0, CozyText_OverlayFirstFrameProbe_failure_was_after_the_visible_frame_4dac2c26);
    end
    else if Mode <> 3 then
    begin
      Require(HookSeen, CozyText_OverlayFirstFrameProbe_expiry_injected_at_actual_frame_boundary_44d1e781);
      Require((Status <> 0) and (ReadyCount = 0), CozyText_OverlayFirstFrameProbe_expiry_cannot_acknowledge_READY_4aef081c);
      Require(WaitForSingleObject(ReadyEvent, 0) = WAIT_TIMEOUT, CozyText_OverlayFirstFrameProbe_READY_event_remained_unsignalled_e74fb9a3);
    end
    else
    begin
      Require(InteractionSeen, CozyText_OverlayFirstFrameProbe_real_focus_minimize_DPI_message_path_executed_aa9aa54d);
      Require((Status = 0) and (ReadyCount = 1), CozyText_OverlayFirstFrameProbe_one_real_visible_frame_acknowledges_READY_89edaee3);
      Require(WaitForSingleObject(ReadyEvent, 0) = WAIT_OBJECT_0, CozyText_OverlayFirstFrameProbe_consumer_observes_READY_event_8112f659);
    end;
    WriteLn(CozyText_OverlayFirstFrameProbe_PASS_real_renderer_first_frame_READY_case_58d308b1,Mode);
  finally
    SetOverlayTestHooks(nil,nil); CloseHandle(ReadyEvent);
  end;
end;
begin
  try
    SealApiPointerStorage;
    RunCase(1); RunCase(2); RunCase(4); RunCase(5); RunCase(3);
    WriteLn(CozyText_OverlayFirstFrameProbe_PASS_actual_HWND_D3D11_expiry_and_readiness_no_s_51703732);
  except on E: Exception do begin WriteLn(E.ClassName, CozyText_OverlayFirstFrameProbe_Text_201a2895, E.Message); Halt(1); end; end;
end.
