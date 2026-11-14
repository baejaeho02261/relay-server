program Cozy_OverlayEnvironmentProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF GAME_OVERLAY_CONTRACT_TESTS}{$MESSAGE FATAL 'Isolated overlay test build required.'}{$ENDIF}
{$IFDEF GAME_APPLICATION_BUILD}{$MESSAGE FATAL 'Never link this probe into an application build.'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',
 Cozy.Clock, Winapi.Windows, Winapi.Messages, System.SysUtils, System.JSON, System.IOUtils,
  Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver, Cozy.Overlay.Renderer;
const
  SessionChanged = $02B1;
  DpiChanged = $02E0;
type TReadWindowDpi = function(Wnd: HWND): UINT; stdcall;
var
  SlotProbeDpi: TEncodedApiPointer;
  Interactive, IntroChecked, ContractDone, Finished, TimedOut: Boolean;
  OutputFile, Nonce: string;
  Events: TJSONArray;
  Started, LastSample, IntroStarted: UInt64;
  SeenMessages: Integer;
  InputEnabled: Boolean;
  InputCommits, InputBegins, InputEnds, InputCancels, InputFocusLosses: Integer;
  InputText: UTF8String;
  LegacyStartCalls, LegacyStateReads: Integer;
  ProductStartCalls, FixtureProductState: Integer;
procedure Require(Value: Boolean; const Name: string);
begin if not Value then raise Exception.Create(CozyText_OverlayEnvironmentProbe_OVERLAY_ENVIRONMENT_e186af34+Name); end;
function PointParam(X,Y: Integer): LPARAM;
begin Result := LPARAM(Cardinal(Word(X)) or (Cardinal(Word(Y)) shl 16)); end;
procedure AddEvent(const Kind: string; Msg: Cardinal; WP: NativeUInt; LP: NativeInt; ClearsBefore: Cardinal = 0);
var S: TOverlayEnvironmentSnapshot; Row: TJSONObject; X,Y: Integer; Monitor: HMONITOR;
  Info: TMonitorInfo; WindowDpi: Cardinal; ReadDpi: TReadWindowDpi;
begin
  if Events.Count >= 16000 then begin TimedOut := True; Finished := True; Exit; end;
  S := OverlayTestEnvironment;
  if S.Window = 0 then Exit;
  Monitor := MonitorFromWindow(HWND(S.Window), MONITOR_DEFAULTTONEAREST);
  FillChar(Info,SizeOf(Info),0); Info.cbSize := SizeOf(Info);
  Require(GetMonitorInfo(Monitor,@Info),CozyText_OverlayEnvironmentProbe_monitor_workarea_readback_dca78ed0);
  ReadDpi := TReadWindowDpi(DecodeApiPointer(SlotProbeDpi));
  WindowDpi := ReadDpi(HWND(S.Window));
  Row := TJSONObject.Create;
  Row.AddPair(CozyText_OverlayEnvironmentProbe_kind_8b51a854,Kind); Row.AddPair(CozyText_OverlayEnvironmentProbe_seq_6847db02,TJSONNumber.Create(Events.Count));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_tick_a34a7c48,TJSONNumber.Create(CozyTick-Started));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_msg_05fdd00c,TJSONNumber.Create(Msg)); Row.AddPair(CozyText_OverlayEnvironmentProbe_wparam_979dbc9b,TJSONNumber.Create(Int64(WP)));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_dpi_baa614b7,TJSONNumber.Create(S.Dpi)); Row.AddPair(CozyText_OverlayEnvironmentProbe_windowDpi_4cdda6e3,TJSONNumber.Create(WindowDpi));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_monitor_f2203376,IntToHex(NativeUInt(Monitor),16));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_left_cb59d493,TJSONNumber.Create(S.WindowRect.Left)); Row.AddPair(CozyText_OverlayEnvironmentProbe_top_8c1c2945,TJSONNumber.Create(S.WindowRect.Top));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_right_97c4f306,TJSONNumber.Create(S.WindowRect.Right)); Row.AddPair(CozyText_OverlayEnvironmentProbe_bottom_10ed4a2d,TJSONNumber.Create(S.WindowRect.Bottom));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_workLeft_a710126f,TJSONNumber.Create(Info.rcWork.Left)); Row.AddPair(CozyText_OverlayEnvironmentProbe_workTop_3ec18ac2,TJSONNumber.Create(Info.rcWork.Top));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_workRight_703f3e4f,TJSONNumber.Create(Info.rcWork.Right)); Row.AddPair(CozyText_OverlayEnvironmentProbe_workBottom_3fc99347,TJSONNumber.Create(Info.rcWork.Bottom));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_clearCount_4e10dd44,TJSONNumber.Create(S.InputClearCount));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_clearBefore_2be06509,TJSONNumber.Create(ClearsBefore));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_dragging_2291c119,TJSONBool.Create(S.Dragging)); Row.AddPair(CozyText_OverlayEnvironmentProbe_buttonTracking_7ffd4dcb,TJSONBool.Create(S.ButtonTracking));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_captureOwned_1da82c51,TJSONBool.Create(S.CaptureOwned));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_sessionPaused_2464779c,TJSONBool.Create(S.SessionPaused));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_sessionRegistered_3b217bcc,TJSONBool.Create(S.SessionNotificationsRegistered));
  Row.AddPair(CozyText_OverlayEnvironmentProbe_suggestedMatches_987e396f,TJSONBool.Create(S.DpiSuggestedMatches));
  if (Msg=WM_LBUTTONDOWN) or (Msg=WM_LBUTTONUP) then
  begin
    X := SmallInt(LOWORD(LP)); Y := SmallInt(HIWORD(LP));
    Row.AddPair('x',TJSONNumber.Create(X)); Row.AddPair('y',TJSONNumber.Create(Y));
    Row.AddPair(CozyText_OverlayEnvironmentProbe_hostButtonHit_ab3779e7,TJSONBool.Create(OverlayTestButtonHit(X,Y)));
  end;
  Row.AddPair(CozyText_OverlayEnvironmentProbe_revealComplete_165dc7cb,TJSONBool.Create(S.RevealComplete));
  Events.AddElement(Row);
end;
procedure IntroContract;
var W: HWND; S: TOverlayEnvironmentSnapshot;
begin
  W:=HWND(OverlayTestWindow); S:=OverlayTestEnvironment;
  Require((W<>0) and not S.RevealComplete,CozyText_OverlayEnvironmentProbe_INTRO_FIRST_VISIBLE_FRAME_IS_PARTIAL_a57d76a6);
  IntroStarted:=CozyTick; InputEnabled:=True;
  SendMessage(W,WM_KEYDOWN,VK_RETURN,0);
  SendMessage(W,WM_KEYDOWN,VK_RIGHT,0);
  SendMessage(W,WM_CHAR,Ord('x'),0);
  SendMessage(W,WM_LBUTTONDOWN,MK_LBUTTON,PointParam(10,10));
  SendMessage(W,WM_LBUTTONDOWN,MK_LBUTTON,PointParam(340,220));
  SendMessage(W,WM_PAINT,0,0); S:=OverlayTestEnvironment;
  Require((S.ScenePhase=0) and (S.SceneSelected=1) and
    not S.Dragging and not S.ButtonTracking and not S.CaptureOwned and
    (InputCommits=0) and (LegacyStartCalls=0),CozyText_OverlayEnvironmentProbe_INTRO_BLOCKS_HOST_AND_SCENE_INPUT_bbc37a20);
  SendMessage(W,WM_KEYUP,VK_RETURN,0);
  SendMessage(W,WM_KEYUP,VK_RIGHT,0);
  SendMessage(W,WM_LBUTTONUP,0,PointParam(340,220));
  InputEnabled:=False;
end;
procedure Contract;
var W: HWND; S: TOverlayEnvironmentSnapshot; R, ClientArea: TRect;
  D,OldClears: Cardinal; I: Integer; SceneScale, HeightScale: Single;
  Monitor: HMONITOR; Info: TMonitorInfo;
const Dpis: array[0..4] of Cardinal = (96,120,144,192,240);
begin
  Require(OverlayTestEnvironment.RevealComplete,CozyText_OverlayEnvironmentProbe_INTRO_COMPLETES_BEFORE_INTERACTION_CONTRACT_2124418e);
  W := HWND(OverlayTestWindow); Require(W<>0,CozyText_OverlayEnvironmentProbe_owned_real_renderer_HWND_d9480fad);
  InputEnabled := False;
  SendMessage(W, WM_SETFOCUS, 0, 0);
  SendMessage(W, WM_CHAR, Ord('x'), 0);
  Require(InputCommits=0,CozyText_OverlayEnvironmentProbe_display_only_ignores_characters_9671c46c);
  InputEnabled := True;
  SendMessage(W, WM_CHAR, $D55C, 0);
  Require((InputCommits=1) and (InputText=UTF8String('한')),CozyText_OverlayEnvironmentProbe_owned_WM_CHAR_commits_Korean_de41012e);
  SendMessage(W, WM_IME_CHAR, $AE00, 0);
  Require((InputCommits=2) and (InputText=UTF8String(CozyText_OverlayEnvironmentProbe_Text_9a5dccdf)),CozyText_OverlayEnvironmentProbe_WM_IME_CHAR_default_processing_commits_exactly_o_217faa37);
  SendMessage(W, WM_IME_STARTCOMPOSITION, 0, 0);
  SendMessage(W, WM_IME_COMPOSITION, 0, 0);
  SendMessage(W, WM_IME_ENDCOMPOSITION, 0, 0);
  Require((InputBegins=1) and (InputCancels=1) and (InputEnds=1) and
    (InputCommits=2),CozyText_OverlayEnvironmentProbe_composition_cancel_never_fabricates_committed_te_ab46a136);
  SendMessage(W, WM_CHAR, $D800, 0);
  SendMessage(W, WM_KILLFOCUS, 0, 0);
  SendMessage(W, WM_SETFOCUS, 0, 0);
  SendMessage(W, WM_CHAR, $DC00, 0);
  Require((InputCommits=2) and (InputFocusLosses=1),CozyText_OverlayEnvironmentProbe_focus_loss_wipes_pending_UTF16_78e2609e);
  SendMessage(W, WM_CHAR, Ord('a'), 0);
  Require((InputCommits=3) and (InputText=UTF8String(CozyText_OverlayEnvironmentProbe_a_eda41243)),CozyText_OverlayEnvironmentProbe_input_resumes_only_after_new_focus_a3509a10);
  SendMessage(W, WM_CHAR, $D800, 0);
  SendMessage(W, WM_CHAR, 8, 0);
  SendMessage(W, WM_CHAR, $AC00, 0);
  Require(InputCommits=4,CozyText_OverlayEnvironmentProbe_Backspace_retires_a_pending_surrogate_fa18a975);
  SendMessage(W, WM_CHAR, $D800, 0);
  SendMessage(W, WM_CHAR, 13, 0);
  SendMessage(W, WM_CHAR, $AC01, 0);
  Require(InputCommits=5,CozyText_OverlayEnvironmentProbe_Enter_retires_a_pending_surrogate_d6b11f59);
  SendMessage(W, WM_CHAR, $D800, 0);
  SendMessage(W, WM_CHAR, $10000, 0);
  SendMessage(W, WM_CHAR, $AC02, 0);
  Require(InputCommits=6,CozyText_OverlayEnvironmentProbe_out_of_range_WM_CHAR_retires_a_pending_surrogate_7d3acd49);
  InputEnabled := False;
  SendMessage(W, WM_CHAR, Ord('z'), 0);
  Require(InputCommits=6,CozyText_OverlayEnvironmentProbe_editor_opt_out_immediately_disables_text_transpo_6f0704d0);
  InputText := '';
  S:=OverlayTestEnvironment;
  Require((S.ScenePhase=0) and (S.SceneSelected=1),CozyText_OverlayEnvironmentProbe_compact_gallery_is_the_initial_and_only_product__8d06fdb6);
  SendMessage(W,WM_KEYDOWN,VK_RETURN,0); SendMessage(W,WM_PAINT,0,0);
  Require((OverlayTestEnvironment.ScenePhase=0) and (ProductStartCalls=0),
    CozyText_OverlayEnvironmentProbe_INITIAL_UNLICENSED_PRODUCT_START_DISABLED_577f1903);
  SendMessage(W,WM_KEYUP,VK_RETURN,0);
  SendMessage(W,WM_KEYDOWN,VK_RIGHT,0); SendMessage(W,WM_PAINT,0,0);
  S:=OverlayTestEnvironment; Require(S.SceneSelected=2,CozyText_OverlayEnvironmentProbe_Right_selects_the_next_sample_artwork_41cf6cff);
  SendMessage(W,WM_KEYDOWN,Ord('A'),0); SendMessage(W,WM_PAINT,0,0);
  S:=OverlayTestEnvironment; Require(S.SceneSelected=1,CozyText_OverlayEnvironmentProbe_A_selects_the_preceding_sample_artwork_268eed7d);
  SendMessage(W,WM_KEYDOWN,VK_LEFT,0); SendMessage(W,WM_PAINT,0,0);
  S:=OverlayTestEnvironment; Require(S.SceneSelected=0,CozyText_OverlayEnvironmentProbe_A_selects_the_preceding_sample_artwork_268eed7d);
  SendMessage(W,WM_KEYDOWN,VK_LEFT,0); SendMessage(W,WM_PAINT,0,0);
  S:=OverlayTestEnvironment; Require(S.SceneSelected=5,CozyText_OverlayEnvironmentProbe_A_selects_the_preceding_sample_artwork_268eed7d);
  for I:=1 to 6 do begin SendMessage(W,WM_KEYDOWN,VK_RIGHT,0); SendMessage(W,WM_PAINT,0,0); end;
  S:=OverlayTestEnvironment; Require(S.SceneSelected=5,CozyText_OverlayEnvironmentProbe_A_selects_the_preceding_sample_artwork_268eed7d);
  { Allow the real spring to settle on the licensed centre card. }
  for I:=1 to 40 do begin Sleep(15); SendMessage(W,WM_PAINT,0,0); end;
  SendMessage(W,WM_KEYDOWN,VK_RETURN,0); SendMessage(W,WM_PAINT,0,0);
  S:=OverlayTestEnvironment;
  Require((S.ScenePhase=1) and (ProductStartCalls=1) and
    (LegacyStartCalls=0) and (LegacyStateReads=0), CozyText_OverlayEnvironmentProbe_START_PRODUCT_AUTHORIZATION_QUEUED_8409f219);
  SendMessage(W,WM_KEYDOWN,VK_RETURN,LPARAM($40000000));
  SendMessage(W,WM_KEYDOWN,VK_RIGHT,0);
  SendMessage(W,WM_LBUTTONDOWN,MK_LBUTTON,PointParam(340,220));
  SendMessage(W,WM_PAINT,0,0); S:=OverlayTestEnvironment;
  Require((S.SceneSelected=5) and (S.ScenePhase=1) and not S.CaptureOwned,
    CozyText_OverlayEnvironmentProbe_START_PENDING_INPUT_DISABLED_e648153f);
  { This isolated fixture supplies an explicit acknowledgement callback; it
    is not a real server receipt, license or runtime authorization proof. }
  FixtureProductState:=2;
  SendMessage(W,WM_PAINT,0,0); S:=OverlayTestEnvironment;
  Require((S.ScenePhase=2) and not S.ReceiptOnly and IsWindow(W),
    CozyText_OverlayEnvironmentProbe_START_AUTHORIZED_COUNTDOWN_STAYS_OPEN_d5965597);
  SendMessage(W,WM_KEYDOWN,VK_RIGHT,0);
  SendMessage(W,WM_LBUTTONDOWN,MK_LBUTTON,PointParam(300,44));
  SendMessage(W,WM_PAINT,0,0); S:=OverlayTestEnvironment;
  Require((S.ScenePhase=2) and (S.SceneSelected=5) and (S.SceneCategory=0) and not S.CaptureOwned,
    CozyText_OverlayEnvironmentProbe_COUNTDOWN_CARD_TAB_AND_WINDOW_INPUT_DISABLED_f8990afa);
  Sleep(4500); SendMessage(W,WM_PAINT,0,0);
  Require(OverlayTestEnvironment.ScenePhase=2,CozyText_OverlayEnvironmentProbe_COUNTDOWN_DOES_NOT_FINISH_EARLY_cc1b8f73);
  Sleep(550); SendMessage(W,WM_PAINT,0,0); S:=OverlayTestEnvironment;
  Require((S.ScenePhase=0) and not S.ReceiptOnly and IsWindow(W),
    CozyText_OverlayEnvironmentProbe_COUNTDOWN_RETURNS_TO_INTERACTIVE_GALLERY_cf2efbf9);
  Require(S.RevealComplete,CozyText_OverlayEnvironmentProbe_START_DOES_NOT_RESTART_INTRO_84f56168);
  SendMessage(W,WM_KEYDOWN,VK_RIGHT,0); SendMessage(W,WM_PAINT,0,0);
  S:=OverlayTestEnvironment; Require(S.SceneSelected=0,CozyText_OverlayEnvironmentProbe_COUNTDOWN_INPUT_RESTORED_5a835c4d);
  for I:=1 to 40 do begin Sleep(15); SendMessage(W,WM_PAINT,0,0); end;
  SendMessage(W,WM_KEYDOWN,VK_RETURN,0); SendMessage(W,WM_PAINT,0,0);
  Require((OverlayTestEnvironment.ScenePhase=0) and (ProductStartCalls=1),
    CozyText_OverlayEnvironmentProbe_UNLICENSED_PRODUCT_CANNOT_QUEUE_START_698bf247);
  WriteLn(CozyText_OverlayEnvironmentProbe_PASS_owned_window_Korean_text_input_contracts_ph_46d03128);
  for I := Low(Dpis) to High(Dpis) do
  begin
    D := Dpis[I]; R.Left := -120; R.Top := 50;
    R.Right := R.Left+Round(680*D/96); R.Bottom := R.Top+Round(440*D/96);
    SendMessage(W,DpiChanged,D or (D shl 16),LPARAM(@R));
    S := OverlayTestEnvironment;
    Require((S.Dpi=D) and S.DpiSuggestedMatches,CozyText_OverlayEnvironmentProbe_DPI_suggested_rectangle_applied_7e125eb8);
    Monitor := MonitorFromWindow(W,MONITOR_DEFAULTTONEAREST);
    FillChar(Info,SizeOf(Info),0); Info.cbSize := SizeOf(Info);
    Require((Monitor<>0) and GetMonitorInfo(Monitor,@Info),CozyText_OverlayEnvironmentProbe_per_monitor_DPI_transition_keeps_the_complete_sc_0f504ad3);
    Require((S.WindowRect.Left>=Info.rcWork.Left) and
      (S.WindowRect.Top>=Info.rcWork.Top) and
      (S.WindowRect.Right<=Info.rcWork.Right) and
      (S.WindowRect.Bottom<=Info.rcWork.Bottom),CozyText_OverlayEnvironmentProbe_per_monitor_DPI_transition_keeps_the_complete_sc_0f504ad3);
    Require(GetClientRect(W,ClientArea),CozyText_OverlayEnvironmentProbe_per_monitor_DPI_transition_keeps_the_complete_sc_0f504ad3);
    SceneScale := ClientArea.Right / 680;
    HeightScale := ClientArea.Bottom / 440;
    if HeightScale < SceneScale then SceneScale := HeightScale;
    Require(OverlayTestButtonHit(0,Round(90*SceneScale)),CozyText_OverlayEnvironmentProbe_top_left_inclusive_477ddded);
    Require(not OverlayTestButtonHit(ClientArea.Right,Round(90*SceneScale)),CozyText_OverlayEnvironmentProbe_right_exclusive_70538eb1);
    Require(not OverlayTestButtonHit(0,ClientArea.Bottom),CozyText_OverlayEnvironmentProbe_bottom_exclusive_0c644e11);
    Require(not OverlayTestButtonHit(Round(40*SceneScale),Round(20*SceneScale)),CozyText_OverlayEnvironmentProbe_only_the_empty_header_area_drags_the_window_d0a0aec2);
    Require(not OverlayTestButtonHit(ClientArea.Right-Round(24*SceneScale),Round(20*SceneScale)),CozyText_OverlayEnvironmentProbe_only_the_empty_header_area_drags_the_window_d0a0aec2);
    Require(OverlayTestButtonHit(Round(298*SceneScale),Round(52*SceneScale)),CozyText_OverlayEnvironmentProbe_scaled_button_hit_owns_capture_8d48b5d4);
    Require(OverlayTestButtonHit(Round(388*SceneScale),Round(52*SceneScale)),CozyText_OverlayEnvironmentProbe_scaled_button_hit_owns_capture_8d48b5d4);
    SendMessage(W,WM_LBUTTONDOWN,MK_LBUTTON,PointParam(Round(40*SceneScale),Round(90*SceneScale)));
    S := OverlayTestEnvironment;
    Require(S.ButtonTracking and S.CaptureOwned and not S.Dragging,CozyText_OverlayEnvironmentProbe_scaled_button_hit_owns_capture_8d48b5d4);
    OldClears := S.InputClearCount;
    SendMessage(W,SessionChanged,4,0); S := OverlayTestEnvironment;
    Require(S.SessionPaused and (S.InputClearCount>OldClears) and not S.CaptureOwned and
      not S.Dragging and not S.ButtonTracking,CozyText_OverlayEnvironmentProbe_disconnect_clears_input_and_pauses_6cd4a0a9);
    SendMessage(W,SessionChanged,3,0); S := OverlayTestEnvironment;
    Require(not S.SessionPaused and not S.CaptureOwned,CozyText_OverlayEnvironmentProbe_reconnect_remains_input_clear_f103a95e);
    SendMessage(W,WM_LBUTTONDOWN,MK_LBUTTON,PointParam(10,10));
    S := OverlayTestEnvironment; Require(S.Dragging and S.CaptureOwned,CozyText_OverlayEnvironmentProbe_empty_header_drag_owns_capture_cb448727);
    SendMessage(W,WM_KILLFOCUS,0,0); S := OverlayTestEnvironment;
    Require(not S.Dragging and not S.ButtonTracking and not S.CaptureOwned,CozyText_OverlayEnvironmentProbe_focus_loss_clears_drag_5d78eda4);
  end;
  S:=OverlayTestEnvironment;
  Require((S.ScenePhase=0) and not S.ReceiptOnly and IsWindow(W),
    CozyText_OverlayEnvironmentProbe_GALLERY_REMAINS_OPEN_AFTER_START_AND_DISPLAY_TES_37bb1a23);
  WriteLn(CozyText_OverlayEnvironmentProbe_PASS_synthetic_message_contracts_five_DPI_scales_9aa44bbb);
  WriteLn(CozyText_OverlayEnvironmentProbe_NOT_RUN_physical_monitors_and_real_RDP_transitio_0cfda407);
end;
procedure Run;
var Status: Integer; Report: TJSONObject; Queued: TMsg; ReportText: string;
begin
  while PeekMessage(Queued,0,WM_QUIT,WM_QUIT,PM_REMOVE) do ;
  Started := CozyTick; LastSample := 0;
  SetOverlayEnvironmentObserver(
    procedure(Msg: Cardinal; WP: NativeUInt; LP: NativeInt; ClearsBefore: Cardinal)
    begin
      if not Interactive then Exit;
      if (Msg=DpiChanged) or (Msg=WM_KILLFOCUS) or (Msg=WM_SETFOCUS) or
        (Msg=SessionChanged) or (Msg=WM_DISPLAYCHANGE) or (Msg=WM_LBUTTONDOWN) or
        (Msg=WM_LBUTTONUP) then begin AddEvent(CozyText_OverlayEnvironmentProbe_message_c0b1bfee,Msg,WP,LP,ClearsBefore); Inc(SeenMessages); end;
      if (Msg=WM_KEYUP) and (WP=VK_F6) then AddEvent(CozyText_OverlayEnvironmentProbe_operator_checkpoint_7cd5e192,Msg,WP,LP);
      if (Msg=WM_KEYUP) and (WP=VK_F10) then Finished := True;
    end);
  try
    Status := RunOverlayUI(
      procedure
      begin
        if not Interactive then
        begin
          if not IntroChecked then begin IntroChecked:=True; IntroContract; end;
          if not OverlayTestEnvironment.RevealComplete then
          begin
            Require(CozyTick-IntroStarted<10000,CozyText_OverlayEnvironmentProbe_INTRO_COMPLETION_DEADLINE_16bce147);
            Exit;
          end;
          if not ContractDone then begin ContractDone := True; Contract; end;
          PostMessage(HWND(OverlayTestWindow),WM_CLOSE,0,0);
        end
        else if (LastSample=0) or (CozyTick-LastSample>=500) then
        begin AddEvent(CozyText_OverlayEnvironmentProbe_sample_e0540f01,0,0,0); LastSample := CozyTick; end;
        if Finished then PostMessage(HWND(OverlayTestWindow),WM_CLOSE,0,0);
      end,
      function: Boolean
      begin
        if CozyTick-Started>1800000 then begin TimedOut := True; Finished := True; end;
        Result := TimedOut;
      end, nil, nil, nil, nil, nil,
      function: Boolean
      begin Result := not Interactive and InputEnabled; end,
      procedure(Event: TOverlayTextInputEvent; const Text: UTF8String)
      begin
        case Event of
          otieCommitted: begin Inc(InputCommits); InputText := InputText + Text; end;
          otieCompositionBegin: Inc(InputBegins);
          otieCompositionEnd: Inc(InputEnds);
          otieCompositionCancelled: Inc(InputCancels);
          otieFocusLost: Inc(InputFocusLosses);
        end;
      end,
      procedure begin Inc(LegacyStartCalls); end,
      function: Integer begin Inc(LegacyStateReads); Result:=2; end,
      nil,nil,
      function: Integer begin Result:=5; end,
      function(Card: Integer): Boolean
      begin
        Result := (Card=5) and (FixtureProductState=0);
        if Result then begin Inc(ProductStartCalls); FixtureProductState:=1; end;
      end,
      function: Integer
      begin
        Result := FixtureProductState;
        if Result in [2,3] then FixtureProductState:=0;
      end);
    Require(Status=0,CozyText_OverlayEnvironmentProbe_renderer_clean_shutdown_0dbdf030);
    if not Interactive then
    begin
      Require(ContractDone,CozyText_OverlayEnvironmentProbe_contract_executed_49b42724);
      Require((LegacyStartCalls=0) and (LegacyStateReads=0),
        CozyText_OverlayEnvironmentProbe_REMOVED_SERVER_SHUTDOWN_CALLBACKS_UNUSED_16ff2d78);
      Exit;
    end;
    Report := TJSONObject.Create;
    try
      Report.AddPair(CozyText_OverlayEnvironmentProbe_version_171ab317,TJSONNumber.Create(1)); Report.AddPair(CozyText_OverlayEnvironmentProbe_kind_8b51a854,CozyText_OverlayEnvironmentProbe_OVERLAY_ENVIRONMENT_MEASUREMENT_d11c6f73);
      Report.AddPair(CozyText_OverlayEnvironmentProbe_nonce_ce7ccaa7,Nonce); Report.AddPair(CozyText_OverlayEnvironmentProbe_mode_5bd0498a,CozyText_OverlayEnvironmentProbe_INTERACTIVE_WINDOW_MESSAGES_d8ff7e36);
      Report.AddPair(CozyText_OverlayEnvironmentProbe_syntheticMessages_a7f6a26f,TJSONBool.Create(False));
      Report.AddPair(CozyText_OverlayEnvironmentProbe_hardwareAttested_2ed128a4,TJSONBool.Create(False));
      Report.AddPair(CozyText_OverlayEnvironmentProbe_operatorFinished_899313b3,TJSONBool.Create(Finished and not TimedOut));
      Report.AddPair(CozyText_OverlayEnvironmentProbe_durationMs_648c3c42,TJSONNumber.Create(Int64(CozyTick-Started)));
      Report.AddPair(CozyText_OverlayEnvironmentProbe_screenCount_69792615,TJSONNumber.Create(GetSystemMetrics(SM_CMONITORS)));
      Report.AddPair(CozyText_OverlayEnvironmentProbe_remoteAtFinish_f3257de7,TJSONBool.Create(GetSystemMetrics(SM_REMOTESESSION)<>0));
      Report.AddPair(CozyText_OverlayEnvironmentProbe_events_2495b16c,Events); Events := nil;
      ReportText := Report.ToJSON;
      Require(not TFile.Exists(OutputFile),CozyText_OverlayEnvironmentProbe_output_must_be_new_5d28dd8f);
      TFile.WriteAllText(OutputFile,ReportText,TEncoding.UTF8);
      WriteLn(CozyText_OverlayEnvironmentProbe_MEASURED_712fa572,SeenMessages,CozyText_OverlayEnvironmentProbe_messages_Physical_results_require_independent_re_6451d6ea);
    finally Report.Free; end;
  finally SetOverlayEnvironmentObserver(nil); end;
end;
begin
  try
    Interactive := (ParamCount=5) and (ParamStr(1)=CozyText_OverlayEnvironmentProbe_interactive_b1e4717f) and (ParamStr(2)=CozyText_OverlayEnvironmentProbe_output_fe11b4d2) and (ParamStr(4)=CozyText_OverlayEnvironmentProbe_nonce_5acaeff0);
    if Interactive then
    begin
      OutputFile := ParamStr(3); Nonce := ParamStr(5);
      Require((Length(Nonce)=64) and TPath.IsPathRooted(OutputFile),CozyText_OverlayEnvironmentProbe_fresh_workflow_nonce_and_absolute_output_292d4807);
      WriteLn(CozyText_OverlayEnvironmentProbe_Drag_the_real_ImGui_window_between_PHYSICAL_moni_e5b37097);
      WriteLn(CozyText_OverlayEnvironmentProbe_On_each_monitor_interact_with_the_artwork_cards__2a2e0384);
      WriteLn(CozyText_OverlayEnvironmentProbe_Hold_mouse_drag_or_a_key_switch_focus_verify_no__25ad78d0);
      WriteLn(CozyText_OverlayEnvironmentProbe_Disconnect_reconnect_the_SAME_Windows_session_ov_7fb90abb);
      WriteLn(CozyText_OverlayEnvironmentProbe_After_all_transitions_inspect_position_and_hit_a_116043aa);
      WriteLn(CozyText_OverlayEnvironmentProbe_No_message_injection_test_automation_or_simulate_9bc1dfbe);
    end
    else Require((ParamCount=0) or ((ParamCount=1) and (ParamStr(1)=CozyText_OverlayEnvironmentProbe_contract_53267b2e)),CozyText_OverlayEnvironmentProbe_arguments_953b5f48);
    Events := TJSONArray.Create;
    BindApiPointer(SlotProbeDpi,RequireProcAddressHash64(CozyText_OverlayEnvironmentProbe_user32_dll_860bcf67,HASH_GetDpiForWindow));
    try SealApiPointerStorage; Run; finally Events.Free; end;
  except on E: Exception do begin WriteLn(E.ClassName,CozyText_OverlayEnvironmentProbe_Text_10b41730,E.Message); Halt(1); end; end;
end.
