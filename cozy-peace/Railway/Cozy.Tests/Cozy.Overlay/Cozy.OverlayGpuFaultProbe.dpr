program Cozy_OverlayGpuFaultProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF GAME_IMGUI_FAULT_TESTS}{$MESSAGE FATAL 'Isolated fault object required.'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',
 Winapi.Windows, System.SysUtils, Cozy.Api.Pointer,
  Cozy.Overlay.ImGui, Cozy.Overlay.State, Cozy.Overlay.Renderer;
procedure game_imgui_test_fault(Stage, Error: Integer); cdecl; external name 'game_imgui_test_fault';
function game_imgui_test_retain_device(Context: Pointer): Pointer; cdecl; external name 'game_imgui_test_retain_device';
function game_imgui_test_live_arena_bytes: NativeUInt; cdecl; external name 'game_imgui_test_live_arena_bytes';
procedure Require(Value: Boolean; const Name: string);
begin if not Value then raise Exception.Create(CozyText_OverlayGpuFaultProbe_OVERLAY_GPU_FAULT_5ddf5ce5+Name); end;
procedure DestroyMeasured(var Context: TImGuiContext);
var Device: IUnknown; Refs: Integer;
begin
  Device := nil;
  Pointer(Device) := game_imgui_test_retain_device(Context);
  Require(Device <> nil, CozyText_OverlayGpuFaultProbe_retain_independent_real_device_reference_f58f259b);
  ImGuiDestroy(Context);
  Require(Context = nil, CozyText_OverlayGpuFaultProbe_context_ownership_retired_13667f49);
  Require(game_imgui_test_live_arena_bytes = 0, CozyText_OverlayGpuFaultProbe_all_context_reservation_ownership_retired_978de361);
  Refs := Device._AddRef; Device._Release;
  Require(Refs = 2, CozyText_OverlayGpuFaultProbe_backend_and_swap_chain_released_external_device__94965756);
  Device := nil;
  ImGuiDestroy(Context);
end;
procedure RunFaults;
const Faults: array[0..3] of Cardinal = ($8007000E,$887A0005,$887A0006,$887A0007);
var Wnd: HWND; Context: TImGuiContext; I, Error: Integer; Rejected: Boolean;
begin
  Wnd := CreateWindowEx(0, CozyText_OverlayGpuFaultProbe_STATIC_4ce096cd, CozyText_OverlayGpuFaultProbe_Native_overlay_fault_probe_1d64fdd8, WS_OVERLAPPEDWINDOW,
    100,100,320,160,0,0,HInstance,nil);
  Require(Wnd <> 0, CozyText_OverlayGpuFaultProbe_real_test_owned_HWND_2bd80fcb); ShowWindow(Wnd,SW_SHOW);
  Context := nil;
  try
    for I := Low(Faults) to High(Faults) do
    begin
      Error := Integer(Faults[I]); Rejected := False;
      game_imgui_test_fault(1,Error);
      try Context := ImGuiCreate(Wnd);
      except on E: Exception do begin
        Require(E is EOverlayImGuiFailure, CozyText_OverlayGpuFaultProbe_create_keeps_typed_graphics_failure_4c72c486);
        Require(EOverlayImGuiFailure(E).Stage = igfsCreate, CozyText_OverlayGpuFaultProbe_create_keeps_failure_stage_f17e89cc);
        Require(EOverlayImGuiFailure(E).NativeCode = Error, CozyText_OverlayGpuFaultProbe_create_keeps_original_HRESULT_9f9eb44c);
        Require(E.Message=OverlayGraphicsFailure(Error,CozyText_OverlayGpuFaultProbe_CREATE_98e063bb),CozyText_OverlayGpuFaultProbe_create_HRESULT_classification_f0e9ebaf);
        Rejected := True;
      end; end;
      Require(Rejected and (Context=nil), CozyText_OverlayGpuFaultProbe_real_allocation_then_injected_Create_failure_0cdd3473);
      Require(game_imgui_test_live_arena_bytes=0, CozyText_OverlayGpuFaultProbe_failed_Create_releases_committed_arena_335fb457);
      game_imgui_test_fault(0,0); Context := ImGuiCreate(Wnd);
      game_imgui_test_fault(2,Error);
      Require(not ImGuiResize(Context,640,320), CozyText_OverlayGpuFaultProbe_actual_Resize_failure_688b8cc4);
      Require(ImGuiLastError(Context)=Error, CozyText_OverlayGpuFaultProbe_resize_HRESULT_preserved_4aa3a417);
      DestroyMeasured(Context);
      game_imgui_test_fault(0,0); Context := ImGuiCreate(Wnd);
      Require(ImGuiNewFrame(Context,320,160,1/60), CozyText_OverlayGpuFaultProbe_actual_backend_NewFrame_d295243f);
      ImGuiBeginCanvas(Context); ImGuiSetCursorPos(Context,32,52);
      ImGuiButton(Context,PAnsiChar(AnsiString(CozyText_OverlayGpuFaultProbe_Injection_441f79ea)),256,44);
      ImGuiEndCanvas(Context); game_imgui_test_fault(3,Error);
      Require(ImGuiPresent(Context)=IMGUI_PRESENT_FAILED, CozyText_OverlayGpuFaultProbe_failed_real_Present_cannot_be_visible_9fae952c);
      Require(ImGuiLastError(Context)=Error, CozyText_OverlayGpuFaultProbe_present_HRESULT_preserved_9dcbb3d8);
      DestroyMeasured(Context);
      WriteLn(CozyText_OverlayGpuFaultProbe_PASS_real_D3D11_create_resize_present_failure_3c45942f,IntToHex(Faults[I],8));
    end;
  finally
    game_imgui_test_fault(0,0); ImGuiDestroy(Context); DestroyWindow(Wnd);
  end;
end;
procedure RunStartupFailureDiagnostics;
const OriginalError = Integer($8007000E);
var DiagnosticThrows, Detailed: Boolean; Scenario, FailAt, FaultStage: Integer;
  ExpectedStage: string; ExpectedTypedStage: TOverlayImGuiFailureStage;
  FailedCount, DetailedCount, ClosingCount, ReadyCount, Order, FailedOrder, ClosingOrder: Integer;
  Rejected: Boolean; RuntimeDeadline: UInt64;
  FailureCallback: TProc<string,Integer>;
begin
  FailureCallback := nil;
  for Scenario := 0 to 7 do
  begin
    DiagnosticThrows := Scenario mod 2 <> 0;
    Detailed := Scenario mod 4 >= 2;
    FaultStage := 1 + Scenario div 4;
    ExpectedStage := CozyText_OverlayGpuFaultProbe_CREATE_98e063bb;
    ExpectedTypedStage := igfsCreate;
    if FaultStage = 2 then
    begin
      ExpectedStage := CozyText_OverlayGpuFaultProbe_RESIZE_8c426906;
      ExpectedTypedStage := igfsResize;
    end;
    FailedCount := 0; DetailedCount := 0; ClosingCount := 0; Order := 0;
    FailedOrder := 0; ClosingOrder := 0; Rejected := False;
    FailureCallback := nil;
    if Detailed then
      FailureCallback :=
        procedure(Stage: string; NativeCode: Integer)
        begin
          Require(Stage = ExpectedStage, CozyText_OverlayGpuFaultProbe_detailed_callback_keeps_exact_create_or_initial__380c2510);
          Require(NativeCode = OriginalError, CozyText_OverlayGpuFaultProbe_detailed_callback_keeps_exact_signed_HRESULT_13d47808);
          Inc(DetailedCount); Inc(Order); FailedOrder := Order;
          if DiagnosticThrows then
            raise Exception.Create(CozyText_OverlayGpuFaultProbe_TEST_STARTUP_DIAGNOSTIC_UNAVAILABLE_42d7a714);
        end;
    game_imgui_test_fault(FaultStage, OriginalError);
    try
      try
        RunOverlayUI(
          procedure begin end,
          function: Boolean begin Result := False; end,
          procedure
          begin
            Inc(ClosingCount); Inc(Order); ClosingOrder := Order;
          end,
          nil, nil, nil,
          procedure(Phase: string)
          begin
            if Phase <> CozyText_OverlayGpuFaultProbe_FAILED_85976e1a then Exit;
            Inc(FailedCount); Inc(Order); FailedOrder := Order;
            if DiagnosticThrows then
              raise Exception.Create(CozyText_OverlayGpuFaultProbe_TEST_STARTUP_DIAGNOSTIC_UNAVAILABLE_42d7a714);
          end,
          nil, nil, nil, nil, FailureCallback);
      except
        on E: EOverlayImGuiFailure do
        begin
          Require((E.Stage = ExpectedTypedStage) and (E.NativeCode = OriginalError),
            CozyText_OverlayGpuFaultProbe_renderer_preserves_original_create_or_initial_re_048c7538);
          Require(E.Message = OverlayGraphicsFailure(OriginalError, ExpectedStage),
            CozyText_OverlayGpuFaultProbe_diagnostic_failure_does_not_replace_original_saf_c3d67e40);
          Rejected := True;
        end;
      end;
    finally game_imgui_test_fault(0, 0); end;
    Require(Rejected, CozyText_OverlayGpuFaultProbe_renderer_propagates_original_startup_error_d49bd272);
    Require((Detailed and (DetailedCount = 1) and (FailedCount = 0)) or
      (not Detailed and (DetailedCount = 0) and (FailedCount = 1)),
      CozyText_OverlayGpuFaultProbe_one_detailed_diagnostic_or_one_legacy_phase_fall_aa881dc8);
    Require(ClosingCount = 1, CozyText_OverlayGpuFaultProbe_one_closing_callback_after_startup_failure_777cf2fe);
    Require((FailedOrder > 0) and (FailedOrder < ClosingOrder),
      CozyText_OverlayGpuFaultProbe_startup_diagnostic_precedes_cancellation_in_OnCl_a76bf0b7);
    Require(game_imgui_test_live_arena_bytes = 0,
      CozyText_OverlayGpuFaultProbe_renderer_startup_diagnostic_path_releases_native_0d688266);
  end;
  FailureCallback := nil;

  for Scenario := 1 to 2 do
  begin
    FailAt := Scenario;
    ReadyCount := 0; FailedCount := 0; DetailedCount := 0; ClosingCount := 0; Rejected := False;
    RuntimeDeadline := GetTickCount64 + 10000;
    try
      RunOverlayUI(
        procedure
        begin
          Inc(ReadyCount);
          if ReadyCount = FailAt then
            raise EInvalidOpException.Create(CozyText_OverlayGpuFaultProbe_TEST_POST_READY_FAILURE_386e760e);
        end,
        function: Boolean begin Result := GetTickCount64 >= RuntimeDeadline; end,
        procedure begin Inc(ClosingCount); end,
        nil, nil, nil,
        procedure(Phase: string)
        begin
          if Phase = CozyText_OverlayGpuFaultProbe_FAILED_85976e1a then Inc(FailedCount);
        end,
        nil, nil, nil, nil,
        procedure(Stage: string; NativeCode: Integer)
        begin Inc(DetailedCount); end);
    except
      on E: EInvalidOpException do
      begin
        Require(E.Message = CozyText_OverlayGpuFaultProbe_TEST_POST_READY_FAILURE_386e760e,
          CozyText_OverlayGpuFaultProbe_visible_frame_failure_remains_original_failure_dcdb0262);
        Rejected := True;
      end;
    end;
    Require(Rejected and (ReadyCount = FailAt), CozyText_OverlayGpuFaultProbe_visible_first_second_ready_callback_fails_as_int_10f2b6cf);
    Require((FailedCount = 0) and (DetailedCount = 0) and (ClosingCount = 1),
      CozyText_OverlayGpuFaultProbe_visible_first_frame_and_post_ready_teardown_neve_064e9044);
    Require(game_imgui_test_live_arena_bytes = 0,
      CozyText_OverlayGpuFaultProbe_visible_renderer_failure_releases_native_reserva_85f8b44b);
  end;
  WriteLn(CozyText_OverlayGpuFaultProbe_PASS_renderer_startup_diagnostics_precede_closin_aade80fe);
end;
procedure RunNumericExceptionDiagnostics;
const ExternalCode = Cardinal($E0424242);
  FloatingPointCode = Cardinal($C000008E);
var Scenario, ExpectedCode, DetailedCount, ClosingCount: Integer;
  ExpectedStage: string; Rejected: Boolean;
begin
  { These synthetic exceptions occur before native allocation. They test only
    the diagnostic boundary; no invalid pointer or actual arithmetic fault is
    needed, and their message must never be parsed into a public code. }
  for Scenario := 0 to 4 do
  begin
    ExpectedStage := CozyText_OverlayGpuFaultProbe_CREATE_98e063bb;
    ExpectedCode := 0;
    case Scenario of
      0: ExpectedCode := Integer(ExternalCode);
      2: ExpectedCode := 5;
      3: begin ExpectedStage := CozyText_OverlayGpuFaultProbe_FLOATING_POINT_99833e6e; ExpectedCode := Integer(FloatingPointCode); end;
    end;
    DetailedCount := 0; ClosingCount := 0; Rejected := False;
    try
      RunOverlayUI(
        procedure begin end,
        function: Boolean begin Result := False; end,
        procedure begin Inc(ClosingCount); end,
        nil, nil, nil,
        procedure(Phase: string)
        var OSError: EOSError;
        begin
          if Phase <> CozyText_OverlayGpuFaultProbe_GPU_BEGIN_263ba954 then Exit;
          case Scenario of
            0: RaiseException(ExternalCode, 0, 0, nil);
            1: raise Exception.Create(CozyText_OverlayGpuFaultProbe_PRIVATE_TEST_MESSAGE_0x8007000E_193e81cf);
            2: begin
              OSError := EOSError.Create(CozyText_OverlayGpuFaultProbe_PRIVATE_TEST_MESSAGE_0x8007000E_193e81cf);
              OSError.ErrorCode := 5;
              raise OSError;
            end;
            3: RaiseException(FloatingPointCode, 0, 0, nil);
            4: raise EExternalException.Create(CozyText_OverlayGpuFaultProbe_PRIVATE_TEST_MESSAGE_0x8007000E_193e81cf);
          end;
        end,
        nil, nil, nil, nil,
        procedure(Stage: string; NativeCode: Integer)
        begin
          Require(Stage = ExpectedStage, CozyText_OverlayGpuFaultProbe_numeric_exception_keeps_its_closed_active_stage_6d567a5e);
          Require(NativeCode = ExpectedCode, CozyText_OverlayGpuFaultProbe_numeric_exception_keeps_only_its_OS_code_or_zero_9e1bca3f);
          Inc(DetailedCount);
          raise Exception.Create(CozyText_OverlayGpuFaultProbe_TEST_STARTUP_DIAGNOSTIC_UNAVAILABLE_42d7a714);
        end);
    except
      on E: Exception do
      begin
        case Scenario of
          0, 4: Require(E is EExternal, CozyText_OverlayGpuFaultProbe_external_exception_propagates_unchanged_1c09892f);
          1: Require(E.ClassType = Exception, CozyText_OverlayGpuFaultProbe_ordinary_exception_propagates_unchanged_bcc2305d);
          2: Require((E is EOSError) and (EOSError(E).ErrorCode = 5), CozyText_OverlayGpuFaultProbe_OS_exception_propagates_unchanged_5ec340e2);
          3: Require(E is EMathError, CozyText_OverlayGpuFaultProbe_floating_point_exception_propagates_unchanged_04042af0);
        end;
        Rejected := True;
      end;
    end;
    Require(Rejected and (DetailedCount = 1) and (ClosingCount = 1),
      CozyText_OverlayGpuFaultProbe_numeric_failure_is_reported_once_before_normal_t_6a56c8fd);
    Require(game_imgui_test_live_arena_bytes = 0, CozyText_OverlayGpuFaultProbe_synthetic_exception_retains_no_native_reservatio_1d544182);
  end;
  WriteLn(CozyText_OverlayGpuFaultProbe_PASS_bounded_startup_OS_exception_diagnostics_65054ca2);
end;
begin
  try SealApiPointerStorage; RunFaults; RunStartupFailureDiagnostics; RunNumericExceptionDiagnostics;
    WriteLn(CozyText_OverlayGpuFaultProbe_PASS_actual_Windows_D3D_resource_failure_unwind__78dda565);
  except on E: Exception do begin WriteLn(E.ClassName,CozyText_OverlayGpuFaultProbe_Text_1d5caa9a,E.Message); Halt(1); end; end;
end.
