program Cozy_OverlayMitigationProbe;
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
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',
 Cozy.Clock, Winapi.Windows, Winapi.Messages, System.SysUtils, System.JSON, System.Generics.Collections,
  Cozy.Api.Pointer, Cozy.ProcessMitigations, Cozy.Overlay.Renderer,
  Cozy.MitigationProbeSupport in '..\Cozy.Security\Cozy.MitigationProbeSupport.pas';
var P,J,Environment: TJSONObject; O: TMitigationObservation;
  Mode,DynamicState,CfgState,RendererState: string;
  Deadline: UInt64; Frames,Status: Integer;
  Authorized,TimedOut,Report,Collected: Boolean;
begin
  P := nil; J := nil; Environment := nil; Frames := 0; Collected := False;
  try
    ParseMitigationTrialArguments(Mode,Report);
    SealApiPointerStorage; Authorized := False; TimedOut := False;
    Deadline := CozyTick + 15000;
    P := NewMitigationTrialSettings(Mode);
    Status := 1;
    try
    Status := RunOverlayUI(
      procedure
      begin
        Inc(Frames);
        PostMessage(HWND(OverlayTestWindow),WM_CLOSE,0,0);
      end,
      function: Boolean
      begin
        TimedOut := CozyTick >= Deadline;
        Result := TimedOut or not Authorized;
      end,
      nil,
      procedure
      begin
        CollectProcessMitigationsProfile(Mode,P,DynamicState,CfgState,O);
        Environment := CollectMitigationEnvironment('O');
        Collected := Environment <> nil;
        if not Collected or (Length(Environment.GetValue<string>(CozyText_OverlayMitigationProbe_gpuIdentitySha512_17c8574e,'')) <> 128) then
          raise Exception.Create(CozyText_OverlayMitigationProbe_GPU_IDENTITY_UNAVAILABLE_d152d451);
        if MitigationProfileReadback(P,O) <> CozyText_OverlayMitigationProbe_PASS_a51e1038 then
          raise Exception.Create(CozyText_OverlayMitigationProbe_MITIGATION_READBACK_FAILED_31f5245f);
        Authorized := True;
      end);
    except
      if not Report or not Collected then raise;
      { Preserve policy query/error observations even when hidden initialization
        or rendering rejects the selected combination. Never claim a frame. }
    end;
    RendererState := CozyText_OverlayMitigationProbe_FAIL_3b31819e;
    if (Status = 0) and not TimedOut and (Frames = 1) then RendererState := CozyText_OverlayMitigationProbe_PASS_a51e1038;
    if Report and Collected then
      J := NewMitigationTrialReport(P,Environment,O,'O',RendererState,Frames)
    else
    begin
      if (RendererState <> CozyText_OverlayMitigationProbe_PASS_a51e1038) or not Collected then
        raise Exception.Create(CozyText_OverlayMitigationProbe_MITIGATION_VISIBLE_FRAME_FAILED_128bb20e);
      J := O.ToJSON; J.AddPair(CozyText_OverlayMitigationProbe_environment_3d2a2ca8,TJSONObject(Environment.Clone));
      J.AddPair(CozyText_OverlayMitigationProbe_scope_392822fd,CozyText_OverlayMitigationProbe_REAL_RENDERER_POLICY_AND_VISIBLE_PRESENT_927155c2);
      J.AddPair(CozyText_OverlayMitigationProbe_visibleFrames_c77f3b54,TJSONNumber.Create(Frames));
    end;
    Writeln(J.ToJSON);
    if (RendererState = CozyText_OverlayMitigationProbe_PASS_a51e1038) and (MitigationProfileReadback(P,O) = CozyText_OverlayMitigationProbe_PASS_a51e1038) then
      Writeln(CozyText_OverlayMitigationProbe_PASS_real_D3D_renderer_under_selected_OS_policy_deaa2528)
    else begin Writeln(CozyText_OverlayMitigationProbe_FAIL_MITIGATION_COMPATIBILITY_0048d2b5); ExitCode := 1; end;
  except on E: Exception do begin Writeln(CozyText_OverlayMitigationProbe_FAIL_fac28b21,E.Message); ExitCode := 1; end; end;
  J.Free; Environment.Free; P.Free;
end.
