unit Cozy.MitigationProbeSupport;
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.TestsSecurity,
 System.JSON, System.Generics.Collections, Cozy.ProcessMitigations;
function NewMitigationTrialSettings(const Mode: string): TJSONObject;
function NewMitigationTrialReport(Settings, Environment: TJSONObject;
  const Observation: TMitigationObservation; const ComponentScope,
  Renderer: string; VisibleFrames: Integer): TJSONObject;
procedure ParseMitigationTrialArguments(out Mode: string; out Report: Boolean);
implementation
uses System.SysUtils;
procedure ParseMitigationTrialArguments(out Mode: string; out Report: Boolean);
var I: Integer; SeenMode: Boolean;
begin
  Mode := CozyText_MitigationProbeSupport_observe_79eadc49; Report := False; SeenMode := False;
  for I := 1 to ParamCount do
    if (ParamStr(I) = CozyText_MitigationProbeSupport_prohibit_a541a1b9) and not SeenMode then
    begin Mode := CozyText_MitigationProbeSupport_prohibit_36748160; SeenMode := True; end
    else if (ParamStr(I) = CozyText_MitigationProbeSupport_report_e8d0c17f) and not Report then Report := True
    else raise EArgumentException.Create(CozyText_MitigationProbeSupport_INVALID_ARGUMENT_0de5a79e);
end;
function NewMitigationTrialSettings(const Mode: string): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair(CozyText_MitigationProbeSupport_version_fd48f73c, TJSONNumber.Create(1));
    Result.AddPair(CozyText_MitigationProbeSupport_id_fca860f8, StringOfChar('a',128));
    Result.AddPair(CozyText_MitigationProbeSupport_dynamicCode_014a8fa3, Mode);
    Result.AddPair(CozyText_MitigationProbeSupport_strictHandles_31ff1275, TJSONBool.Create(True));
    Result.AddPair(CozyText_MitigationProbeSupport_imageLoadMask_3bea60bc, TJSONNumber.Create(3));
    Result.AddPair(CozyText_MitigationProbeSupport_requireCfg_4b636df0, TJSONBool.Create(False));
  except Result.Free; raise; end;
end;
function NewMitigationTrialReport(Settings, Environment: TJSONObject;
  const Observation: TMitigationObservation; const ComponentScope,
  Renderer: string; VisibleFrames: Integer): TJSONObject;
var CopySettings: TJSONObject;
begin
  if (Environment = nil) or ((ComponentScope <> CozyText_MitigationProbeSupport_AB_4603c932) and (ComponentScope <> 'O')) then
    raise EArgumentException.Create(CozyText_MitigationProbeSupport_MITIGATION_ENVIRONMENT_UNAVAILABLE_44542239);
  Result := TJSONObject.Create;
  try
    Result.AddPair(CozyText_MitigationProbeSupport_version_fd48f73c, TJSONNumber.Create(1));
    Result.AddPair(CozyText_MitigationProbeSupport_kind_f6e1ea91, CozyText_MitigationProbeSupport_NATIVE_MITIGATION_OBSERVATION_bd50a831);
    Result.AddPair(CozyText_MitigationProbeSupport_componentScope_0d3a3999, ComponentScope);
    Result.AddPair(CozyText_MitigationProbeSupport_environment_127c268e, TJSONObject(Environment.Clone));
    CopySettings := TJSONObject.Create;
    Result.AddPair(CozyText_MitigationProbeSupport_settings_12ec0d77, CopySettings);
    CopySettings.AddPair(CozyText_MitigationProbeSupport_dynamicCode_014a8fa3, Settings.GetValue<string>(CozyText_MitigationProbeSupport_dynamicCode_014a8fa3,''));
    CopySettings.AddPair(CozyText_MitigationProbeSupport_strictHandles_31ff1275, TJSONBool.Create(True));
    CopySettings.AddPair(CozyText_MitigationProbeSupport_imageLoadMask_3bea60bc, TJSONNumber.Create(3));
    CopySettings.AddPair(CozyText_MitigationProbeSupport_requireCfg_4b636df0, TJSONBool.Create(False));
    Result.AddPair(CozyText_MitigationProbeSupport_observation_d8253779, Observation.ToJSON);
    Result.AddPair(CozyText_MitigationProbeSupport_policyReadback_d0e1a437, MitigationProfileReadback(Settings,Observation));
    Result.AddPair(CozyText_MitigationProbeSupport_renderer_22329632, Renderer);
    Result.AddPair(CozyText_MitigationProbeSupport_visibleFrames_76518971, TJSONNumber.Create(VisibleFrames));
    if ComponentScope = 'O' then Result.AddPair(CozyText_MitigationProbeSupport_scope_6bc7ce98, CozyText_MitigationProbeSupport_REAL_RENDERER_POLICY_AND_VISIBLE_PRESENT_b6e09a38)
    else Result.AddPair(CozyText_MitigationProbeSupport_scope_6bc7ce98, CozyText_MitigationProbeSupport_NATIVE_POLICY_READBACK_NOT_PRODUCT_WORKFLOW_597f7b4e);
  except Result.Free; raise; end;
end;
end.
