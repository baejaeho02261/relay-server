program Cozy_ProcessMitigationProfileProbe;
{$APPTYPE CONSOLE}
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',
 System.SysUtils, System.JSON,
  Cozy.ProcessMitigations in '..\..\Cozy.Source\Cozy.Integrity\Cozy.ProcessMitigations.pas',
  Cozy.MitigationProbeSupport in 'Cozy.MitigationProbeSupport.pas';
var P, J, Environment: TJSONObject; O: TMitigationObservation;
  DynamicState, CfgState, Mode, Readback: string; Report: Boolean;
begin
  P := nil; J := nil; Environment := nil;
  try
    ParseMitigationTrialArguments(Mode,Report);
    P := NewMitigationTrialSettings(Mode);
    CollectProcessMitigationsProfile(Mode,P,DynamicState,CfgState,O);
    Readback := MitigationProfileReadback(P,O);
    Environment := CollectMitigationEnvironment('B');
    if Environment = nil then raise Exception.Create(CozyText_ProcessMitigationProfileProbe_MITIGATION_ENVIRONMENT_UNAVAILABLE_ad4fc4a5);
    if Report then J := NewMitigationTrialReport(P,Environment,O,CozyText_ProcessMitigationProfileProbe_AB_80d85eb8,CozyText_ProcessMitigationProfileProbe_NOT_RUN_f2ab8a47,0)
    else
    begin
      if Readback <> CozyText_ProcessMitigationProfileProbe_PASS_f81b1894 then raise Exception.Create(CozyText_ProcessMitigationProfileProbe_MITIGATION_READBACK_FAILED_d47a63a3);
      J := O.ToJSON;
      J.AddPair(CozyText_ProcessMitigationProfileProbe_environment_ba6d76ac,TJSONObject(Environment.Clone));
      J.AddPair(CozyText_ProcessMitigationProfileProbe_scope_ab3c211f,CozyText_ProcessMitigationProfileProbe_NATIVE_POLICY_READBACK_NOT_GRAPHICS_COMPATIBILIT_36b89a7a);
    end;
    Writeln(J.ToJSON);
    if Readback = CozyText_ProcessMitigationProfileProbe_PASS_f81b1894 then Writeln(CozyText_ProcessMitigationProfileProbe_PASS_process_profile_actual_policy_readback_8e977ff7)
    else begin Writeln(CozyText_ProcessMitigationProfileProbe_FAIL_MITIGATION_READBACK_ab85dbc6,Readback); ExitCode := 1; end;
  except on E: Exception do begin Writeln(CozyText_ProcessMitigationProfileProbe_FAIL_641cfa14,E.Message); ExitCode := 1; end; end;
  J.Free; Environment.Free; P.Free;
end.
