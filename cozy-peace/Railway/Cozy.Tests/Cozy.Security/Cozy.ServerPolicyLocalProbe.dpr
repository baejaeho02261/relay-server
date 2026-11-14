program Cozy_ServerPolicyLocalProbe;
{$APPTYPE CONSOLE}
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',

  System.SysUtils, System.JSON, Cozy.Api.Pointer, Cozy.Platform.ExportResolver, Cozy.ProcessMitigations;
var DynamicState, CfgState, Mode: string; Rejected: Boolean;
  Observation: TMitigationObservation; Obj: TJSONObject;
begin
  try
    Mode := CozyText_ServerPolicyLocalProbe_observe_2b198880;
    if ParamCount > 0 then
    begin
      if (ParamCount <> 1) or (ParamStr(1) <> CozyText_ServerPolicyLocalProbe_prohibit_3a85d63b) then
        raise EArgumentException.Create(CozyText_ServerPolicyLocalProbe_Only_prohibit_is_accepted_default_is_observe_7065a0a9);
      Mode := CozyText_ServerPolicyLocalProbe_prohibit_5a02b784;
    end;
    SealApiPointerStorage;
    if not ApiPointerStorageIsSealed then
      raise EInvalidOpException.Create(CozyText_ServerPolicyLocalProbe_API_arena_is_not_read_only_b933bf4e);
    Rejected := False;
    try
      CollectProcessMitigations(CozyText_ServerPolicyLocalProbe_invalid_mode_97a9d86b, DynamicState, CfgState);
    except
      on E: EArgumentException do Rejected := True;
    end;
    if not Rejected then raise EInvalidOpException.Create(CozyText_ServerPolicyLocalProbe_Unknown_mitigation_mode_was_accepted_3c7003a8);
    CollectProcessMitigations(Mode, DynamicState, CfgState, Observation);
    Obj := Observation.ToJSON;
    try WriteLn(CozyText_ServerPolicyLocalProbe_MITIGATION_OBSERVATION_92bf3d22, Obj.ToJSON); finally Obj.Free; end;
    Writeln(CozyText_ServerPolicyLocalProbe_API_SLOTS_d23639c7, ApiPointerStorageCount);
    Writeln(CozyText_ServerPolicyLocalProbe_API_STORAGE_READ_ONLY_3fc5dc9f);
    Writeln(CozyText_ServerPolicyLocalProbe_DYNAMIC_CODE_64ed89cb, DynamicState);
    Writeln(CozyText_ServerPolicyLocalProbe_CFG_941c4260, CfgState);
    if (Mode = CozyText_ServerPolicyLocalProbe_prohibit_5a02b784) and (DynamicState <> CozyText_ServerPolicyLocalProbe_PROHIBITED_84db45ad) then
      raise EInvalidOpException.Create(CozyText_ServerPolicyLocalProbe_Opt_in_dynamic_code_restriction_was_not_establis_d34623db);
    Writeln(CozyText_ServerPolicyLocalProbe_No_server_connection_or_application_workflow_was_c1ff7780);
  except
    on E: Exception do
    begin
      Writeln(CozyText_ServerPolicyLocalProbe_FAIL_362def22, E.ClassName, CozyText_ServerPolicyLocalProbe_Text_85a71ebc, E.Message);
      ExitCode := 1;
    end;
  end;
end.
