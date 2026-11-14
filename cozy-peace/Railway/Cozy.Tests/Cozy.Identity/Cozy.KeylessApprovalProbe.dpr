program Cozy_KeylessApprovalProbe;
{$APPTYPE CONSOLE}
{$RANGECHECKS ON}
{$OVERFLOWCHECKS ON}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  System.SysUtils, System.JSON,
  Cozy.KeylessBootstrap in '..\..\Cozy.Source\Cozy.Application\Cozy.KeylessBootstrap.pas';
var Checks: Integer;
procedure Check(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(CozyText_KeylessApprovalProbe_FAIL_ba6208e5 + Name);
  Inc(Checks);
end;
procedure Reject(const Code, Name: string; const Action: TProc);
var Rejected: Boolean;
begin
  Rejected := False;
  try Action();
  except on E: Exception do Rejected := E.Message = Code; end;
  Check(Rejected, Name);
end;
function Decision(const Challenge, Status: string; Expiry: Int64;
  Hint: TJSONValue): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair(CozyText_KeylessApprovalProbe_version_d822a155, TJSONNumber.Create(1));
  Result.AddPair(CozyText_KeylessApprovalProbe_challengeId_a63c1730, Challenge);
  Result.AddPair(CozyText_KeylessApprovalProbe_expiresAt_75b3a216, TJSONNumber.Create(Expiry));
  Result.AddPair(CozyText_KeylessApprovalProbe_status_2ff7f48a, Status);
  if Hint <> nil then Result.AddPair(CozyText_KeylessApprovalProbe_pollAfterMs_ffeb08ad, Hint);
end;
procedure Run;
var Reply: TJSONObject; Delay: Cardinal; Status, Expected, Changed: string;
  Fields: TArray<string>; I: Integer;

begin
  Checks := 0;
  Check(KeylessApprovalRemaining(0, False) = 10000, CozyText_KeylessApprovalProbe_per_request_ceiling_e3891fb7);
  Check(KeylessApprovalRemaining(299999, False) = 1, CozyText_KeylessApprovalProbe_no_renewed_total_budget_d5d82bc5);
  Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_APPROVAL_EXPIRED_bc8d4138, CozyText_KeylessApprovalProbe_expired_total_budget_7b26049b,
    procedure begin KeylessApprovalRemaining(300000, False); end);
  Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_APPROVAL_EXPIRED_bc8d4138, CozyText_KeylessApprovalProbe_negative_monotonic_elapsed_rejected_260641d1,
    procedure begin KeylessApprovalRemaining(-1, False); end);
  Reject(CozyText_KeylessApprovalProbe_CONNECT_CANCELLED_fb5610b8, CozyText_KeylessApprovalProbe_cancel_before_network_85bc2a39,
    procedure begin KeylessApprovalRemaining(1, True); end);
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, CozyText_KeylessApprovalProbe_PENDING_APPROVAL_e39b9a0f, 123456789, nil);
  try
    Status := ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay);Check((Status = CozyText_KeylessApprovalProbe_PENDING_APPROVAL_e39b9a0f) and (Delay = 2000), CozyText_KeylessApprovalProbe_compatible_default_hint_12d6f746);
  finally Reply.Free; end;
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, CozyText_KeylessApprovalProbe_APPROVED_ce60ab10, 123456789, TJSONNumber.Create(2001));
  try
    Status := ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay);Check((Status = CozyText_KeylessApprovalProbe_APPROVED_ce60ab10) and (Delay = 2001), CozyText_KeylessApprovalProbe_bounded_server_jitter_retained_4320a414);
    Reject(CozyText_KeylessApprovalProbe_CONNECT_CANCELLED_fb5610b8, CozyText_KeylessApprovalProbe_late_approved_after_cancellation_af5e4098, procedure begin ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, True, Delay); end);
    Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_APPROVAL_EXPIRED_bc8d4138, CozyText_KeylessApprovalProbe_late_approved_after_total_expiry_ce6ffc43, procedure begin ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 300000, False, Delay); end);
  finally Reply.Free; end;
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_two_87c67cc8, CozyText_KeylessApprovalProbe_APPROVED_ce60ab10, 123456789, nil);
  try
    Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_RESPONSE_INVALID_95ee6b6e, CozyText_KeylessApprovalProbe_other_issued_A_challenge_25f5d676, procedure begin ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay); end);
  finally Reply.Free; end;
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, CozyText_KeylessApprovalProbe_APPROVED_ce60ab10, 123456790, nil);
  try
    Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_RESPONSE_INVALID_95ee6b6e, CozyText_KeylessApprovalProbe_expiry_substitution_165f350c, procedure begin ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay); end);
  finally Reply.Free; end;
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, CozyText_KeylessApprovalProbe_CONSUMED_dac16133, 123456789, nil);
  try
    Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_APPROVAL_REJECTED_ec601674, CozyText_KeylessApprovalProbe_consumed_approval_response_7e1f95ac, procedure begin ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay); end);
  finally Reply.Free; end;
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, CozyText_KeylessApprovalProbe_PENDING_APPROVAL_e39b9a0f, 123456789, TJSONNumber.Create(0));
  try ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay);Check(Delay = 1000, CozyText_KeylessApprovalProbe_hint_minimum_37f3d884);finally Reply.Free;end;
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, CozyText_KeylessApprovalProbe_PENDING_APPROVAL_e39b9a0f, 123456789, TJSONNumber.Create(Int64(9007199254740991)));
  try ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay);Check(Delay = 5000, CozyText_KeylessApprovalProbe_hint_maximum_without_overflow_5886a496);finally Reply.Free;end;
  Reply := Decision(CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, CozyText_KeylessApprovalProbe_PENDING_APPROVAL_e39b9a0f, 123456789, TJSONString.Create(CozyText_KeylessApprovalProbe_2000_af9042b8));
  try
    Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_RESPONSE_INVALID_95ee6b6e, CozyText_KeylessApprovalProbe_invalid_hint_type_41b76263, procedure begin ValidateKeylessDecision(Reply, CozyText_KeylessApprovalProbe_issued_A_challenge_one_8ac95730, 123456789, 10, False, Delay); end);
  finally Reply.Free; end;
  Fields := TArray<string>.Create(CozyText_KeylessApprovalProbe_COZY_KEYLESS_BOOTSTRAP_V1_b7af7cf3, CozyText_KeylessApprovalProbe_challenge_55ed0611, CozyText_KeylessApprovalProbe_nonce_fa3f7533,
    CozyText_KeylessApprovalProbe_request_848cf541, CozyText_KeylessApprovalProbe_issued_A_efc4fd25, CozyText_KeylessApprovalProbe_file_sha512_0c21b684, CozyText_KeylessApprovalProbe_file_crc64_682fb2a0, CozyText_KeylessApprovalProbe_code_sha512_db87a686, CozyText_KeylessApprovalProbe_code_crc64_844cc5e7,
    CozyText_KeylessApprovalProbe_machine_a311a4e6, CozyText_KeylessApprovalProbe_application_key_dabff63c, CozyText_KeylessApprovalProbe_persistent_key_40794cd6, CozyText_KeylessApprovalProbe_provider_6f42003f, CozyText_KeylessApprovalProbe_epoch_9fddb2a8, CozyText_KeylessApprovalProbe_revision_94b794bb, CozyText_KeylessApprovalProbe_expiry_7371a3a6);
  Expected := string.Join(#10, Fields);
  ValidateKeylessBinding(Expected, Expected);Check(True, CozyText_KeylessApprovalProbe_exact_canonical_19014d81);
  for I := 1 to High(Fields) do
  begin
    Fields[I] := Fields[I] + CozyText_KeylessApprovalProbe_other_acaa437e;Changed := string.Join(#10, Fields);
    Reject(CozyText_KeylessApprovalProbe_COZY_KEYLESS_BINDING_INVALID_f114cf98, CozyText_KeylessApprovalProbe_canonical_substitution_1b0304b2 + IntToStr(I),
      procedure begin ValidateKeylessBinding(Changed, Expected); end);
    Delete(Fields[I], Length(Fields[I]) - 5, 6);
  end;

end;
begin
  try
    Run;
    Writeln(CozyText_KeylessApprovalProbe_KEYLESS_APPROVAL_PROBE_PASS_ae57399b, Checks);
    Writeln(CozyText_KeylessApprovalProbe_Decision_and_canonical_guards_only_no_device_enr_304ed464);
  except on E: Exception do
    begin Writeln(E.ClassName + CozyText_KeylessApprovalProbe_Text_a2be73f3 + E.Message);ExitCode := 1;end;
  end;
end.
