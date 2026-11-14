program Cozy_ProtocolSchemaProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
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
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$ENDIF}
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsProtocol in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsProtocol.pas',

  System.SysUtils, System.JSON, Cozy.Bootstrap, Cozy.Integrity, Cozy.Api.Pointer,
  Cozy.ProtocolJson;
const
  EmptySHA512 = CozyText_ProtocolSchemaProbe_Digest_05f9222b +
    CozyText_ProtocolSchemaProbe_Digest_425fb305;
  AbcSHA512 = CozyText_ProtocolSchemaProbe_Digest_699a6697 +
    CozyText_ProtocolSchemaProbe_Digest_a766c823;
  AbcSHA256 = CozyText_ProtocolSchemaProbe_Digest_69a30067;
{$I Cozy.ProtocolSchemaPolicyCases.inc}
procedure Check(Condition: Boolean; const MessageText: string);
begin
  if not Condition then raise Exception.Create(MessageText);
end;
procedure RejectHash(const Text: string);
var Rejected: Boolean;
begin
  Rejected := False;
  try
    BootstrapCheckSHA512(Text);
  except
    on E: EBootstrap do Rejected := True;
  end;
  Check(Rejected, CozyText_ProtocolSchemaProbe_Malformed_or_legacy_measurement_digest_accepted_f6c81761);
end;
procedure RunPolicyWireCases;
var I, MaximumBytes, AcceptedCount, RejectedCount: Integer;
  Parsed: TJSONObject; Accepted: Boolean;
begin
  AcceptedCount := 0; RejectedCount := 0;
  for I := Low(PolicyWireCases) to High(PolicyWireCases) do
  begin
    MaximumBytes := PolicyWireCases[I].MaximumBytes;
    if MaximumBytes = -1 then MaximumBytes := ProtocolRequestMaximumBytes;
    Parsed := nil; Accepted := False;
    try
      try
        Parsed := ParseProtocolRequest(PolicyWireCases[I].WireText, MaximumBytes);
        Accepted := True;
      except
        on E: EConvertError do begin end;
      end;
      Check(Accepted = PolicyWireCases[I].Accept,
        CozyText_ProtocolSchemaProbe_Policy_wire_boundary_mismatch_23f08e2e + PolicyWireCases[I].Name);
      if Accepted then Inc(AcceptedCount) else Inc(RejectedCount);
    finally
      Parsed.Free;
    end;
  end;
  Check((AcceptedCount = 43) and (RejectedCount = 75), CozyText_ProtocolSchemaProbe_Policy_fixture_coverage_changed_9ccc6914);
  Writeln(CozyText_ProtocolSchemaProbe_PASS_policy_request_schema_boundaries_43_accepte_f7f5c13a);
  Writeln(CozyText_ProtocolSchemaProbe_Shape_validation_is_separate_from_server_signatu_320a8579);
end;
var Bytes: TBytes; Invalid: string;
begin
  try
    SealApiPointerStorage;
    Bytes := nil;
    Check(IntegritySHA512Bytes(Bytes) = EmptySHA512, CozyText_ProtocolSchemaProbe_Native_CNG_SHA_512_empty_vector_failed_8dd03723);
    Check(IntegritySHA512Text(CozyText_ProtocolSchemaProbe_abc_47ac2fc6) = AbcSHA512, CozyText_ProtocolSchemaProbe_Native_CNG_SHA_512_abc_vector_failed_4131a44d);
    Check(IntegritySHA256Text(CozyText_ProtocolSchemaProbe_abc_47ac2fc6) = AbcSHA256, CozyText_ProtocolSchemaProbe_Stable_identity_SHA_256_compatibility_failed_fb9b415b);
    BootstrapCheckSHA512(AbcSHA512);
    RejectHash(AbcSHA256);
    RejectHash('');
    RejectHash(Copy(AbcSHA512, 1, 127));
    RejectHash(AbcSHA512 + '0');
    Invalid := AbcSHA512; Invalid[1] := 'g'; RejectHash(Invalid);
    Invalid := AbcSHA512; Invalid[1] := 'D'; RejectHash(Invalid);
    Check(Length(HashFileSHA512(ParamStr(0))) = 128, CozyText_ProtocolSchemaProbe_Full_file_SHA_512_width_is_invalid_8ac64bd8);
    Writeln(CozyText_ProtocolSchemaProbe_PASS_native_CNG_vectors_v3_digest_validation_ide_cd224218);
    RunPolicyWireCases;
    Writeln(CozyText_ProtocolSchemaProbe_No_server_connection_or_application_workflow_was_dcb08730);
  except
    on E: Exception do
    begin
      Writeln(CozyText_ProtocolSchemaProbe_FAIL_5c954936, E.ClassName, CozyText_ProtocolSchemaProbe_Text_eb6e295e, E.Message);
      ExitCode := 1;
    end;
  end;
end.
