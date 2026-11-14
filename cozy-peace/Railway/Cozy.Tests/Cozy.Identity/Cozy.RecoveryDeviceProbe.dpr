program Cozy_RecoveryDeviceProbe;
{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$B-}
{$IFNDEF GAME_RECOVERY_DEVICE_PROBE}
  {$MESSAGE FATAL 'Cozy.RecoveryDeviceProbe requires its isolated test define.'}
{$ENDIF}
{$IFDEF GAME_APPLICATION_BUILD}
  {$MESSAGE FATAL 'Cozy.RecoveryDeviceProbe must never be linked into A/B/O.'}
{$ENDIF}

uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils, System.JSON, Cozy.ProtocolJson, Cozy.Security,
  Cozy.DeviceKey, Cozy.Api.Pointer;

{ A single private pipe owns the CNG handles, including the ephemeral AIK used
  by the real production TPM certify/activate exchange. No private key bytes
  are serialized. Original keys are opened only; replacement keys are created
  exclusively in the namespace provided by an isolated restored server. }

var
  CurrentRequest: Integer;
  CleanupStatus: string;

procedure Fail(const Code: string);
begin
  raise EInvalidOpException.Create(Code);
end;

function InputObject: TJSONObject;
var Line: string; C: Char; Complete: Boolean;
begin
  Complete := False;
  try
    while not System.Eof(System.Input) do
    begin
      Read(System.Input, C);
      if C = #10 then begin Complete := True; Break; end;
      if C = #13 then Continue;
      if (Ord(C) < 32) or (Ord(C) > 126) or (Length(Line) >= 32768) then
        Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_INPUT_LIMIT_e07010d8);
      Line := Line + C;
    end;
    if not Complete or (Line = '') then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_PIPE_CLOSED_27d4b178);
    Result := ParseProtocolObject(Line, 32768);
  finally WipeText(Line); end;
end;

function Text(Obj: TJSONObject; const Name: string; Maximum: Integer): string;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name);
  if not (V is TJSONString) then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_INPUT_INVALID_8efb55bc);
  Result := V.Value;
  if (Length(Result) = 0) or (Length(Result) > Maximum) then
    Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_INPUT_INVALID_8efb55bc);
end;

function Number(Obj: TJSONObject; const Name: string): Integer;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name);
  if not (V is TJSONNumber) or not TryStrToInt(V.Value, Result) then
    Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_INPUT_INVALID_8efb55bc);
end;

procedure Fields(Obj: TJSONObject; const Extra: array of string);
var I, J: Integer; Name: string; Found: Boolean;
begin
  for I := 0 to Obj.Count - 1 do
  begin
    Name := Obj.Pairs[I].JsonString.Value;
    Found := (Name = CozyText_RecoveryDeviceProbe_version_d2c26597) or (Name = CozyText_RecoveryDeviceProbe_command_fc6c3472) or (Name = CozyText_RecoveryDeviceProbe_requestId_f6fe5747);
    for J := Low(Extra) to High(Extra) do Found := Found or (Name = Extra[J]);
    if not Found then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_FIELD_INVALID_655747b2);
  end;
end;

procedure Hex(const Value: string; Size: Integer);
var C: Char;
begin
  if Length(Value) <> Size then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_INPUT_INVALID_8efb55bc);
  for C in Value do
    if not CharInSet(C, ['0'..'9', 'a'..'f']) then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_INPUT_INVALID_8efb55bc);
end;

procedure Output(Obj: TJSONObject);
var Encoded: string;
begin
  try
    Encoded := Obj.ToJSON;
    Writeln(Encoded);
    Flush(System.Output);
  finally WipeText(Encoded); end;
end;

procedure DescribeKey(Answer: TJSONObject; Key: TPersistentDeviceKey;
  const Provider, Namespace: string);
var PublicKey: string;
begin
  try
    if not Key.ProbePrivateExportBlocked then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_PRIVATE_EXPORT_ALLOWED_a6f5264a);
    PublicKey := Key.PublicKey;
    Answer.AddPair(CozyText_RecoveryDeviceProbe_publicKey_19f41909, PublicKey);
    Answer.AddPair(CozyText_RecoveryDeviceProbe_keyId_292c4df2, DevicePublicKeyID(PublicKey));
    Answer.AddPair(CozyText_RecoveryDeviceProbe_provider_9c1b872a, Provider);
    Answer.AddPair(CozyText_RecoveryDeviceProbe_namespace_9e159f44, Namespace);
    Answer.AddPair(CozyText_RecoveryDeviceProbe_providerImplementation_c72617f8, TJSONNumber.Create(Int64(Key.RecoveryProviderImplementation)));
    Answer.AddPair(CozyText_RecoveryDeviceProbe_privateExportBlocked_6c863783, TJSONTrue.Create);
    Answer.AddPair(CozyText_RecoveryDeviceProbe_hardwareAttested_b87b642b, TJSONFalse.Create);
  finally WipeText(PublicKey); end;
end;

procedure RequireCanonical(const Canonical, RunID: string);
var C: Char; Domain: string; Split: Integer;
begin
  for C in Canonical do
    if ((Ord(C) < 32) and (C <> #10)) or (Ord(C) > 126) then
      Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_CANONICAL_INVALID_295c8611);
  Split := Pos(#10, Canonical);
  if Split <= 1 then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_DOMAIN_INVALID_bc08afce);
  Domain := Copy(Canonical, 1, Split - 1);
  if (Domain <> CozyText_RecoveryDeviceProbe_GAME_DEVICE_IDENTITY_V2_9160c5b0) and
    (Domain <> CozyText_RecoveryDeviceProbe_GAME_DEVICE_ACTIVATION_V2_92de6b81) and
    (Domain <> CozyText_RecoveryDeviceProbe_GAME_RECOVERY_DRILL_ORIGINAL_V1_4f77860a) then
    Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_DOMAIN_INVALID_bc08afce);
  if (Domain = CozyText_RecoveryDeviceProbe_GAME_RECOVERY_DRILL_ORIGINAL_V1_4f77860a) and
    (Copy(Canonical, 1, Length(Domain) + Length(RunID) + 2) <>
      Domain + #10 + RunID + #10) then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_RUN_BINDING_INVALID_d93f0ec3);
end;

procedure Run;
var
  Request, Answer: TJSONObject;
  Original, Replacement, Key, Reopened: TPersistentDeviceKey;
  Command, OriginalNamespace, ReplacementNamespace, ExpectedPublicKey,
    Provider, RunID, Canonical, Nonce, Activation, Secret: string;
  Platform, Initialized, CreatedReplacement, DeletedReplacement, Closing: Boolean;
  Count: Integer;
begin
  Request := nil; Answer := nil; Original := nil; Replacement := nil; Reopened := nil;
  Platform := False; Initialized := False; CreatedReplacement := False;
  DeletedReplacement := False; Closing := False; Count := 0;
  try
    while not Closing do
    begin
      Inc(Count);
      if Count > 256 then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_COMMAND_LIMIT_e95310c3);
      Request := InputObject;
      if (Number(Request, CozyText_RecoveryDeviceProbe_version_d2c26597) <> 1) or
        (Number(Request, CozyText_RecoveryDeviceProbe_requestId_f6fe5747) <> Count) then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_REQUEST_ORDER_e019f10e);
      CurrentRequest := Count;
      Command := Text(Request, CozyText_RecoveryDeviceProbe_command_fc6c3472, 40);
      Answer := TJSONObject.Create;
      Answer.AddPair(CozyText_RecoveryDeviceProbe_version_d2c26597, TJSONNumber.Create(1));
      Answer.AddPair(CozyText_RecoveryDeviceProbe_requestId_f6fe5747, TJSONNumber.Create(Count));
      Answer.AddPair(CozyText_RecoveryDeviceProbe_ok_d2930d7d, TJSONTrue.Create);
      if Command = CozyText_RecoveryDeviceProbe_init_31dbd2da then
      begin
        Fields(Request, [CozyText_RecoveryDeviceProbe_namespace_9e159f44, CozyText_RecoveryDeviceProbe_provider_9c1b872a, CozyText_RecoveryDeviceProbe_expectedPublicKey_41915c28, CozyText_RecoveryDeviceProbe_runId_7c7b879b]);
        if Initialized or (Count <> 1) then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_ALREADY_INITIALIZED_8a7dfddc);
        OriginalNamespace := Text(Request, CozyText_RecoveryDeviceProbe_namespace_9e159f44, 64); Hex(OriginalNamespace, 64);
        RunID := Text(Request, CozyText_RecoveryDeviceProbe_runId_7c7b879b, 32); Hex(RunID, 32);
        Provider := Text(Request, CozyText_RecoveryDeviceProbe_provider_9c1b872a, 16);
        if (Provider <> CozyText_RecoveryDeviceProbe_SOFTWARE_7b07a827) and (Provider <> CozyText_RecoveryDeviceProbe_PLATFORM_1fd15a0b) then
          Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_PROVIDER_INVALID_cb8c502f);
        Platform := Provider = CozyText_RecoveryDeviceProbe_PLATFORM_1fd15a0b;
        ExpectedPublicKey := Text(Request, CozyText_RecoveryDeviceProbe_expectedPublicKey_41915c28, 512);
        DevicePublicKeyID(ExpectedPublicKey);
        Original := TPersistentDeviceKey.OpenRecoveryProbe(OriginalNamespace, Platform, False);
        if Original.PublicKey <> ExpectedPublicKey then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_ORIGINAL_KEY_MISMATCH_d7f90c3f);
        Initialized := True;
        DescribeKey(Answer, Original, Provider, OriginalNamespace);
        Answer.AddPair(CozyText_RecoveryDeviceProbe_created_2f9c5d57, TJSONFalse.Create);
        Answer.AddPair(CozyText_RecoveryDeviceProbe_originalKeyDeleted_0d2744a3, TJSONFalse.Create);
      end
      else
      begin
        if not Initialized then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_INIT_REQUIRED_94e62581);
        if Command = CozyText_RecoveryDeviceProbe_create_replacement_2ed7feeb then
        begin
          Fields(Request, [CozyText_RecoveryDeviceProbe_namespace_9e159f44]);
          if CreatedReplacement then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_REPLACEMENT_ALREADY_CREATED_ae72e8a4);
          ReplacementNamespace := Text(Request, CozyText_RecoveryDeviceProbe_namespace_9e159f44, 64); Hex(ReplacementNamespace, 64);
          if ReplacementNamespace = OriginalNamespace then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_ORIGINAL_NAMESPACE_REFUSED_2a560b53);
          CleanupStatus := CozyText_RecoveryDeviceProbe_CONSTRUCTION_FAILED_UNKNOWN_dfadd250;
          Replacement := TPersistentDeviceKey.OpenRecoveryProbe(ReplacementNamespace, Platform, True);
          CreatedReplacement := True; CleanupStatus := CozyText_RecoveryDeviceProbe_PENDING_72a6d859;
          if Replacement.PublicKey = ExpectedPublicKey then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_REPLACEMENT_KEY_NOT_DISTINCT_7b7221cf);
          DescribeKey(Answer, Replacement, Provider, ReplacementNamespace);
          Answer.AddPair(CozyText_RecoveryDeviceProbe_created_2f9c5d57, TJSONTrue.Create);
        end
        else if (Command = CozyText_RecoveryDeviceProbe_delete_replacement_c99d231e) or (Command = CozyText_RecoveryDeviceProbe_close_c554d40b) then
        begin
          Fields(Request, []);
          if Replacement <> nil then
          begin
            Replacement.DeleteRecoveryProbeKey;
            DeletedReplacement := True; CleanupStatus := CozyText_RecoveryDeviceProbe_DELETED_ff26c48c;
            FreeAndNil(Replacement);
          end
          else if (Command = CozyText_RecoveryDeviceProbe_delete_replacement_c99d231e) and not DeletedReplacement then
            Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_REPLACEMENT_REQUIRED_20e1a073);
          Answer.AddPair(CozyText_RecoveryDeviceProbe_deleted_465b05c8, TJSONBool.Create(DeletedReplacement));
          Answer.AddPair(CozyText_RecoveryDeviceProbe_replacementCreated_3246ca4b, TJSONBool.Create(CreatedReplacement));
          Answer.AddPair(CozyText_RecoveryDeviceProbe_replacementDeleted_44b597c0, TJSONBool.Create(DeletedReplacement));
          Answer.AddPair(CozyText_RecoveryDeviceProbe_originalKeyDeleted_0d2744a3, TJSONFalse.Create);
          if Command = CozyText_RecoveryDeviceProbe_close_c554d40b then
          begin
            Reopened := TPersistentDeviceKey.OpenRecoveryProbe(OriginalNamespace, Platform, False);
            if Reopened.PublicKey <> ExpectedPublicKey then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_ORIGINAL_KEY_MISMATCH_d7f90c3f);
            FreeAndNil(Reopened);
            Answer.AddPair(CozyText_RecoveryDeviceProbe_originalKeyStillPresent_90c68bc1, TJSONTrue.Create);
            Closing := True;
          end;
        end
        else
        begin
          if (Command = CozyText_RecoveryDeviceProbe_sign_original_d607a234) or (Command = CozyText_RecoveryDeviceProbe_evidence_original_517361ef) or
            (Command = CozyText_RecoveryDeviceProbe_activate_original_5253a2d8) then Key := Original
          else if (Command = CozyText_RecoveryDeviceProbe_sign_replacement_1e982d43) or (Command = CozyText_RecoveryDeviceProbe_evidence_replacement_8c84ea43) or
            (Command = CozyText_RecoveryDeviceProbe_activate_replacement_f01aafd4) then Key := Replacement
          else begin Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_COMMAND_INVALID_e9d776ac); Key := nil; end;
          if Key = nil then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_REPLACEMENT_REQUIRED_20e1a073);
          if Copy(Command, 1, 5) = CozyText_RecoveryDeviceProbe_sign_7a213811 then
          begin
            Fields(Request, [CozyText_RecoveryDeviceProbe_canonical_e008d353]); Canonical := Text(Request, CozyText_RecoveryDeviceProbe_canonical_e008d353, 16384);
            RequireCanonical(Canonical, RunID);
            Answer.AddPair(CozyText_RecoveryDeviceProbe_signature_3bea9931, Key.Sign(Canonical));
          end
          else if Copy(Command, 1, 9) = CozyText_RecoveryDeviceProbe_evidence_0e0fb37e then
          begin
            Fields(Request, [CozyText_RecoveryDeviceProbe_nonce_4adb5617]); Nonce := Text(Request, CozyText_RecoveryDeviceProbe_nonce_4adb5617, 64);
            Answer.AddPair(CozyText_RecoveryDeviceProbe_evidence_dff2a5b4, Key.CreateEvidence(Nonce));
          end
          else
          begin
            Fields(Request, [CozyText_RecoveryDeviceProbe_activationBlob_7e956180]); Activation := Text(Request, CozyText_RecoveryDeviceProbe_activationBlob_7e956180, 4096);
            Secret := Key.Activate(Activation);
            Answer.AddPair(CozyText_RecoveryDeviceProbe_secret_7b4d4352, Secret);
          end;
        end;
      end;
      Output(Answer); FreeAndNil(Answer); FreeAndNil(Request);
      WipeText(Canonical); WipeText(Nonce); WipeText(Activation); WipeText(Secret);
    end;
  finally
    if Replacement <> nil then
      try Replacement.DeleteRecoveryProbeKey; CleanupStatus := CozyText_RecoveryDeviceProbe_DELETED_ff26c48c;
      except CleanupStatus := CozyText_RecoveryDeviceProbe_FAILED_978863ae; end;
    Reopened.Free; Replacement.Free; Original.Free; Answer.Free; Request.Free;
    WipeText(OriginalNamespace); WipeText(ReplacementNamespace); WipeText(ExpectedPublicKey);
    WipeText(Provider); WipeText(RunID); WipeText(Command); WipeText(Canonical);
    WipeText(Nonce); WipeText(Activation); WipeText(Secret);
  end;
end;

function SafeError(const MessageText: string): string;
var C: Char;
begin
  Result := UpperCase(MessageText);
  if (Length(Result) = 0) or (Length(Result) > 128) then Exit(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_FAILED_e32b3597);
  for C in Result do if not CharInSet(C, ['A'..'Z', '0'..'9', '_']) then
    Exit(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_FAILED_e32b3597);
end;

var Error: TJSONObject;
begin
  CurrentRequest := 0; CleanupStatus := CozyText_RecoveryDeviceProbe_NOT_CREATED_ef2d6115; Error := nil;
  try
    if ParamCount <> 0 then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_STDIN_ONLY_cd31f0a8);
    SealApiPointerStorage;
    if not ApiPointerStorageIsSealed then Fail(CozyText_RecoveryDeviceProbe_RECOVERY_PROBE_API_STORAGE_UNSEALED_18dab085);
    Run;
  except
    on E: Exception do
    begin
      Error := TJSONObject.Create;
      try
        Error.AddPair(CozyText_RecoveryDeviceProbe_version_d2c26597, TJSONNumber.Create(1));
        Error.AddPair(CozyText_RecoveryDeviceProbe_requestId_f6fe5747, TJSONNumber.Create(CurrentRequest));
        Error.AddPair(CozyText_RecoveryDeviceProbe_ok_d2930d7d, TJSONFalse.Create);
        Error.AddPair(CozyText_RecoveryDeviceProbe_error_fba7b57d, SafeError(E.Message));
        Error.AddPair(CozyText_RecoveryDeviceProbe_originalKeyDeleted_0d2744a3, TJSONFalse.Create);
        Error.AddPair(CozyText_RecoveryDeviceProbe_replacementCleanup_de788ede, CleanupStatus);
        Output(Error);
      finally Error.Free; end;
      ExitCode := 1;
    end;
  end;
end.
