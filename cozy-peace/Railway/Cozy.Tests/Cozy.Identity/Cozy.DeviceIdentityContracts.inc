{ Test-only calls into the same guard and request-owner code used by A/B/O.
  No TPM/provider/key creation occurs in --contracts mode. Hardware success
  still requires the original interactive probe and an actual Windows TPM. }
procedure RunDeviceIdentityContracts;
var Checks, CaseID: Integer; P, C, A, E: TJSONObject;
  Policy: TDeviceIdentityPolicy; Challenge: TDeviceIdentityChallenge;
  SessionSecret, ActivationSecret: TCozySecret; Request: TDeviceIdentityRequest;
  Failed: Boolean; Ignored: Cardinal; Value: TJSONObject;
const
  AppContext = CozyText_DeviceIdentityContracts_B_0123456789ABCDEF01234567_APP_KEY_2129d116;
  KeyID = CozyText_DeviceIdentityContracts_Digest_8c968359;
  LowerID = CozyText_DeviceIdentityContracts_Digest_8ea18dfe;
  Nonce = CozyText_DeviceIdentityContracts_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_c31594ba;
  ChallengeID = CozyText_DeviceIdentityContracts_native_contract_challenge_b93592d9;
  Expires = 1800000000000;
  procedure Check(Condition: Boolean; const LabelText: string);
  begin
    if not Condition then raise EInvalidOpException.Create(CozyText_DeviceIdentityContracts_IDENTITY_CONTRACT_ebb12c79+LabelText);
    Inc(Checks);
  end;
  procedure Put(Obj: TJSONObject; const Name: string; V: TJSONValue);
  var Pair: TJSONPair;
  begin Pair := Obj.RemovePair(Name); Pair.Free; Obj.AddPair(Name,V); end;
  procedure S(Obj: TJSONObject; const Name, V: string);
  begin Put(Obj,Name,TJSONString.Create(V)); end;
  procedure N(Obj: TJSONObject; const Name: string; V: Int64);
  begin Put(Obj,Name,TJSONNumber.Create(V)); end;
  procedure B(Obj: TJSONObject; const Name: string; V: Boolean);
  begin Put(Obj,Name,TJSONBool.Create(V)); end;
  procedure Reset(Platform: Boolean);
  var Mode: string;
  begin
    FreeAndNil(P);FreeAndNil(C);FreeAndNil(A);FreeAndNil(E);
    if Platform then Mode := CozyText_DeviceIdentityContracts_TPM_ATTESTED_eab30229 else Mode := CozyText_DeviceIdentityContracts_COMPATIBLE_025663a0;
    P:=TJSONObject.Create;N(P,CozyText_DeviceIdentityContracts_version_d613fa03,2);N(P,CozyText_DeviceIdentityContracts_epoch_76732650,7);N(P,CozyText_DeviceIdentityContracts_revision_fd36e2bb,9);
    S(P,CozyText_DeviceIdentityContracts_mode_95921e9d,Mode);S(P,CozyText_DeviceIdentityContracts_keyNamespace_269dc0d7,LowerID);B(P,CozyText_DeviceIdentityContracts_trustConfigured_1349d965,Platform);
    if Platform then S(P,CozyText_DeviceIdentityContracts_keyProvider_cccfe04a,CozyText_DeviceIdentityContracts_PLATFORM_74e20b5a) else S(P,CozyText_DeviceIdentityContracts_keyProvider_cccfe04a,CozyText_DeviceIdentityContracts_SOFTWARE_a88dec85);
    C:=TJSONObject.Create;N(C,CozyText_DeviceIdentityContracts_version_d613fa03,2);N(C,CozyText_DeviceIdentityContracts_epoch_76732650,7);N(C,CozyText_DeviceIdentityContracts_revision_fd36e2bb,9);
    N(C,CozyText_DeviceIdentityContracts_expiresAt_fb4a750d,Expires);S(C,CozyText_DeviceIdentityContracts_challengeId_7898e58a,ChallengeID);S(C,CozyText_DeviceIdentityContracts_nonce_03230f40,Nonce);
    S(C,CozyText_DeviceIdentityContracts_context_9dffc245,AppContext);S(C,CozyText_DeviceIdentityContracts_keyId_bafc5c7e,KeyID);S(C,CozyText_DeviceIdentityContracts_bindingId_63d8b644,LowerID);
    S(C,CozyText_DeviceIdentityContracts_mode_95921e9d,Mode);B(C,CozyText_DeviceIdentityContracts_requireTpm_59d62efb,Platform);
    S(C,CozyText_DeviceIdentityContracts_canonical_fb1dbc83,CozyText_DeviceIdentityContracts_GAME_DEVICE_IDENTITY_V2_064b0471+#10+ChallengeID+#10+Nonce+#10+
      AppContext+#10+KeyID+#10+LowerID+#10+'7'+#10+'9'+#10+IntToStr(Expires)+#10+Mode);
    A:=TJSONObject.Create;N(A,CozyText_DeviceIdentityContracts_version_d613fa03,2);N(A,CozyText_DeviceIdentityContracts_expiresAt_fb4a750d,Expires);
    S(A,CozyText_DeviceIdentityContracts_status_5510ee87,CozyText_DeviceIdentityContracts_TPM_ACTIVATION_REQUIRED_60122140);S(A,CozyText_DeviceIdentityContracts_challengeId_7898e58a,ChallengeID);
    S(A,CozyText_DeviceIdentityContracts_activationCanonical_ad7bf2a7,CozyText_DeviceIdentityContracts_GAME_DEVICE_ACTIVATION_V2_1d67efd8+#10+ChallengeID+#10+AppContext+#10+LowerID);
    E:=TJSONObject.Create;N(E,CozyText_DeviceIdentityContracts_version_d613fa03,2);S(E,CozyText_DeviceIdentityContracts_status_5510ee87,CozyText_DeviceIdentityContracts_ENROLLED_ef12c1bc);S(E,CozyText_DeviceIdentityContracts_enrollmentId_2eb98099,LowerID);
    S(E,CozyText_DeviceIdentityContracts_identityScheme_4c402bd5,CozyText_DeviceIdentityContracts_APP_CNG_RSA2048_V2_51fe2b4c);B(E,CozyText_DeviceIdentityContracts_tpmAttested_bc99a954,Platform);
    if Platform then S(E,CozyText_DeviceIdentityContracts_assurance_adc12894,CozyText_DeviceIdentityContracts_TPM_KEY_ATTESTED_1367c4ec) else S(E,CozyText_DeviceIdentityContracts_assurance_adc12894,CozyText_DeviceIdentityContracts_PERSISTENT_KEY_POSSESSION_2b1578f4);
  end;
begin
  Checks:=0;P:=nil;C:=nil;A:=nil;E:=nil;Request:=nil;
  try
    Reset(False);Policy:=ReadIdentityPolicy(P);
    Challenge:=ReadIdentityChallenge(Policy,C,AppContext,KeyID,False);
    Check(Challenge.Context=AppContext,CozyText_DeviceIdentityContracts_SOFTWARE_BINDING_add53d53);
    ValidateIdentityEnrolled(E,Policy,False);Inc(Checks);
    Reset(True);Policy:=ReadIdentityPolicy(P);
    Challenge:=ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);
    ValidateIdentityActivation(A,Challenge,True);
    ValidateIdentityActivationDomain(A,Challenge,LowerID);
    ValidateIdentityEnrolled(E,Policy,True);Inc(Checks);
    { An existing TPM registration remains TPM-backed even in COMPATIBLE mode. }
    S(P,CozyText_DeviceIdentityContracts_mode_95921e9d,CozyText_DeviceIdentityContracts_COMPATIBLE_025663a0);Policy:=ReadIdentityPolicy(P);
    ValidateIdentityEnrolled(E,Policy,True);Inc(Checks);
    for CaseID:=1 to 28 do begin
      Reset(True);Policy:=ReadIdentityPolicy(P);
      Challenge:=ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);
      Failed:=False;
      try
        case CaseID of
          1: begin S(P,CozyText_DeviceIdentityContracts_keyProvider_cccfe04a,CozyText_DeviceIdentityContracts_SOFTWARE_a88dec85);ReadIdentityPolicy(P);end;
          2: begin B(P,CozyText_DeviceIdentityContracts_trustConfigured_1349d965,False);ReadIdentityPolicy(P);end;
          3: begin N(P,CozyText_DeviceIdentityContracts_version_d613fa03,1);ReadIdentityPolicy(P);end;
          4: begin S(P,CozyText_DeviceIdentityContracts_keyNamespace_269dc0d7,CozyText_DeviceIdentityContracts_invalid_aff0066d);ReadIdentityPolicy(P);end;
          5: begin N(P,CozyText_DeviceIdentityContracts_epoch_76732650,-1);ReadIdentityPolicy(P);end;
          6: begin N(P,CozyText_DeviceIdentityContracts_revision_fd36e2bb,9007199254740992);ReadIdentityPolicy(P);end;
          7: begin S(C,CozyText_DeviceIdentityContracts_context_9dffc245,CozyText_DeviceIdentityContracts_B_OTHER_APP_bc11070d);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          8: begin S(C,CozyText_DeviceIdentityContracts_keyId_bafc5c7e,CozyText_DeviceIdentityContracts_OTHER_67ad27f1);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          9: begin N(C,CozyText_DeviceIdentityContracts_epoch_76732650,8);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          10: begin N(C,CozyText_DeviceIdentityContracts_revision_fd36e2bb,10);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          11: begin S(C,CozyText_DeviceIdentityContracts_mode_95921e9d,CozyText_DeviceIdentityContracts_COMPATIBLE_025663a0);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          12: begin S(C,CozyText_DeviceIdentityContracts_bindingId_63d8b644,CozyText_DeviceIdentityContracts_other_device_a22b4202);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          13: begin B(C,CozyText_DeviceIdentityContracts_requireTpm_59d62efb,False);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          14: ReadIdentityChallenge(Policy,C,AppContext,KeyID,False);
          15: begin S(C,CozyText_DeviceIdentityContracts_nonce_03230f40,CozyText_DeviceIdentityContracts_AA_cc6812d6);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          16: begin S(C,CozyText_DeviceIdentityContracts_canonical_fb1dbc83,CozyText_DeviceIdentityContracts_unbound_domain_201583df);ReadIdentityChallenge(Policy,C,AppContext,KeyID,True);end;
          17: begin S(A,CozyText_DeviceIdentityContracts_challengeId_7898e58a,CozyText_DeviceIdentityContracts_other_challenge_fd8951bf);ValidateIdentityActivation(A,Challenge,True);end;
          18: begin N(A,CozyText_DeviceIdentityContracts_expiresAt_fb4a750d,Expires+1);ValidateIdentityActivation(A,Challenge,True);end;
          19: ValidateIdentityActivation(A,Challenge,False);
          20: begin S(A,CozyText_DeviceIdentityContracts_activationCanonical_ad7bf2a7,CozyText_DeviceIdentityContracts_other_domain_3c184ea2);ValidateIdentityActivationDomain(A,Challenge,LowerID);end;
          21: ValidateIdentityEnrolled(E,Policy,False);
          22: begin S(E,CozyText_DeviceIdentityContracts_assurance_adc12894,CozyText_DeviceIdentityContracts_PERSISTENT_KEY_POSSESSION_2b1578f4);ValidateIdentityEnrolled(E,Policy,True);end;
          23: begin B(E,CozyText_DeviceIdentityContracts_tpmAttested_bc99a954,False);ValidateIdentityEnrolled(E,Policy,True);end;
          24: begin S(E,CozyText_DeviceIdentityContracts_status_5510ee87,CozyText_DeviceIdentityContracts_FAILED_0d796134);ValidateIdentityEnrolled(E,Policy,True);end;
          25: begin N(E,CozyText_DeviceIdentityContracts_version_d613fa03,1);ValidateIdentityEnrolled(E,Policy,True);end;
          26: begin S(E,CozyText_DeviceIdentityContracts_identityScheme_4c402bd5,CozyText_DeviceIdentityContracts_LEGACY_5238e418);ValidateIdentityEnrolled(E,Policy,True);end;
          27: begin S(E,CozyText_DeviceIdentityContracts_enrollmentId_2eb98099,CozyText_DeviceIdentityContracts_invalid_aff0066d);ValidateIdentityEnrolled(E,Policy,True);end;
          28: begin Reset(False);Policy:=ReadIdentityPolicy(P);B(E,CozyText_DeviceIdentityContracts_tpmAttested_bc99a954,True);ValidateIdentityEnrolled(E,Policy,False);end;
        end;
      except on Err:Exception do Failed:=True;end;
      Check(Failed,CozyText_DeviceIdentityContracts_REJECTION_91d52f5c+IntToStr(CaseID));
    end;
    Check(IdentityRemainingMs(0)=10000,CozyText_DeviceIdentityContracts_BUDGET_INITIAL_130240e0);
    Check(IdentityRemainingMs(80000)=10000,CozyText_DeviceIdentityContracts_BUDGET_BOUND_25a99826);
    Check(IdentityRemainingMs(89999)=1,CozyText_DeviceIdentityContracts_BUDGET_FINAL_cc8beebc);
    for CaseID:=0 to 1 do begin
      Failed:=False;Ignored:=0;
      try
        if CaseID=0 then Ignored:=IdentityRemainingMs(90000)
        else Ignored:=IdentityRemainingMs(-1);
      except on Err:Exception do Failed:=True;end;
      Check(Failed and (Ignored=0),CozyText_DeviceIdentityContracts_EXPIRED_REJECTED_fa355929);
    end;
    SessionSecret.Assign(CozyText_DeviceIdentityContracts_synthetic_session_token_84114ff1);ActivationSecret.Assign(CozyText_DeviceIdentityContracts_synthetic_activation_45fe1b6a);
    Request:=TDeviceIdentityRequest.Create(CozyText_DeviceIdentityContracts_tpmActivate_33f093dd,'B',CozyText_DeviceIdentityContracts_SESSION_f43d2781,CozyText_DeviceIdentityContracts_MACHINE_a025bb25,SessionSecret);
    Request.AddActivationSecret(ActivationSecret);
    Check(IdentityText(Request.Body,CozyText_DeviceIdentityContracts_sessionToken_c0627a4b)=CozyText_DeviceIdentityContracts_synthetic_session_token_84114ff1,CozyText_DeviceIdentityContracts_TOKEN_BOUNDARY_154c0416);
    Check(IdentityText(Request.Body,CozyText_DeviceIdentityContracts_secret_c7729d0f)=CozyText_DeviceIdentityContracts_synthetic_activation_45fe1b6a,CozyText_DeviceIdentityContracts_ACTIVATION_BOUNDARY_5bdeed74);
    Failed:=False;try Request.AddActivationSecret(ActivationSecret);except on Err:Exception do Failed:=True;end;
    Check(Failed,CozyText_DeviceIdentityContracts_DUPLICATE_SECRET_3ae956d1);Request.Close;Request.Close;
    Failed:=False;Value:=nil;try Value:=Request.Body;except on Err:Exception do Failed:=True;end;
    Check(Failed and (Value=nil),CozyText_DeviceIdentityContracts_CLOSED_BODY_baf0156a);FreeAndNil(Request);
    SessionSecret.Clear;ActivationSecret.Clear;
    Check(SessionSecret.IsEmpty and ActivationSecret.IsEmpty,CozyText_DeviceIdentityContracts_OPERATION_OWNERS_CLEARED_07a97d74);
    Failed:=False;try Request:=TDeviceIdentityRequest.Create(CozyText_DeviceIdentityContracts_policy_75da5ca9,'B',CozyText_DeviceIdentityContracts_SESSION_f43d2781,CozyText_DeviceIdentityContracts_MACHINE_a025bb25,SessionSecret);except on Err:Exception do Failed:=True;end;
    Check(Failed,CozyText_DeviceIdentityContracts_EMPTY_SESSION_0c35766a);
    Writeln(CozyText_DeviceIdentityContracts_JsonFixture_f6a879a0+IntToStr(Checks)+CozyText_DeviceIdentityContracts_hardwareAttestation_false_7edb0f64);
  finally
    Request.Free;P.Free;C.Free;A.Free;E.Free;
    SessionSecret.Clear;ActivationSecret.Clear;
  end;
end;
