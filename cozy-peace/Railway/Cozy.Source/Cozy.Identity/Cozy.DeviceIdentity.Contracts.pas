unit Cozy.DeviceIdentity.Contracts;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Identity,
 System.SysUtils, System.JSON, Cozy.SensitiveText;
type
  TDeviceIdentityPolicy = record
    Mode, ProviderKind, KeyNamespace: string;
    Epoch, Revision: Int64;
  end;
  TDeviceIdentityChallenge = record
    ID, Nonce, Context, Canonical, BindingID: string;
    ExpiresAt: Int64;
  end;
  { One request owns its JSON and the only app-maintained boundary strings.
    JSON dies before these strings are wiped. Session/activation backing stores
    stay separately owned by the operation. RTL/transport copies are not a
    claim of whole-process physical erasure. Never share this mutable owner. }
  TDeviceIdentityRequest = class
  private
    FBody: TJSONObject;
    FTokenText, FSecretText: UnicodeString;
    function GetBody: TJSONObject;
  public
    constructor Create(const Action, Stage, SessionID, MachineID: string;
      const SessionToken: TCozySecret);
    destructor Destroy; override;
    procedure AddActivationSecret(const Secret: TCozySecret);
    procedure Close;
    property Body: TJSONObject read GetBody;
  end;
function IdentityText(Obj: TJSONObject; const Name: string;
  Max: Integer = 16384): string;
function IdentityNumber(Obj: TJSONObject; const Name: string): Int64;
function IdentityBoolean(Obj: TJSONObject; const Name: string): Boolean;
function IdentityRemainingMs(ElapsedMs: Int64): Cardinal;
function ReadIdentityPolicy(Obj: TJSONObject): TDeviceIdentityPolicy;
function ReadIdentityChallenge(const Policy: TDeviceIdentityPolicy;
  Obj: TJSONObject; const Context, KeyID: string;
  IsPlatform: Boolean): TDeviceIdentityChallenge;
procedure ValidateIdentityActivation(Obj: TJSONObject;
  const Challenge: TDeviceIdentityChallenge; IsPlatform: Boolean);
procedure ValidateIdentityActivationDomain(Obj: TJSONObject;
  const Challenge: TDeviceIdentityChallenge; const SecretSha256: string);
procedure ValidateIdentityEnrolled(Obj: TJSONObject;
  const Policy: TDeviceIdentityPolicy; ActivationCompleted: Boolean);
implementation
uses System.NetEncoding, Cozy.Security;
procedure Invalid(const Code: string = CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_RESPONSE_INVALID_2b9b8b86);
begin raise EDeviceSecurity.Create(Code); end;
procedure LowerHex64(const S: string);
var C: Char;
begin
  if Length(S) <> 64 then Invalid;
  for C in S do if not CharInSet(C, ['0'..'9','a'..'f']) then Invalid;
end;
function IdentityText(Obj: TJSONObject; const Name: string; Max: Integer): string;
var V: TJSONValue;
begin
  if Obj = nil then Invalid;
  V := Obj.GetValue(Name);
  if not (V is TJSONString) then Invalid;
  Result := TJSONString(V).Value;
  if (Length(Result) < 1) or (Length(Result) > Max) then Invalid;
end;
function IdentityNumber(Obj: TJSONObject; const Name: string): Int64;
var V: TJSONValue;
begin
  if Obj = nil then Invalid;
  V := Obj.GetValue(Name);
  if not (V is TJSONNumber) then Invalid;
  if not TryStrToInt64(V.Value, Result) or (Result < 0) or
    (Result > 9007199254740991) then Invalid;
end;
function IdentityBoolean(Obj: TJSONObject; const Name: string): Boolean;
var V: TJSONValue;
begin
  if Obj = nil then Invalid;
  V := Obj.GetValue(Name);
  if not (V is TJSONBool) then Invalid;
  Result := V.Value = CozyText_DeviceIdentity_Contracts_true_9873fa0f;
end;
function IdentityRemainingMs(ElapsedMs: Int64): Cardinal;
begin
  if (ElapsedMs < 0) or (ElapsedMs >= 90000) then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_CHALLENGE_EXPIRED_e7676d4c);
  Result := Cardinal(90000 - ElapsedMs);
  if Result > 10000 then Result := 10000;
end;
function ReadIdentityPolicy(Obj: TJSONObject): TDeviceIdentityPolicy;
begin
  if IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_version_0f1065f8) <> 2 then Invalid;
  Result.Mode := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_mode_88824e40, 32);
  Result.ProviderKind := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_keyProvider_85bf7541, 16);
  Result.KeyNamespace := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_keyNamespace_b2c0f4b9, 64);
  LowerHex64(Result.KeyNamespace);
  Result.Epoch := IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_epoch_b2d26101);
  Result.Revision := IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_revision_74827b98);
  if ((Result.Mode <> CozyText_DeviceIdentity_Contracts_COMPATIBLE_22596379) and (Result.Mode <> CozyText_DeviceIdentity_Contracts_PERSISTENT_d0177f67) and
    (Result.Mode <> CozyText_DeviceIdentity_Contracts_TPM_ATTESTED_95f1f2b0)) or
    ((Result.ProviderKind <> CozyText_DeviceIdentity_Contracts_PLATFORM_c7c6b01c) and (Result.ProviderKind <> CozyText_DeviceIdentity_Contracts_SOFTWARE_f80b411a)) then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_POLICY_INVALID_05ffbdfa);
  if (Result.Mode = CozyText_DeviceIdentity_Contracts_TPM_ATTESTED_95f1f2b0) and (Result.ProviderKind <> CozyText_DeviceIdentity_Contracts_PLATFORM_c7c6b01c) then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_TPM_REQUIRED_79db1f7b);
  if (Result.ProviderKind = CozyText_DeviceIdentity_Contracts_PLATFORM_c7c6b01c) and not IdentityBoolean(Obj, CozyText_DeviceIdentity_Contracts_trustConfigured_6fa045ac) then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_TPM_TRUST_NOT_CONFIGURED_515a6eca);
end;
function ReadIdentityChallenge(const Policy: TDeviceIdentityPolicy;
  Obj: TJSONObject; const Context, KeyID: string;
  IsPlatform: Boolean): TDeviceIdentityChallenge;
var Expected: string; Bytes: TBytes; E: TBase64Encoding;
begin
  Result.Canonical := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_canonical_1c429a9a);
  Result.ID := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_challengeId_258fb983, 64);
  Result.Nonce := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_nonce_36f2f025, 64);
  Result.Context := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_context_a085e57f);
  Result.BindingID := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_bindingId_a5e66520, 64);
  Result.ExpiresAt := IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_expiresAt_10934131);
  LowerHex64(Result.BindingID);
  E := TBase64Encoding.Create(0);
  try
    Bytes := E.DecodeStringToBytes(Result.Nonce);
    if (Length(Bytes) <> 32) or (E.EncodeBytesToString(Bytes) <> Result.Nonce) then Invalid;
  finally WipeBytes(Bytes); E.Free; end;
  if (IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_version_0f1065f8) <> 2) or
    (Result.Context <> Context) or (IdentityText(Obj, CozyText_DeviceIdentity_Contracts_keyId_6cd63011, 64) <> KeyID) or
    (IdentityText(Obj, CozyText_DeviceIdentity_Contracts_mode_88824e40, 32) <> Policy.Mode) or
    (IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_epoch_b2d26101) <> Policy.Epoch) or
    (IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_revision_74827b98) <> Policy.Revision) or
    (IsPlatform <> (Policy.ProviderKind = CozyText_DeviceIdentity_Contracts_PLATFORM_c7c6b01c)) or
    (IdentityBoolean(Obj, CozyText_DeviceIdentity_Contracts_requireTpm_45c3fb17) <> IsPlatform) then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_BINDING_INVALID_5259dadb);
  Expected := CozyText_DeviceIdentity_Contracts_GAME_DEVICE_IDENTITY_V2_a0d36c92+#10+Result.ID+#10+Result.Nonce+#10+
    Context+#10+KeyID+#10+Result.BindingID+#10+IntToStr(Policy.Epoch)+#10+
    IntToStr(Policy.Revision)+#10+IntToStr(Result.ExpiresAt)+#10+Policy.Mode;
  try
    if Result.Canonical <> Expected then Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_DOMAIN_INVALID_46076d74);
  finally WipeBoundaryText(Expected); end;
end;
procedure ValidateIdentityActivation(Obj: TJSONObject;
  const Challenge: TDeviceIdentityChallenge; IsPlatform: Boolean);
begin
  if not IsPlatform or (IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_version_0f1065f8) <> 2) or
    (IdentityText(Obj, CozyText_DeviceIdentity_Contracts_status_62ddfb4d, 64) <> CozyText_DeviceIdentity_Contracts_TPM_ACTIVATION_REQUIRED_35057a26) or
    (IdentityText(Obj, CozyText_DeviceIdentity_Contracts_challengeId_258fb983, 64) <> Challenge.ID) or
    (IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_expiresAt_10934131) <> Challenge.ExpiresAt) then Invalid;
end;
procedure ValidateIdentityActivationDomain(Obj: TJSONObject;
  const Challenge: TDeviceIdentityChallenge; const SecretSha256: string);
var Expected: string;
begin
  LowerHex64(SecretSha256);
  Expected := CozyText_DeviceIdentity_Contracts_GAME_DEVICE_ACTIVATION_V2_24520ad4+#10+Challenge.ID+#10+
    Challenge.Context+#10+SecretSha256;
  try
    if IdentityText(Obj, CozyText_DeviceIdentity_Contracts_activationCanonical_cac054ea) <> Expected then
      Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_DOMAIN_INVALID_46076d74);
  finally WipeBoundaryText(Expected); end;
end;
procedure ValidateIdentityEnrolled(Obj: TJSONObject;
  const Policy: TDeviceIdentityPolicy; ActivationCompleted: Boolean);
var Assurance: string; Attested, MustAttest: Boolean;
begin
  if (IdentityNumber(Obj, CozyText_DeviceIdentity_Contracts_version_0f1065f8) <> 2) or
    (IdentityText(Obj, CozyText_DeviceIdentity_Contracts_status_62ddfb4d, 64) <> CozyText_DeviceIdentity_Contracts_ENROLLED_ae87de01) then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_SERVER_REJECTED_e05aff78);
  if IdentityText(Obj, CozyText_DeviceIdentity_Contracts_identityScheme_d7e29017, 64) <> CozyText_DeviceIdentity_Contracts_APP_CNG_RSA2048_V2_4f2b7860 then Invalid;
  LowerHex64(IdentityText(Obj, CozyText_DeviceIdentity_Contracts_enrollmentId_1f9dfb25, 64));
  Assurance := IdentityText(Obj, CozyText_DeviceIdentity_Contracts_assurance_31cd0d82, 64);
  Attested := IdentityBoolean(Obj, CozyText_DeviceIdentity_Contracts_tpmAttested_46502a47);
  MustAttest := (Policy.Mode = CozyText_DeviceIdentity_Contracts_TPM_ATTESTED_95f1f2b0) or (Policy.ProviderKind = CozyText_DeviceIdentity_Contracts_PLATFORM_c7c6b01c);
  if MustAttest then begin
    if not ActivationCompleted or (Assurance <> CozyText_DeviceIdentity_Contracts_TPM_KEY_ATTESTED_0bb487b4) or not Attested then
      Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_TPM_REQUIRED_79db1f7b);
  end else if ActivationCompleted or Attested or (Assurance <> CozyText_DeviceIdentity_Contracts_PERSISTENT_KEY_POSSESSION_f5a99de2) then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_RESPONSE_INVALID_2b9b8b86);
end;
constructor TDeviceIdentityRequest.Create(const Action, Stage, SessionID,
  MachineID: string; const SessionToken: TCozySecret);
begin
  inherited Create;
  if SessionToken.IsEmpty then Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_CONTEXT_INVALID_1ab0ebdd);
  FBody := TJSONObject.Create;
  FTokenText := SessionToken.CopyText;
  FBody.AddPair(CozyText_DeviceIdentity_Contracts_action_f4cb38d3, Action); FBody.AddPair(CozyText_DeviceIdentity_Contracts_stage_f2df5cef, Stage);
  FBody.AddPair(CozyText_DeviceIdentity_Contracts_sessionId_4dee0c93, SessionID); FBody.AddPair(CozyText_DeviceIdentity_Contracts_machineId_0211ef83, MachineID);
  FBody.AddPair(CozyText_DeviceIdentity_Contracts_sessionToken_87ab5983, FTokenText);
end;
function TDeviceIdentityRequest.GetBody: TJSONObject;
begin
  if FBody = nil then Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_REQUEST_CLOSED_7c596213);
  Result := FBody;
end;
procedure TDeviceIdentityRequest.AddActivationSecret(const Secret: TCozySecret);
begin
  GetBody;
  if (FSecretText <> '') or (FBody.GetValue(CozyText_DeviceIdentity_Contracts_secret_af4784b2) <> nil) or Secret.IsEmpty then
    Invalid(CozyText_DeviceIdentity_Contracts_DEVICE_IDENTITY_REQUEST_INVALID_b26b1ae9);
  FSecretText := Secret.CopyText;
  FBody.AddPair(CozyText_DeviceIdentity_Contracts_secret_af4784b2, FSecretText);
end;
procedure TDeviceIdentityRequest.Close;
begin
  try FreeAndNil(FBody);
  finally
    WipeBoundaryText(FSecretText);
    WipeBoundaryText(FTokenText);
  end;
end;
destructor TDeviceIdentityRequest.Destroy;
begin Close; inherited; end;
end.
