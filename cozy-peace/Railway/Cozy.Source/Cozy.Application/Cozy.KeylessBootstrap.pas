unit Cozy.KeylessBootstrap;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Application,
 System.SysUtils, System.JSON, Cozy.Security, Cozy.Transport;
{ Public profile + externally approved device possession. No launcher bearer
  secret is read from disk. The returned proof body is memory-only and is NOT
  approval; beginKeyless must atomically revalidate and consume it server-side. }
function WaitForKeylessApproval(Transport: TConnectTransport;
  Security: TDeviceSecurity; const RequestID, LauncherID, LauncherSHA512,
  LauncherCRC64, CodeSHA512, CodeCRC64: string;
  const Cancelled: TFunc<Boolean>; DiagnosticCode: PInteger = nil): TJSONObject;

{ Shared by the production A path and the native rejection probe. These helpers
  validate scheduling/bindings; they never grant execution or replace beginKeyless. }
function KeylessApprovalRemaining(ElapsedMs: Int64; Cancelled: Boolean): Cardinal;
procedure ValidateKeylessBinding(const Canonical, Expected: string);
function ValidateKeylessDecision(Reply: TJSONObject; const ChallengeID: string;
  ExpiresAt, ElapsedMs: Int64; Cancelled: Boolean;
  out PollDelayMs: Cardinal): string;

implementation
uses Cozy.Clock, System.Classes, System.Diagnostics, System.NetEncoding, Cozy.DeviceKey;
const
  ApprovalBudgetMs = 300000;
  RequestBudgetMs = 10000;
  DefaultPollMilliseconds = 2000;
  MinimumPollMilliseconds = 1000;
  MaximumPollMilliseconds = 5000;

procedure Fail(const Code: string);
begin
  raise EDeviceSecurity.Create(Code);
end;

function Text(Obj: TJSONObject; const Name: string; Maximum: Integer): string;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONString) then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
  Result := TJSONString(Value).Value;
  if (Length(Result) < 1) or (Length(Result) > Maximum) then
    Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
end;

function Number(Obj: TJSONObject; const Name: string): Int64;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONNumber) or not TryStrToInt64(Value.Value, Result) or
    (Result < 0) or (Result > 9007199254740991) then
    Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
end;

function TrueField(Obj: TJSONObject; const Name: string): Boolean;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONBool) then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
  Result := Value.Value = CozyText_KeylessBootstrap_true_65da0efd;
end;

procedure Hex64(const Value: string);
var Ch: Char;
begin
  if Length(Value) <> 64 then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
  for Ch in Value do
    if not CharInSet(Ch, ['0'..'9', 'a'..'f']) then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
end;

procedure Identifier(const Value: string);
var Ch: Char;
begin
  if (Length(Value) < 16) or (Length(Value) > 128) then
    Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
  for Ch in Value do
    if not CharInSet(Ch, ['0'..'9', 'a'..'z', 'A'..'Z', '-', '_']) then
      Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
end;

procedure Nonce32(const Value: string);
var Encoding: TBase64Encoding; Bytes: TBytes;
begin
  Encoding := TBase64Encoding.Create(0); Bytes := nil;
  try
    Bytes := Encoding.DecodeStringToBytes(Value);
    if (Length(Bytes) <> 32) or (Encoding.EncodeBytesToString(Bytes) <> Value) then
      Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
  finally WipeBytes(Bytes); Encoding.Free; end;
end;

function ActivationSecretDigest(const Value: string): string;
var Bytes, Digest: TBytes; Encoding: TBase64Encoding; I: Integer;
const Digits = CozyText_KeylessBootstrap_0123456789abcdef_28002505;
begin
  Bytes := nil; Digest := nil; Encoding := TBase64Encoding.Create(0);
  try
    Bytes := Encoding.DecodeStringToBytes(Value);
    if (Length(Bytes) <> 32) or (Encoding.EncodeBytesToString(Bytes) <> Value) then
      Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
    Digest := DeviceSHA256(Bytes); SetLength(Result, 64);
    for I := 0 to 31 do
    begin
      Result[I * 2 + 1] := Digits[(Digest[I] shr 4) + 1];
      Result[I * 2 + 2] := Digits[(Digest[I] and 15) + 1];
    end;
  finally WipeBytes(Bytes); WipeBytes(Digest); Encoding.Free; end;
end;

function KeylessApprovalRemaining(ElapsedMs: Int64; Cancelled: Boolean): Cardinal;
var Left: Int64;
begin
  if Cancelled then Fail(CozyText_KeylessBootstrap_CONNECT_CANCELLED_0c17670b);
  if (ElapsedMs < 0) or (ElapsedMs >= ApprovalBudgetMs) then
    Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_APPROVAL_EXPIRED_8aed2b80);
  Left := ApprovalBudgetMs - ElapsedMs;
  if Left > RequestBudgetMs then Left := RequestBudgetMs;
  Result := Cardinal(Left);
end;

procedure ValidateKeylessBinding(const Canonical, Expected: string);
begin
  if Canonical <> Expected then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_BINDING_INVALID_e71c9222);
end;

function ValidateKeylessDecision(Reply: TJSONObject; const ChallengeID: string;
  ExpiresAt, ElapsedMs: Int64; Cancelled: Boolean;
  out PollDelayMs: Cardinal): string;
var Hint: Int64;
begin
  { Check time and cancellation before interpreting even an APPROVED response. }
  KeylessApprovalRemaining(ElapsedMs, Cancelled);
  if Reply = nil then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
  if (Number(Reply, CozyText_KeylessBootstrap_version_3b2f77bb) <> 1) or
    (Text(Reply, CozyText_KeylessBootstrap_challengeId_64201889, 128) <> ChallengeID) or
    (Number(Reply, CozyText_KeylessBootstrap_expiresAt_74ebe00f) <> ExpiresAt) then
    Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
  Result := Text(Reply, CozyText_KeylessBootstrap_status_3649cf3b, 32);
  if (Result <> CozyText_KeylessBootstrap_PENDING_APPROVAL_31d34458) and (Result <> CozyText_KeylessBootstrap_APPROVED_85ab39c8) then
    Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_APPROVAL_REJECTED_49c6f942);
  Hint := DefaultPollMilliseconds;
  if Reply.GetValue(CozyText_KeylessBootstrap_pollAfterMs_760409e8) <> nil then Hint := Number(Reply, CozyText_KeylessBootstrap_pollAfterMs_760409e8);
  { The server adds load-aware random jitter. A hint affects only polling and
    cannot extend the original total budget or the 100ms cancellation slices. }
  if Hint < MinimumPollMilliseconds then Hint := MinimumPollMilliseconds;
  if Hint > MaximumPollMilliseconds then Hint := MaximumPollMilliseconds;
  PollDelayMs := Cardinal(Hint);
end;

function WaitForKeylessApproval(Transport: TConnectTransport;
  Security: TDeviceSecurity; const RequestID, LauncherID, LauncherSHA512,
  LauncherCRC64, CodeSHA512, CodeCRC64: string;
  const Cancelled: TFunc<Boolean>; DiagnosticCode: PInteger): TJSONObject;
var Body, Policy, Challenge, Reply, Evidence: TJSONObject;
  Key: TPersistentDeviceKey; Clock: TStopwatch;
  Namespace, ProviderKind, Mode, ChallengeID, Nonce, Canonical, Expected,
    AppSignature, PersistentSignature, PersistentKeyID, Status, ActivationSecret,
    ActivationCanonical, ActivationBlob, SecretDigest: string;
  Epoch, Revision, ExpiresAt: Int64;
  PollDelayMs: Cardinal; CancellationSeen, TpmRequired: Boolean;
  function Remaining: Cardinal;
  begin
    if Assigned(Cancelled) and Cancelled() then CancellationSeen := True;
    Result := KeylessApprovalRemaining(Clock.ElapsedMilliseconds, CancellationSeen);
  end;
  function Base(const Action: string): TJSONObject;
  begin
    Result := TJSONObject.Create;
    try
      Result.AddPair(CozyText_KeylessBootstrap_action_e64f6d64, Action);
      Result.AddPair(CozyText_KeylessBootstrap_version_3b2f77bb, TJSONNumber.Create(1));
    except Result.Free; raise; end;
  end;
  function Exchange(Request: TJSONObject): TJSONObject;
  var Envelope: TJSONObject; Value: TJSONValue;
  begin
    Envelope := nil;
    try
      Envelope := Transport.PostJSON(CozyText_KeylessBootstrap_bootstrap_7a975087, Request, Remaining);
      Remaining; { A late response cannot survive cancellation or total expiry. }
      if not TrueField(Envelope, CozyText_KeylessBootstrap_ok_e477fd64) then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_SERVER_REJECTED_ab61606a);
      Value := Envelope.GetValue(CozyText_KeylessBootstrap_data_796cbeae);
      if not (Value is TJSONObject) then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
      Result := TJSONObject(Value.Clone);
    finally Envelope.Free; end;
  end;
  function Proof(const Action: string): TJSONObject;
  begin
    Result := Base(Action);
    try
      Result.AddPair(CozyText_KeylessBootstrap_challengeId_64201889, ChallengeID);
      Result.AddPair(CozyText_KeylessBootstrap_appSignature_ee7e20fe, AppSignature);
      Result.AddPair(CozyText_KeylessBootstrap_persistentSignature_d91fde61, PersistentSignature);
    except Result.Free; raise; end;
  end;
  procedure ValidateDecision;
  begin
    Remaining;
    Status := ValidateKeylessDecision(Reply, ChallengeID, ExpiresAt,
      Clock.ElapsedMilliseconds, CancellationSeen, PollDelayMs);
  end;
  procedure WaitPoll;
  var UntilMs, Left: Int64; Budget: Cardinal;
  begin
    { No persistent timer/thread is created. Interrupted or delayed scheduling
      consumes the same monotonic total budget as transport and approval. }
    UntilMs := Clock.ElapsedMilliseconds + PollDelayMs;
    while True do
    begin
      Budget := Remaining;
      Left := UntilMs - Clock.ElapsedMilliseconds;
      if Left <= 0 then Break;
      if Left > 100 then Left := 100;
      if Left > Budget then Left := Budget;
      CozyWaitForDelay(Cardinal(Left),
        function: Boolean
        begin
          if Assigned(Cancelled) and Cancelled() then CancellationSeen := True;
          Result := CancellationSeen;
        end);
    end;
    Remaining;
  end;

begin
  Result := nil; Body := nil; Policy := nil; Challenge := nil; Reply := nil;
  Key := nil; Evidence := nil; CancellationSeen := False; PollDelayMs := DefaultPollMilliseconds;
  Clock := TStopwatch.StartNew;
  if (Transport = nil) or (Security = nil) then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_CONTEXT_INVALID_260af869);
  try
    try
    Body := Base(CozyText_KeylessBootstrap_keylessPolicy_bd3a7837);
    Body.AddPair(CozyText_KeylessBootstrap_launcherId_22378e44, LauncherID);
    Body.AddPair(CozyText_KeylessBootstrap_machineId_65c980d1, Security.MachineID);
    if DiagnosticCode <> nil then DiagnosticCode^ := 31024;
    Policy := Exchange(Body); FreeAndNil(Body);
    if Number(Policy, CozyText_KeylessBootstrap_version_3b2f77bb) <> 1 then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
    Namespace := Text(Policy, CozyText_KeylessBootstrap_keyNamespace_5dd9cb0e, 64); Hex64(Namespace);
    ProviderKind := Text(Policy, CozyText_KeylessBootstrap_keyProvider_6ce6bd1a, 16);
    Mode := Text(Policy, CozyText_KeylessBootstrap_mode_aa5a939a, 32);
    Epoch := Number(Policy, CozyText_KeylessBootstrap_epoch_a1a1772d); Revision := Number(Policy, CozyText_KeylessBootstrap_revision_f18cfc17);
    if (ProviderKind <> CozyText_KeylessBootstrap_SOFTWARE_e6be1b4a) and (ProviderKind <> CozyText_KeylessBootstrap_PLATFORM_a0c64076) then
      Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_POLICY_INVALID_532a62a2);
    if (Mode <> CozyText_KeylessBootstrap_COMPATIBLE_374fbb5d) and (Mode <> CozyText_KeylessBootstrap_PERSISTENT_43e19d6f) and (Mode <> CozyText_KeylessBootstrap_TPM_ATTESTED_71a9b66a) then
      Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_POLICY_INVALID_532a62a2);
    if (Mode = CozyText_KeylessBootstrap_TPM_ATTESTED_71a9b66a) and (ProviderKind <> CozyText_KeylessBootstrap_PLATFORM_a0c64076) then
      Fail(CozyText_KeylessBootstrap_DEVICE_TPM_REQUIRED_21ac8cce);
    if (ProviderKind = CozyText_KeylessBootstrap_PLATFORM_a0c64076) and not TrueField(Policy, CozyText_KeylessBootstrap_trustConfigured_8f08284d) then
      Fail(CozyText_KeylessBootstrap_DEVICE_TPM_TRUST_NOT_CONFIGURED_620e19fc);
    { A single OS-managed non-exportable identity is intentionally retained.
      Private key bytes are never exported, embedded or written by this app. }
    if DiagnosticCode <> nil then DiagnosticCode^ := 31025;
    Key := TPersistentDeviceKey.Create(Namespace, ProviderKind = CozyText_KeylessBootstrap_PLATFORM_a0c64076);
    Remaining;
    PersistentKeyID := DevicePublicKeyID(Key.PublicKey);
    Body := Base(CozyText_KeylessBootstrap_keylessChallenge_48d263b5);
    Body.AddPair(CozyText_KeylessBootstrap_requestId_159cbf32, RequestID);
    Body.AddPair(CozyText_KeylessBootstrap_launcherId_22378e44, LauncherID);
    Body.AddPair(CozyText_KeylessBootstrap_launcherSha512_8d19df33, LauncherSHA512);
    Body.AddPair(CozyText_KeylessBootstrap_launcherCrc64_f6972d80, LauncherCRC64);
    Body.AddPair(CozyText_KeylessBootstrap_aCodeSha512_0c044c0c, CodeSHA512);
    Body.AddPair(CozyText_KeylessBootstrap_aCodeCrc64_266f5bd2, CodeCRC64);
    Body.AddPair(CozyText_KeylessBootstrap_publicKey_b0c93de8, Security.PublicKeyBlob);
    Body.AddPair(CozyText_KeylessBootstrap_deviceId_88be9b21, Security.DeviceID);
    Body.AddPair(CozyText_KeylessBootstrap_machineId_65c980d1, Security.MachineID);
    Body.AddPair(CozyText_KeylessBootstrap_handoffVersion_70afc6ca, TJSONNumber.Create(3));
    Body.AddPair(CozyText_KeylessBootstrap_persistentPublicKey_7f3e6135, Key.PublicKey);
    Body.AddPair(CozyText_KeylessBootstrap_persistentKeyId_5e1fba40, PersistentKeyID);
    Body.AddPair(CozyText_KeylessBootstrap_keyProvider_6ce6bd1a, ProviderKind);
    Body.AddPair(CozyText_KeylessBootstrap_epoch_a1a1772d, TJSONNumber.Create(Epoch));
    Body.AddPair(CozyText_KeylessBootstrap_revision_f18cfc17, TJSONNumber.Create(Revision));
    if DiagnosticCode <> nil then DiagnosticCode^ := 31026;
    Challenge := Exchange(Body); FreeAndNil(Body);
    if (Number(Challenge, CozyText_KeylessBootstrap_version_3b2f77bb) <> 1) or
      (Text(Challenge, CozyText_KeylessBootstrap_status_3649cf3b, 32) <> CozyText_KeylessBootstrap_PROOF_REQUIRED_a1bb91e8) or
      (Number(Challenge, CozyText_KeylessBootstrap_epoch_a1a1772d) <> Epoch) or
      (Number(Challenge, CozyText_KeylessBootstrap_revision_f18cfc17) <> Revision) then Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
    ChallengeID := Text(Challenge, CozyText_KeylessBootstrap_challengeId_64201889, 128); Identifier(ChallengeID);
    Nonce := Text(Challenge, CozyText_KeylessBootstrap_nonce_4e0280e4, 44); Nonce32(Nonce);
    ExpiresAt := Number(Challenge, CozyText_KeylessBootstrap_expiresAt_74ebe00f);
    Canonical := Text(Challenge, CozyText_KeylessBootstrap_canonical_4b039eaf, 16384);
    Expected := CozyText_KeylessBootstrap_COZY_KEYLESS_BOOTSTRAP_V1_953de90a + #10 + ChallengeID + #10 + Nonce + #10 +
      RequestID + #10 + LauncherID + #10 + LauncherSHA512 + #10 + LauncherCRC64 + #10 +
      CodeSHA512 + #10 + CodeCRC64 + #10 + Security.MachineID + #10 + Security.DeviceID + #10 +
      PersistentKeyID + #10 + ProviderKind + #10 + IntToStr(Epoch) + #10 +
      IntToStr(Revision) + #10 + IntToStr(ExpiresAt);
    ValidateKeylessBinding(Canonical, Expected);
    if DiagnosticCode <> nil then DiagnosticCode^ := 31027;
    AppSignature := Security.Sign(Canonical);
    PersistentSignature := Key.Sign(Canonical);
    TpmRequired := Challenge.GetValue(CozyText_KeylessBootstrap_tpmRequired_5405d545) <> nil;
    if TpmRequired then
    begin
      if not TrueField(Challenge, CozyText_KeylessBootstrap_tpmRequired_5405d545) or (ProviderKind <> CozyText_KeylessBootstrap_PLATFORM_a0c64076) then
        Fail(CozyText_KeylessBootstrap_DEVICE_TPM_REQUIRED_21ac8cce);
    end;
    Body := Proof(CozyText_KeylessBootstrap_keylessProve_adcc5669);
    if TpmRequired then
    begin
      Evidence := Key.CreateEvidence(Nonce); Remaining;
      Body.AddPair(CozyText_KeylessBootstrap_tpmEvidence_539053e6, Evidence); Evidence := nil;
    end;
    Reply := Exchange(Body); FreeAndNil(Body);
    if TpmRequired then
    begin
      if (Number(Reply, CozyText_KeylessBootstrap_version_3b2f77bb) <> 1) or
        (Text(Reply, CozyText_KeylessBootstrap_status_3649cf3b, 32) <> CozyText_KeylessBootstrap_TPM_ACTIVATION_REQUIRED_bd0ade1b) or
        (Text(Reply, CozyText_KeylessBootstrap_challengeId_64201889, 128) <> ChallengeID) or
        (Number(Reply, CozyText_KeylessBootstrap_expiresAt_74ebe00f) <> ExpiresAt) then
        Fail(CozyText_KeylessBootstrap_COZY_KEYLESS_RESPONSE_INVALID_3d587ab5);
      ActivationBlob := Text(Reply, CozyText_KeylessBootstrap_activationBlob_119ce7c8, 4096);
      ActivationSecret := Key.Activate(ActivationBlob); Remaining;
      SecretDigest := ActivationSecretDigest(ActivationSecret);
      Expected := CozyText_KeylessBootstrap_COZY_KEYLESS_TPM_ACTIVATE_V1_45d2bd7e + #10 + ChallengeID + #10 +
        LauncherID + #10 + Security.MachineID + #10 + PersistentKeyID + #10 + SecretDigest;
      ActivationCanonical := Text(Reply, CozyText_KeylessBootstrap_activationCanonical_c0bbbc5c, 16384);
      ValidateKeylessBinding(ActivationCanonical, Expected);
      FreeAndNil(Reply);
      Body := Base(CozyText_KeylessBootstrap_keylessTpmActivate_38f3db1e);
      Body.AddPair(CozyText_KeylessBootstrap_challengeId_64201889, ChallengeID);
      Body.AddPair(CozyText_KeylessBootstrap_secret_0bc0cca1, ActivationSecret);
      Body.AddPair(CozyText_KeylessBootstrap_appSignature_ee7e20fe, Security.Sign(ActivationCanonical));
      Body.AddPair(CozyText_KeylessBootstrap_persistentSignature_d91fde61, Key.Sign(ActivationCanonical));
      try Reply := Exchange(Body);
      finally FreeAndNil(Body); WipeText(ActivationSecret); end;
      WipeText(ActivationCanonical); WipeText(ActivationBlob); WipeText(SecretDigest);
    end;
    { TPM proof alone grants no execution. Release key/provider handles before
      waiting for the separate administrator decision for this exact issued A. }
    FreeAndNil(Key); FreeAndNil(Policy); FreeAndNil(Challenge);
    WipeText(Namespace); WipeText(ProviderKind); WipeText(Mode);
    WipeText(Nonce); WipeText(Canonical); WipeText(Expected); WipeText(PersistentKeyID);
    Remaining;
    ValidateDecision;
    while Status <> CozyText_KeylessBootstrap_APPROVED_85ab39c8 do
    begin
      if DiagnosticCode <> nil then DiagnosticCode^ := 31028;
      FreeAndNil(Reply); WaitPoll;
      Body := Proof(CozyText_KeylessBootstrap_keylessStatus_f2b922d3); Reply := Exchange(Body); FreeAndNil(Body);
      ValidateDecision;
    end;
    Remaining;
    Result := TJSONObject.Create;
    Result.AddPair(CozyText_KeylessBootstrap_version_3b2f77bb, TJSONNumber.Create(1));
    Result.AddPair(CozyText_KeylessBootstrap_challengeId_64201889, ChallengeID);
    Result.AddPair(CozyText_KeylessBootstrap_appSignature_ee7e20fe, AppSignature);
    Result.AddPair(CozyText_KeylessBootstrap_persistentSignature_d91fde61, PersistentSignature);
  except
    FreeAndNil(Result);
    raise;
    end;
  finally
    Body.Free; Policy.Free; Challenge.Free; Reply.Free; Evidence.Free; Key.Free;
    WipeText(ActivationSecret); WipeText(ActivationCanonical);
    WipeText(ActivationBlob); WipeText(SecretDigest);
    WipeText(Namespace); WipeText(ProviderKind); WipeText(Mode); WipeText(ChallengeID);
    WipeText(Nonce); WipeText(Canonical); WipeText(Expected); WipeText(AppSignature);
    WipeText(PersistentSignature); WipeText(PersistentKeyID); WipeText(Status);
  end;
end;

end.
