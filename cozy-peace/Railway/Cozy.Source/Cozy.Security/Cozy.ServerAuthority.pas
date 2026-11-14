unit Cozy.ServerAuthority;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Security,

{ Cozy central text imports. }

  System.JSON, Cozy.Transport, Cozy.Security, Cozy.CodeIntegrity, Cozy.Integrity, Cozy.OwnedRuntime, Cozy.NHW.TpmQuote;

type
  TAuthorityCancelled = reference to function: Boolean;
  TAuthorityExtensionResult = (aerUnavailable, aerAdded, aerInvalid);

  { Each role owns its observer. Only the pinned authority transport may pass
    a challenge or verdict into this interface. }
  ICozyAuthorityExtension = interface
    procedure SetQuoteProvider(const Quoter: ICozyTpmQuoter);
    procedure ConfigureResponses(Transport: TConnectTransport;
      Security: TDeviceSecurity; const Stage, SessionID, SessionToken: string);
    function AddEvidence(const EncodedChallenge: string;
      Document: TJSONObject): TAuthorityExtensionResult;
    function ApplyVerdict(const EncodedVerdict: string; ExpectedAccepted: Boolean): Boolean;
    procedure RetireObservation;
    procedure FlushSecurityReports(TimeoutMS: Cardinal = 3500);
  end;

{ No local authority database, cached permission token, signer list or policy
  file. This module sends bounded observations and follows the server result. }
procedure RequireServerObservation(Transport: TConnectTransport;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
  const Stage, SessionID, SessionToken, Intent, Binding,
  FileSHA512, FileCRC64: string;
  const Cancelled: TAuthorityCancelled = nil; OwnImage: TImageIntegrity = nil;
  const Runtime: ICozyRuntimeMeasurement = nil;
  const Extension: ICozyAuthorityExtension = nil);
function AuthorityBinding(const OperationID, PayloadHash: string): string;

implementation

uses Cozy.Clock,
  System.SysUtils, Cozy.Measurement, System.RegularExpressions, System.Classes,
  System.Diagnostics, System.Generics.Collections,
  Cozy.ProtocolJson, Cozy.Api.Types, Cozy.OwnMeasurement, Cozy.Api.Pointer, Cozy.ProcessMitigations,
  Cozy.DeviceSignals
  {$IFDEF GAME_PRODUCT_FAULT_TESTS}, Cozy.ProductFaults{$ENDIF};

const
  AuthorityDomain = CozyText_ServerAuthority_GAME_AUTHORITY_V2_8ae9fd0f;
  ObservationBudgetMs = 25000;
  NHWVersionField = CozyText_ServerAuthority_nhwVersion_d3612220;
  NHWChallengeField = CozyText_ServerAuthority_nhwChallenge_5bfa1ea9;
  NHWVerdictField = CozyText_ServerAuthority_nhwVerdict_6af42903;
var
  ObservationLock: TObject;
  ActiveObservations: TDictionary<string, Byte>;

procedure Invalid;
begin
  raise EGameApi.Create(CozyText_ServerAuthority_SECURITY_RESPONSE_INVALID_ae0f58bd,
    CozyText_ServerAuthority_Text_72f3251a);
end;

procedure RequireAuthorityDocument(const Name: string; Value: TJSONObject);
begin
  try ValidateProtocolDocument(Name, Value);
  except on E: EConvertError do Invalid; end;
end;

function RemainingBudget(const Clock: TStopwatch;
  const Cancelled: TAuthorityCancelled): Cardinal;
var Left: Int64;
begin
  if Assigned(Cancelled) and Cancelled() then
    raise EGameApi.Create(CozyText_ServerAuthority_CLIENT_STOPPING_1829bd1c, CozyText_ServerAuthority_Session_is_closing_b81bf06a);
  Left := ObservationBudgetMs - Clock.ElapsedMilliseconds;
  if Left <= 0 then
    raise EGameApi.Create(CozyText_ServerAuthority_SECURITY_OBSERVATION_TIMEOUT_8c795aca,
      CozyText_ServerAuthority_Text_6007d1b9, True);
  if Left > 10000 then Left := 10000;
  Result := Cardinal(Left);
end;

procedure WaitBeforeRetry(const Clock: TStopwatch;
  const Cancelled: TAuthorityCancelled; const OperationKey: string);
var DelayMs, Piece: Cardinal;
begin
  { Timing dispersion only, not a secret or an authorization decision. }
  DelayMs := 250 + Cardinal(Ord(OperationKey[1]) * 17 +
    Ord(OperationKey[2]) + Clock.ElapsedMilliseconds mod 251) mod 500;
  while DelayMs > 0 do
  begin
    Piece := RemainingBudget(Clock, Cancelled);
    if Piece > 25 then Piece := 25;
    if Piece > DelayMs then Piece := DelayMs;
    if not CozyWaitForDelay(Piece,
      function: Boolean
      begin
        Result := Assigned(Cancelled) and Cancelled();
      end) then raise EGameApi.Create(CozyText_ServerAuthority_CLIENT_STOPPING_1829bd1c, CozyText_ServerAuthority_Session_is_closing_b81bf06a);
    Dec(DelayMs, Piece);
  end;
end;

procedure BeginObservation(const OperationKey: string);
begin
  TMonitor.Enter(ObservationLock);
  try
    if ActiveObservations.ContainsKey(OperationKey) or
      (ActiveObservations.Count >= 128) then
      raise EGameApi.Create(CozyText_ServerAuthority_SECURITY_OBSERVATION_BUSY_f35596ed,
        CozyText_ServerAuthority_Text_848d7235, True);
    ActiveObservations.Add(OperationKey, 0);
  finally
    TMonitor.Exit(ObservationLock);
  end;
end;

procedure EndObservation(const OperationKey: string);
begin
  TMonitor.Enter(ObservationLock);
  try
    ActiveObservations.Remove(OperationKey);
  finally
    TMonitor.Exit(ObservationLock);
  end;
end;

function Text(Obj: TJSONObject; const Name: string; MaxSize: Integer): string;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONString) then Invalid;
  Result := Value.Value;
  if (Length(Result) = 0) or (Length(Result) > MaxSize) or
    (Pos(#10, Result) <> 0) or (Pos(#13, Result) <> 0) then Invalid;
end;

function Number(Obj: TJSONObject; const Name: string): Int64;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONNumber) then Invalid;
  if not TryStrToInt64(Value.Value, Result) or (Result < 0) or
    (Result > 9007199254740991) then Invalid;
end;

function IsTrue(Obj: TJSONObject; const Name: string): Boolean;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONBool) then Invalid;
  Result := Value.Value = CozyText_ServerAuthority_true_5a5135e9;
end;

type
  { This subtype records local transport provenance. A server-supplied error
    string cannot authorize replay of a committed, signed submit. }
  EAuthorityTransportFailure = class(EGameApi);

function Post(Transport: TConnectTransport; Body: TJSONObject;
  const Clock: TStopwatch; const Cancelled: TAuthorityCancelled): TJSONObject;
var Response: TJSONObject; Value: TJSONValue; Code: string;
begin
  try
    Response := Transport.PostJSON(CozyText_ServerAuthority_security_70a7e1e8, Body, RemainingBudget(Clock, Cancelled));
  except
    on E: EConnectTransport do
      raise EAuthorityTransportFailure.Create(E.Code, E.Message,
        (E.Code = CozyText_ServerAuthority_CONNECT_TIMEOUT_e18c1f98) or (E.Code = CozyText_ServerAuthority_CONNECT_UNAVAILABLE_348a6c0f) or
        (E.Code = CozyText_ServerAuthority_CONNECT_SEND_FAILED_bb1a979b) or (E.Code = CozyText_ServerAuthority_CONNECT_RECEIVE_FAILED_c7440a32) or
        (E.Code = CozyText_ServerAuthority_NETWORK_UNAVAILABLE_429d6e4b));
  end;
  try
    if Response = nil then Invalid;
    if not IsTrue(Response, CozyText_ServerAuthority_ok_9ea7db66) then
    begin
      Code := Text(Response, CozyText_ServerAuthority_error_9eefe280, 80);
      if not TRegEx.IsMatch(Code, CozyText_ServerAuthority_Pattern_084c1bd6) then Invalid;
      raise EGameApi.Create(Code, CozyText_ServerAuthority_Text_4311750c,
        (Code = CozyText_ServerAuthority_SECURITY_FRESH_OBSERVATION_REQUIRED_b268784a) or
        (Code = CozyText_ServerAuthority_SECURITY_CHALLENGE_INVALID_01125686) or (Code = CozyText_ServerAuthority_SECURITY_RATE_LIMIT_eabda515) or
        (Code = CozyText_ServerAuthority_SECURITY_OBSERVATION_BUSY_f35596ed) or (Code = CozyText_ServerAuthority_SECURITY_CAPACITY_1df6b4d3));
    end;
    Value := Response.GetValue(CozyText_ServerAuthority_data_b9326ab6);
    if not (Value is TJSONObject) then Invalid;
    Result := TJSONObject(Value.Clone);
  finally
    Response.Free;
  end;
end;

function SubmitExact(Transport: TConnectTransport; Body: TJSONObject;
  const Clock: TStopwatch; const Cancelled: TAuthorityCancelled): TJSONObject;
var Attempt: Integer;
begin
  Result := nil;
  { A lost response may follow a committed decision. Reuse the exact signed
    request and challenge once; the server receipt never extends permission. }
  for Attempt := 1 to 2 do
  begin
    RemainingBudget(Clock, Cancelled);
    try
      Result := Post(Transport, Body, Clock, Cancelled);
      Exit;
    except
      on E: EAuthorityTransportFailure do
        if (Attempt = 2) or not E.Retryable or
          not ((E.Code = CozyText_ServerAuthority_CONNECT_TIMEOUT_e18c1f98) or
          (E.Code = CozyText_ServerAuthority_CONNECT_UNAVAILABLE_348a6c0f) or
          (E.Code = CozyText_ServerAuthority_CONNECT_SEND_FAILED_bb1a979b) or
          (E.Code = CozyText_ServerAuthority_CONNECT_RECEIVE_FAILED_c7440a32) or
          (E.Code = CozyText_ServerAuthority_NETWORK_UNAVAILABLE_429d6e4b)) then raise;
    end;
  end;
end;

function AuthorityBinding(const OperationID, PayloadHash: string): string;
begin
  Result := IntegritySHA512Text(OperationID + '|' + PayloadHash);
end;

procedure ObserveOnce(Transport: TConnectTransport;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
  const Stage, SessionID, SessionToken, Intent, Binding,
  FileSHA512, FileCRC64: string; const Clock: TStopwatch;
  const Cancelled: TAuthorityCancelled; OwnImage: TImageIntegrity;
  const Runtime: ICozyRuntimeMeasurement; const Extension: ICozyAuthorityExtension);
var
  Body, Challenge, Evidence, SubmitBody, Reply, CrcLayers, Bundle, Environment, Profile: TJSONObject;
  ProfileValue, DeviceSignalsValue, NHWVerdictValue: TJSONValue;
  ExpectedChallengeFields, ExpectedReplyFields: Integer;
  DeviceSignalsRequested, NHWEvidenceSent, Proceed: Boolean;
  CurrentImage: TImageDigest; MeasurementState: TMeasurementStatus;
  ChallengeID, Nonce, Epoch, RequestedMode, PayloadText, Canonical,
    DynamicCodeState, CfgState, Measurement, Status, Reason, NHWChallenge: string;
  Seq, Revision, ExpiresAt: Int64;
  Code: TCodeIntegrityMeasurement;
  Mitigation: TMitigationObservation;
  procedure BindContext(Obj: TJSONObject; const Action: string);
  begin
    Obj.AddPair(CozyText_ServerAuthority_action_3cf8ef05, Action);
    Obj.AddPair(CozyText_ServerAuthority_stage_dc5b7edd, Stage);
    Obj.AddPair(CozyText_ServerAuthority_sessionId_63d5bd84, SessionID);
    Obj.AddPair(CozyText_ServerAuthority_sessionToken_ddf86030, SessionToken);
    Obj.AddPair(CozyText_ServerAuthority_machineId_b7bf7b62, Security.MachineID);
    Obj.AddPair(CozyText_ServerAuthority_intent_83992ce4, Intent);
    Obj.AddPair(CozyText_ServerAuthority_binding_308e17a7, Binding);
  end;
begin
  if (Transport = nil) or (Security = nil) or (CodeIntegrity = nil) then Invalid;
  if ((Stage <> 'A') and (Stage <> 'B') and (Stage <> 'O')) or
    not TRegEx.IsMatch(Binding, CozyText_ServerAuthority_Pattern_1413addd) then Invalid;
  Body := TJSONObject.Create;
  Challenge := nil; Evidence := nil; SubmitBody := nil; Reply := nil; CrcLayers := nil; Bundle := nil;
  try
    BindContext(Body, CozyText_ServerAuthority_challenge_662ced51);
    if Extension <> nil then
    begin
      Body.AddPair(NHWVersionField, TJSONNumber.Create(1));
    end;
    Body.AddPair(CozyText_ServerAuthority_deviceSignalsVersion_0a96eb08, TJSONNumber.Create(1));
    Environment := CollectMitigationEnvironment(Stage);
    if Environment <> nil then
    begin
      Body.AddPair(CozyText_ServerAuthority_mitigationProfileVersion_c5166409, TJSONNumber.Create(1));
      Body.AddPair(CozyText_ServerAuthority_mitigationEnvironment_c0780a83, Environment);
    end;
    Challenge := Post(Transport, Body, Clock, Cancelled);
    RequireAuthorityDocument(CozyText_ServerAuthority_authorityChallenge_7c9cc734, Challenge);
    ExpectedChallengeFields := 8;
    if Extension <> nil then
    begin
      NHWChallenge := Text(Challenge, NHWChallengeField, 80);
      Inc(ExpectedChallengeFields);
    end;
    Profile := nil; ProfileValue := Challenge.GetValue(CozyText_ServerAuthority_mitigationProfile_ce0336da);
    if ProfileValue <> nil then
    begin
      if not (ProfileValue is TJSONObject) then Invalid;
      Inc(ExpectedChallengeFields); Profile := TJSONObject(ProfileValue);
    end;
    DeviceSignalsRequested := False;
    DeviceSignalsValue := Challenge.GetValue(CozyText_ServerAuthority_deviceSignalsRequested_c9b9d556);
    if DeviceSignalsValue <> nil then
    begin
      if not (DeviceSignalsValue is TJSONBool) then Invalid;
      Inc(ExpectedChallengeFields);
      DeviceSignalsRequested := TJSONBool(DeviceSignalsValue).AsBoolean;
    end;
    if Challenge.Count <> ExpectedChallengeFields then Invalid;
    if Number(Challenge, CozyText_ServerAuthority_version_3101a476) <> 1 then Invalid;
    ChallengeID := Text(Challenge, CozyText_ServerAuthority_challengeId_6dd74210, 48);
    Nonce := Text(Challenge, CozyText_ServerAuthority_nonce_5928ba20, 48);
    Epoch := Text(Challenge, CozyText_ServerAuthority_epoch_4ee28422, 48);
    if not TRegEx.IsMatch(ChallengeID, CozyText_ServerAuthority_Pattern_1b2bcaae) or
      not TRegEx.IsMatch(Nonce, CozyText_ServerAuthority_Pattern_1b2bcaae) or
      not TRegEx.IsMatch(Epoch, CozyText_ServerAuthority_Pattern_1b2bcaae) then Invalid;
    Seq := Number(Challenge, CozyText_ServerAuthority_sequence_9e85f21c);
    Revision := Number(Challenge, CozyText_ServerAuthority_revision_93adf670);
    ExpiresAt := Number(Challenge, CozyText_ServerAuthority_expiresAt_936e4de3);
    if (Seq = 0) or (ExpiresAt = 0) then Invalid;
    RequestedMode := Text(Challenge, CozyText_ServerAuthority_dynamicCode_20202cec, 16);
    RemainingBudget(Clock, Cancelled);
    CollectProcessMitigationsProfile(RequestedMode, Profile, DynamicCodeState, CfgState, Mitigation);
    { Measure AFTER receipt of the one-use challenge, not a cached success. }
    MeasurementState := msNotMeasured; CurrentImage := Default(TImageDigest);
    Code := Default(TCodeIntegrityMeasurement);
    {$IFDEF GAME_PRODUCT_FAULT_TESTS}
    if (Stage = 'O') and ProductFaultArmed(CozyText_ServerAuthority_authority_measurement_skipped_53a3d46f) then
      ProductFaultObserved(CozyText_ServerAuthority_authority_measurement_skipped_53a3d46f)
    else
    {$ENDIF}
    Bundle := CollectOwnMeasurement(OwnImage, CodeIntegrity,
      TMeasurementBudget.Start(128 * 1024 * 1024, RemainingBudget(Clock, Cancelled),
        function: Boolean
        begin Result := Assigned(Cancelled) and Cancelled(); end),
      CurrentImage, Code, CrcLayers, MeasurementState, Runtime);
    if (MeasurementState = msMeasured) and
      not OwnMeasurementComplete(Bundle, CurrentImage, Code, CrcLayers, MeasurementState) then
    begin MeasurementState := msCoverageInsufficient; FreeAndNil(Bundle); end;
    if MeasurementState <> msMeasured then
    begin CurrentImage := Default(TImageDigest); Code := Default(TCodeIntegrityMeasurement); end;
    Measurement := MeasurementStatusName(MeasurementState);
    if (MeasurementState = msMeasured) and
      ((CurrentImage.SHA512 <> FileSHA512) or (CurrentImage.CRC64 <> FileCRC64)) then
      Invalid;
    Evidence := TJSONObject.Create;
    Evidence.AddPair(CozyText_ServerAuthority_version_3101a476, TJSONNumber.Create(1));
    Evidence.AddPair(CozyText_ServerAuthority_hashVersion_f0b7fb6d, TJSONNumber.Create(3));
    Evidence.AddPair(CozyText_ServerAuthority_measurement_ef68f65d, Measurement);
    Evidence.AddPair(CozyText_ServerAuthority_fileSha512_0effe453, CurrentImage.SHA512);
    Evidence.AddPair(CozyText_ServerAuthority_fileCrc64_f8383054, CurrentImage.CRC64);
    Evidence.AddPair(CozyText_ServerAuthority_codeSha512_008274fe, Code.SHA512);
    Evidence.AddPair(CozyText_ServerAuthority_codeCrc64_00e5aa47, Code.CRC64);
    Evidence.AddPair(CozyText_ServerAuthority_codeXxh3_128_2645c76b, Code.XXH3_128);
    Evidence.AddPair(CozyText_ServerAuthority_codeBlake3_c9cf06fa, Code.Blake3);
    if Bundle <> nil then begin Evidence.AddPair(CozyText_ServerAuthority_ownMeasurement_75447b40, Bundle); Bundle := nil; end;
    if CrcLayers <> nil then
    begin
      Evidence.AddPair(CozyText_ServerAuthority_crcLayers_a1b12042, CrcLayers);
      CrcLayers := nil;
    end;
    Evidence.AddPair(CozyText_ServerAuthority_apiSealed_6447305e, TJSONBool.Create(ApiPointerStorageIsSealed));
    Evidence.AddPair(CozyText_ServerAuthority_apiSlots_17b25661, TJSONNumber.Create(Int64(ApiPointerStorageCount)));
    Evidence.AddPair(CozyText_ServerAuthority_dynamicCode_20202cec, DynamicCodeState);
    Evidence.AddPair(CozyText_ServerAuthority_cfg_0b4824d7, CfgState);
    Evidence.AddPair(CozyText_ServerAuthority_mitigationDiagnostics_bd6aefb3, Mitigation.ToJSON);
    NHWEvidenceSent := False;
    if Extension <> nil then
    begin
      RemainingBudget(Clock, Cancelled);
      case Extension.AddEvidence(NHWChallenge, Evidence) of
        aerAdded: NHWEvidenceSent := True;
        aerInvalid: Invalid;
      end;
      RemainingBudget(Clock, Cancelled);
    end;
    RequireAuthorityDocument(CozyText_ServerAuthority_authorityPayload_56056ffe, Evidence);
    PayloadText := Evidence.ToJSON;
    if TEncoding.UTF8.GetByteCount(PayloadText) > 16384 then Invalid;
    { Reconstruct the canonical message, never sign arbitrary server text. }
    Canonical := AuthorityDomain + #10 + Stage + #10 + SessionID + #10 +
      Intent + #10 + Binding + #10 + ChallengeID + #10 + Nonce + #10 +
      Epoch + #10 + IntToStr(Seq) + #10 + IntToStr(Revision) + #10 +
      IntToStr(ExpiresAt) + #10 + IntegritySHA512Text(PayloadText);
    SubmitBody := TJSONObject.Create;
    BindContext(SubmitBody, CozyText_ServerAuthority_submit_665a2c63);
    SubmitBody.AddPair(CozyText_ServerAuthority_challengeId_6dd74210, ChallengeID);
    SubmitBody.AddPair(CozyText_ServerAuthority_payload_042d9fd9, PayloadText);
    SubmitBody.AddPair(CozyText_ServerAuthority_signature_aed6856e, Security.Sign(Canonical));
    {$IFDEF GAME_PRODUCT_FAULT_TESTS}
    if (Stage = 'O') and ProductFaultArmed(CozyText_ServerAuthority_authority_report_stopped_014a1f8d) then
    begin
      ProductFaultObserved(CozyText_ServerAuthority_authority_report_stopped_014a1f8d);
      raise EGameApi.Create(CozyText_ServerAuthority_PRODUCT_FAULT_REPORT_STOPPED_67736fb8, CozyText_ServerAuthority_Isolated_report_stop_test_bc3bb9f6);
    end;
    {$ENDIF}
    Reply := SubmitExact(Transport, SubmitBody, Clock, Cancelled);
    RemainingBudget(Clock, Cancelled);
    RequireAuthorityDocument(CozyText_ServerAuthority_authorityReply_ebe1af0d, Reply);
    ExpectedReplyFields := 8;
    NHWVerdictValue := Reply.GetValue(NHWVerdictField);
    if NHWVerdictValue <> nil then Inc(ExpectedReplyFields);
    if (Reply.Count <> ExpectedReplyFields) or (Number(Reply, CozyText_ServerAuthority_version_3101a476) <> 1) or
      not IsTrue(Reply, CozyText_ServerAuthority_accepted_93e25289) or (Number(Reply, CozyText_ServerAuthority_sequence_9e85f21c) <> Seq) then Invalid;
    if IsTrue(Reply, CozyText_ServerAuthority_attested_d629bbbf) or (Number(Reply, CozyText_ServerAuthority_expiresAt_936e4de3) = 0) then Invalid;
    Reason := Text(Reply, CozyText_ServerAuthority_reason_95413850, 80);
    Status := Text(Reply, CozyText_ServerAuthority_status_09762dac, 20);
    if (Status <> CozyText_ServerAuthority_PASS_c0904000) and (Status <> CozyText_ServerAuthority_INDETERMINATE_f930248a) and
      (Status <> CozyText_ServerAuthority_MISMATCH_99711c35) then Invalid;
    Proceed := IsTrue(Reply, CozyText_ServerAuthority_proceed_b2275828);
    if NHWEvidenceSent and Proceed and (NHWVerdictValue = nil) then Invalid;
    if NHWVerdictValue <> nil then
    begin
      if (Extension = nil) or not NHWEvidenceSent or
        not (NHWVerdictValue is TJSONString) then Invalid;
      { The matching, authenticated verdict can invalidate, but cannot grant a
        license or override the existing authority disposition. }
      if (not Proceed and (Status <> CozyText_ServerAuthority_MISMATCH_99711c35)) or
        not Extension.ApplyVerdict(NHWVerdictValue.Value, Proceed) then Invalid;
    end;
    if not Proceed then
      raise EGameApi.Create(CozyText_ServerAuthority_SECURITY_OBSERVATION_e9752426 + Status,
        CozyText_ServerAuthority_Text_a2b88c6b,
        (Status = CozyText_ServerAuthority_INDETERMINATE_f930248a) and (Reason = CozyText_ServerAuthority_MEASUREMENT_UNAVAILABLE_41cca989));
    { No hardware query occurs here. Only the explicitly requested, accepted
      observation can arm a short-lived one-use diagnostic collection. }
    ConfigureDeviceSignalsRequest(DeviceSignalsRequested, SessionID, ChallengeID, Nonce);
    { The real operation is STILL authorized by the server, using its own
      short-lived decision. This response is not stored as an authority token. }
  finally
    if Extension <> nil then Extension.RetireObservation;
    Bundle.Free; CrcLayers.Free;
    Reply.Free; SubmitBody.Free; Evidence.Free; Challenge.Free; Body.Free;
    WipeText(PayloadText); WipeText(Canonical);
    WipeText(ChallengeID); WipeText(Nonce); WipeText(Epoch); WipeText(NHWChallenge);
  end;
end;

procedure RequireServerObservation(Transport: TConnectTransport;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
  const Stage, SessionID, SessionToken, Intent, Binding,
  FileSHA512, FileCRC64: string; const Cancelled: TAuthorityCancelled; OwnImage: TImageIntegrity;
  const Runtime: ICozyRuntimeMeasurement; const Extension: ICozyAuthorityExtension);
var
  Attempt: Integer;
  Clock: TStopwatch;
  OperationKey: string;
begin
  if Transport = nil then Invalid;
  if Extension <> nil then
    Extension.ConfigureResponses(Transport, Security, Stage, SessionID, SessionToken);
  Clock := TStopwatch.StartNew;
  OperationKey := IntegritySHA512Text(Transport.BindingID + '|' + Stage + '|' +
    SessionID + '|' + Intent + '|' + Binding);
  BeginObservation(OperationKey);
  try
    { A new observation obtains a fresh one-use challenge. A lost submit reply
      first recovers the same signed request through SubmitExact. Nothing is
      cached locally; observation and receipt attempts share this one budget. }
    for Attempt := 1 to 2 do
    begin
      RemainingBudget(Clock, Cancelled);
      try
        ObserveOnce(Transport, Security, CodeIntegrity, Stage, SessionID,
          SessionToken, Intent, Binding, FileSHA512, FileCRC64, Clock, Cancelled, OwnImage, Runtime, Extension);
        Exit;
      except
        on E: EGameApi do
          if (Attempt = 2) or not E.Retryable then raise;
      end;
      WaitBeforeRetry(Clock, Cancelled, OperationKey);
    end;
  finally
    EndObservation(OperationKey);
    WipeText(OperationKey);
  end;
end;

initialization
  ObservationLock := TObject.Create;
  ActiveObservations := TDictionary<string, Byte>.Create;
finalization
  ActiveObservations.Free;
  ObservationLock.Free;
end.
