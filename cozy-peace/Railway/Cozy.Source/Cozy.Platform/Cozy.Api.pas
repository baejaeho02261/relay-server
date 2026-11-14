unit Cozy.Api;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,
 Cozy.OwnedRuntime,
  System.SysUtils, Cozy.Lifetime, System.JSON, Cozy.Security, Cozy.Api.Types,
  Cozy.Lifecycle, Cozy.Transport, Cozy.Server.Profile, Cozy.Integrity, Cozy.CodeIntegrity, Cozy.Measurement, Cozy.ServerAuthority, Cozy.NHW.Guard, Cozy.NHW.TpmQuote;

type
  TGameApi = class
  private
    FRuntimeGraph: TCozyOwnedRuntimeGraph;
    FGate: TGameCallGate;
    FSecurity: TDeviceSecurity;
    FLifecycle: TLifecycleReporter;
    FOverlayProfile: TConnectServerProfile;
    FOverlayStarted: Boolean;
    FOverlayRestrictedPrivileges: Boolean;
    FImageIntegrity: TImageIntegrity;
    FCodeIntegrity: TCodeIntegrity;
    FBoundImage: TImageDigest;
    FBoundCodeSHA512, FBoundCodeCRC64: string;
    FNextModules: UInt64;
    FModuleDeadlineTick, FModuleCycleMilliseconds: UInt64;
    FModuleReceiptID: string;
    FModuleReceiptServerTime, FModuleReceiptExpiresAt: Int64;
    FModuleSnapshot: TJSONObject;
    FModuleSnapshotID: string;
    FModuleSnapshotCompleted: Boolean;
    FModuleGenerationRetries: Integer;
    FModuleGenerationStarted: UInt64;
    FModuleNextIndex, FModuleBatchIndex, FModuleBatchCount, FModuleBatchSize: Integer;
    FStopRequested: LongInt;
    FNHWGuard: TCozyNHWGuard;
    FNHWAuthority: ICozyAuthorityExtension;
    FNHWOverlayID: string;
    FNHWStopFinished: Boolean;
    FLock: TObject;
    FTransport: TConnectTransport;
    FServerDisplayName: string;
    FActivationToken: string;
    FBootstrapSessionID, FBootstrapSessionToken: string;
    FPendingAction: string;
    FPendingRequestID: string;
    FPendingPayloadJSON: string;
    FCurrent: TLicenseState;
    FLastErrorCode: string;
    function OwnRuntime(Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity): ICozyRuntimeMeasurement;
    procedure RequireRunning;
    function NHWStopConfirmed: Boolean;
    procedure RequireServerProfile;
    function GetHasServerProfile: Boolean;
    function GetDeviceID: string;
    function GetHasAuthorization: Boolean;
    function GetCurrent: TLicenseState;
    function PostJSON(const Operation: string; Body: TJSONObject;
      ExactTransportRetry: Boolean = False;
      const Cancelled: TAuthorityCancelled = nil): TJSONObject;
    function ExecuteProof(const Action: string;
      const PayloadText: string; const RetryID: string = ''): TJSONObject;
    function ParseState(Data: TJSONObject; StartedAt: UInt64): TLicenseState;
    procedure AddBootstrapSession(Payload: TJSONObject);
    procedure MeasureOwn(out Image: TImageDigest; out Code: TCodeIntegrityMeasurement);
    procedure AddIntegrityBoundSession(Body: TJSONObject);
    function IntegritySubmitOverheadBytes: Integer;
    procedure SendIntegrityReport(Payload: TJSONObject;
      const Cancelled: TAuthorityCancelled = nil);
    procedure ReportMeasurementFailure(Status: TMeasurementStatus = msReadError);
    procedure ReportOverlayFailure(const Reason: string);
    procedure ClearModuleSnapshot;
    procedure RequireModuleSnapshotLease;
    procedure ApplyModuleSnapshotBudget(Reply: TJSONObject; StartedAt: UInt64);
    function CreateModulePayload(BatchIndex, BatchCount: Integer): TJSONObject;
    function ReportModulesIfDue: Boolean;
    procedure PreparePending(const Action: string; Payload: TJSONObject);
    procedure ClearPending;
    function ResumePending: TLicenseState;
    procedure FailOperation(const Code: string);
    function GetModuleInventoryReady: Boolean;
    function GetOverlayTransferred: Boolean;
    function GetLastErrorCode: string;
    function GetServerDisplayName: string;
    function StartOverlayCore(RestrictedPrivileges: Boolean;
      const Progress: TProc<Integer>): Boolean;
    function RedeemCore(const Key: string): TLicenseState;
    function VerifyCore: TLicenseState;
    procedure ReleaseCore;
    procedure CheckIntegrityCore(const Cancelled: TAuthorityCancelled = nil);
    function ContinueModuleInventoryCore: Boolean;
    procedure RequestStopCore;
    function GetDeviceIDCore: string;
    function GetHasAuthorizationCore: Boolean;
    function GetCurrentCore: TLicenseState;
    function GetHasServerProfileCore: Boolean;
    function GetModuleInventoryReadyCore: Boolean;
    function GetOverlayTransferredCore: Boolean;
    function GetLastErrorCodeCore: string;
    function GetServerDisplayNameCore: string;
  public
    { Takes ownership of Security and both integrity objects even on failure. }
    constructor Create(Profile: TConnectServerProfile; Security: TDeviceSecurity;
      const SessionID, SessionToken: string; ImageIntegrity: TImageIntegrity;
      CodeIntegrity: TCodeIntegrity; const CodeSHA512, CodeCRC64: string);
    destructor Destroy; override;
    { Caller retains this client until the call returns. Cancelled must be a
      nonblocking poll and must not reenter/free this client. No automatic call. }
    function InvokeServerPolicy(FunctionID: Word; const Args: array of Integer;
      const Cancelled: TAuthorityCancelled = nil): Integer;
    { Enable only after testing the final O in the target Windows environment.
      True requests fail-closed privilege reduction; it is not a resource sandbox. }
    { Progress is an observation only. It must not block, reenter or free this
      client; 100 is emitted only after an acknowledged ownership transfer. }
    function StartOverlay(RestrictedPrivileges: Boolean = False;
      const Progress: TProc<Integer> = nil): Boolean;
    function Redeem(const Key: string): TLicenseState;
    function Verify: TLicenseState;
    procedure Release;
    procedure CheckIntegrity;
    function ContinueModuleInventory: Boolean;
    procedure RequestStop;
    { Attach before starting the worker. The session owner keeps Guard alive
      until this API is released. Finish runs after the API worker joins
      and the sensor decision is sealed for shutdown. }
    procedure AttachNHW(Guard: TCozyNHWGuard; const Quoter: ICozyTpmQuoter = nil);
    procedure FlushNHWReports(TimeoutMS: Cardinal = 3500);
    procedure FinishNHWStop;
    { Owner-only after worker join. Retain signing key until the owner has
      reported the exact cleanup outcome, but release all image read pins. }
    procedure RetireImagesForShutdown;
    property Lifecycle: TLifecycleReporter read FLifecycle write FLifecycle;
    property ModuleInventoryReady: Boolean read GetModuleInventoryReady;
    { Published only after the authenticated transfer receipt is validated.
      Read after joining the worker to avoid a redundant shutdown request. }
    property OverlayTransferred: Boolean read GetOverlayTransferred;
    property DeviceID: string read GetDeviceID;
    property HasAuthorization: Boolean read GetHasAuthorization;
    property Current: TLicenseState read GetCurrent;
    property LastErrorCode: string read GetLastErrorCode;
    property HasServerProfile: Boolean read GetHasServerProfile;
    property ServerDisplayName: string read GetServerDisplayName;
  end;

implementation

uses Cozy.Clock,
  Winapi.Windows, System.Classes, System.Generics.Collections, System.RegularExpressions, Cozy.ModuleInventory, Cozy.ServerOperations, Cozy.OwnMeasurement, Cozy.Overlay.Client, Cozy.Handoff,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer, Cozy.Api.Guid,
  Cozy.NHW.Authority, Cozy.NHW.ResponsePath.Dispatch;

{ Private API pointers: initialized before application code starts. }
var

  ApiSlot_GetComputerName: TEncodedApiPointer;


const
  {$I ..\Cozy.Configuration\Cozy.Version.inc}
  MaxLeaseMilliseconds = 120000;
  ModuleBatchMaximum = 16;
  ModulePayloadMaximum = 24576;
  ModuleEnvelopeMaximum = 32768;
  ModuleSnapshotInterval = 60000;
  { One bounded O chunk (15 s) plus a lease/own-image renewal checkpoint.
    The measured scan AND all report batches are reserved separately. }
  ModuleSnapshotCheckpointReserve = 30000;
  ModuleGenerationRetryLimit = 2;
  ModuleGenerationRetryMilliseconds = 90000;

{ POINTER WRAPPERS 1 BEGIN }

function GetComputerName(Buffer: PWideChar; var Size: DWORD): BOOL; stdcall;
var
  ApiTarget: TApiGetComputerName;
begin
  ApiTarget := TApiGetComputerName(DecodeApiPointer(ApiSlot_GetComputerName));
  Result := ApiTarget(Buffer, Size);
end;
{ POINTER WRAPPERS 1 END }

function JsonString(Obj: TJSONObject; const Name: string;
  Required: Boolean = True): string;
var
  Value: TJSONValue;
begin
  Result := '';
  Value := Obj.GetValue(Name);
  if (Value = nil) and not Required then
    Exit;
  if not (Value is TJSONString) then
    raise EGameApi.Create(CozyText_Api_RESPONSE_INVALID_7c33082c,
      CozyText_Api_Text_e5363b36);
  Result := Value.Value;
  if Required and (Result = '') then
    raise EGameApi.Create(CozyText_Api_RESPONSE_INVALID_7c33082c,
      CozyText_Api_Text_0bc06c70);
end;

function JsonInteger(Obj: TJSONObject; const Name: string): Int64;
var
  Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONNumber) then
    raise EGameApi.Create(CozyText_Api_RESPONSE_INVALID_7c33082c,
      CozyText_Api_Text_63e20645);
  if not TryStrToInt64(Value.Value, Result) or (Result < 0) then
    raise EGameApi.Create(CozyText_Api_RESPONSE_INVALID_7c33082c,
      CozyText_Api_Text_9f015d49);
end;

function JsonTrue(Obj: TJSONObject; const Name: string): Boolean;
var
  Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  Result := (Value is TJSONBool) and (Value.Value = CozyText_Api_true_6c21d98e);
end;

function ErrorDescription(const Code: string): string;
begin
  if Code = CozyText_Api_DESKTOP_KEY_INVALID_7368322e then
    Exit(CozyText_Api_Text_71616e78);
  if Code = CozyText_Api_DESKTOP_KEY_USED_46deffda then
    Exit(CozyText_Api_Text_f0bbeba9);
  if Code = CozyText_Api_DESKTOP_REVOKED_661962ca then
    Exit(CozyText_Api_Text_a8c07451);
  if Code = CozyText_Api_DESKTOP_RELEASED_36e42d39 then
    Exit(CozyText_Api_Text_f3e46ffd);
  if Code = CozyText_Api_DESKTOP_EXPIRED_b6b3ee68 then
    Exit(CozyText_Api_Text_edc810c7);
  if Code = CozyText_Api_DESKTOP_DEVICE_MISMATCH_41fd9983 then
    Exit(CozyText_Api_Text_32af3b77);
  if Code = CozyText_Api_DESKTOP_ACTIVATION_INVALID_797d982e then
    Exit(CozyText_Api_Text_e2bf45d3);
  if Code = CozyText_Api_DESKTOP_PROOF_INVALID_0b662a1e then
    Exit(CozyText_Api_Text_f8e29556);
  if (Code = CozyText_Api_DESKTOP_RATE_LIMIT_1b0aaf4c) or (Code = CozyText_Api_DESKTOP_CAPACITY_cdec56f4) then
    Exit(CozyText_Api_Text_9757ef58);
  if Code = CozyText_Api_STORAGE_SAVE_FAILED_0de27f28 then
    Exit(CozyText_Api_verify_ba43c0c6);
  if (Code = CozyText_Api_NETWORK_UNAVAILABLE_bad73935) or (Code = CozyText_Api_SERVER_UNAVAILABLE_218c8e9e) then
    Exit(CozyText_Api_Text_7e4042dc);
  if (Code = CozyText_Api_LICENSE_NOT_FOUND_0fe2cc38) or (Code = CozyText_Api_LICENSE_KEY_INVALID_6126d5ed) or
    (Code = CozyText_Api_LICENSE_INVALID_40254b1e) then
    Exit(CozyText_Api_Text_71616e78);
  if (Code = CozyText_Api_LICENSE_EXPIRED_efcf4b27) then
    Exit(CozyText_Api_Text_edc810c7);
  if (Code = CozyText_Api_LICENSE_REVOKED_19e05c16) or (Code = CozyText_Api_LICENSE_DISABLED_bc026452) then
    Exit(CozyText_Api_Text_3b9a3fa9);
  if (Code = CozyText_Api_LICENSE_ALREADY_USED_22a6e1fa) or (Code = CozyText_Api_LICENSE_IN_USE_4d5b6a1e) or
    (Code = CozyText_Api_LICENSE_DEVICE_MISMATCH_dcee6322) or (Code = CozyText_Api_DEVICE_MISMATCH_29be812e) then
    Exit(CozyText_Api_Text_0d378b71);
  if (Code = CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394) or (Code = CozyText_Api_ACTIVATION_NOT_FOUND_38fe5b7a) or
    (Code = CozyText_Api_ACTIVATION_REVOKED_3e71b57b) or (Code = CozyText_Api_TOKEN_INVALID_54eb26e0) then
    Exit(CozyText_Api_Text_11b8d3a4);
  if (Code = CozyText_Api_RATE_LIMITED_87e1616b) or (Code = CozyText_Api_DESKTOP_RATE_LIMITED_e00faa3e) then
    Exit(CozyText_Api_Text_745e1447);
  if (Code = CozyText_Api_CHALLENGE_EXPIRED_7ad45ede) or (Code = CozyText_Api_DESKTOP_CHALLENGE_EXPIRED_bd352e6b) then
    Exit(CozyText_Api_Text_1592915b);
  if (Code = CozyText_Api_SERVICE_DISABLED_60b15675) then
    Exit(CozyText_Api_Text_a0b0229f);
  Result := CozyText_Api_Text_cf7744db + Code + ')';
end;

function RequestID: string;
var
  ID: TGUID;
begin
  if WindowsApiCreateGUID(ID) <> 0 then
    raise EGameApi.Create(CozyText_Api_REQUEST_ID_FAILED_7cc586ce,
      CozyText_Api_Text_a819bfcb);
  Result := LowerCase(Copy(GUIDToString(ID), 2, 36));
end;

function ComputerLabel: string;
var
  Buffer: array[0..255] of Char;
  Count: DWORD;
begin
  Count := DWORD(Length(Buffer));
  if GetComputerName(@Buffer[0], Count) then
    SetString(Result, PChar(@Buffer[0]), Integer(Count))
  else
    Result := CozyText_Api_Windows_PC_7f64a651;
  if Length(Result) > 80 then
    SetLength(Result, 80);
end;

function TGameApi.OwnRuntime(Security: TDeviceSecurity;
  CodeIntegrity: TCodeIntegrity): ICozyRuntimeMeasurement;
begin
  if FRuntimeGraph = nil then raise ECozyRuntimeGraph.Create(CozyText_Api_RUNTIME_GRAPH_REQUIRED_8db6bde0);
  { Registration is explicit and rejects replacement of a live binding.
    All captures occur inside this client's existing lifetime gate. }
  FRuntimeGraph.BindDependencies(Security, FImageIntegrity, CodeIntegrity);
  Result := FRuntimeGraph.Measurement(
    function: TCozyRuntimeBindings
    begin
      Result := CozyRuntimeBindings(Self, FGate, FTransport, Security,
        FImageIntegrity, CodeIntegrity);
    end);
end;

constructor TGameApi.Create(Profile: TConnectServerProfile;
  Security: TDeviceSecurity; const SessionID, SessionToken: string;
  ImageIntegrity: TImageIntegrity; CodeIntegrity: TCodeIntegrity;
  const CodeSHA512, CodeCRC64: string);
begin
  inherited Create;
  FSecurity := Security;
  FImageIntegrity := ImageIntegrity;
  FCodeIntegrity := CodeIntegrity;
  FGate := TGameCallGate.Create;
  FLock := TObject.Create;
  if (Profile = nil) or (Security = nil) or (ImageIntegrity = nil) or
    (CodeIntegrity = nil) or (SessionID = '') or (SessionToken = '') then
    raise EGameApi.Create(CozyText_Api_BOOTSTRAP_REQUIRED_eaf73372,
      CozyText_Api_A_6fb2a102);
  if not TRegEx.IsMatch(FSecurity.DeviceID, CozyText_Api_Pattern_67c2fa3e) then
    raise EGameApi.Create(CozyText_Api_DEVICE_ID_INVALID_6b6230a3, CozyText_Api_Text_0693b48a);
  FOverlayProfile := Profile.Clone;
  FTransport := TConnectTransport.Create(Profile);
  FRuntimeGraph := TCozyOwnedRuntimeGraph.Create(rpLicenseApi, Self, FGate, FTransport);
  FRuntimeGraph.BindDependencies(FSecurity, FImageIntegrity, FCodeIntegrity);
  FServerDisplayName := FTransport.DisplayEndpoint;
  FBootstrapSessionID := SessionID;
  FBootstrapSessionToken := SessionToken;
  FBoundImage := FImageIntegrity.VerifyNow;
  FBoundCodeSHA512 := CodeSHA512;
  FBoundCodeCRC64 := CodeCRC64;
  if not TRegEx.IsMatch(CodeSHA512, CozyText_Api_Pattern_b8863bd8) or
    not TRegEx.IsMatch(CodeCRC64, CozyText_Api_Pattern_2fa9066c) then
    raise EGameApi.Create(CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f, CozyText_Api_Invalid_authenticated_code_baseline_27ec04d1);
  FNextModules := CozyTick;
end;

function TGameApi.GetHasServerProfileCore: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    Result := Assigned(FTransport);
  finally
    TMonitor.Exit(FLock);
  end;
end;

procedure TGameApi.RequireServerProfile;
begin
  if not Assigned(FTransport) then
  begin
    FLastErrorCode := CozyText_Api_SERVER_PROFILE_REQUIRED_c8eed0ab;
    raise EGameApi.Create(CozyText_Api_SERVER_PROFILE_REQUIRED_c8eed0ab,
      CozyText_Api_A_c6a4461b);
  end;
end;

destructor TGameApi.Destroy;
begin
  RequestStopCore;
  if FGate <> nil then FGate.CloseAndWait;
  if FRuntimeGraph <> nil then
  begin
    try FRuntimeGraph.Close;
    except { Teardown still releases resources; no closed graph can be evidence. } end;
    FreeAndNil(FRuntimeGraph);
  end;
  FNHWAuthority := nil;
  FNHWGuard := nil;
  ClearModuleSnapshot;
  WipeText(FActivationToken);
  WipeText(FBootstrapSessionID);
  WipeText(FBootstrapSessionToken);
  ClearPending;
  FOverlayProfile.Free;
  FTransport.Free;
  FSecurity.Free;
  FImageIntegrity.Free;
  FCodeIntegrity.Free;
  FLock.Free;
  FGate.Free;
  inherited;
end;

function TGameApi.GetDeviceIDCore: string;
begin
  Result := FSecurity.DeviceID;
end;

function TGameApi.GetHasAuthorizationCore: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    Result := (FActivationToken <> '') or (FPendingAction <> '');
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TGameApi.GetCurrentCore: TLicenseState;
begin
  TMonitor.Enter(FLock);
  try
    Result := FCurrent;
  finally
    TMonitor.Exit(FLock);
  end;
end;

procedure TGameApi.AddIntegrityBoundSession(Body: TJSONObject);
begin
  { Authentication uses the last server-accepted identity, even when a new
    measurement fails. The signed payload describes the actual observation. }
  Body.AddPair(CozyText_Api_sessionId_853f6b3a, FBootstrapSessionID);
  Body.AddPair(CozyText_Api_sessionToken_1de43d9f, FBootstrapSessionToken);
  Body.AddPair(CozyText_Api_machineId_3117889a, FSecurity.MachineID);
  Body.AddPair(CozyText_Api_binarySha512_f63e79ae, FBoundImage.SHA512);
  Body.AddPair(CozyText_Api_binaryCrc64_d5a2c3b3, FBoundImage.CRC64);
  Body.AddPair(CozyText_Api_codeSha512_dc876766, FBoundCodeSHA512);
  Body.AddPair(CozyText_Api_codeCrc64_edb1d41f, FBoundCodeCRC64);
end;

function TGameApi.IntegritySubmitOverheadBytes: Integer;
var Envelope, Body: TJSONObject;
begin
  Envelope := TJSONObject.Create;
  try
    Envelope.AddPair(CozyText_Api_operation_9a9df433, CozyText_Api_report_2eb959c9);
    Envelope.AddPair(CozyText_Api_tlsPinVersion_0f5dfadf, TJSONNumber.Create(1));
    Body := TJSONObject.Create;
    Envelope.AddPair(CozyText_Api_body_2422e5c9, Body);
    AddIntegrityBoundSession(Body);
    Body.AddPair(CozyText_Api_action_a7b64efd, CozyText_Api_submit_b60bb019);
    { Protocol maxima, not an assumed ECDSA/report identifier encoding. }
    Body.AddPair(CozyText_Api_reportId_a121727c, StringOfChar('X', 160));
    Body.AddPair(CozyText_Api_signature_f5c615b8, StringOfChar('X', 1024));
    Body.AddPair(CozyText_Api_payload_72cc18dd, '');
    { Exclude the empty payload string's two quotes; the packing calculation
      supplies the encoded JSON string including both quotes. }
    Result := TEncoding.UTF8.GetByteCount(Envelope.ToJSON) - 2;
  finally
    Envelope.Free;
  end;
end;

procedure TGameApi.SendIntegrityReport(Payload: TJSONObject;
  const Cancelled: TAuthorityCancelled);
var ChallengeBody, Challenge, SubmitBody, Reply: TJSONObject;
  ReportID, Nonce, Text, Canonical: string;
  ExpiresAt: Int64;
  StartedAt: UInt64;

begin
  if Assigned(Cancelled) and Cancelled() then
    raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
  ChallengeBody := TJSONObject.Create;
  Challenge := nil;
  SubmitBody := nil;
  Reply := nil;
  try
    { This anchor covers the challenge, submit, and every exact transport
      retry. A cached receipt must never gain a new local time window. }
    StartedAt := CozyTick;
    Payload.AddPair(CozyText_Api_hashVersion_6d224b4f, TJSONNumber.Create(3));
    Text := Payload.ToJSON;
    if TEncoding.UTF8.GetByteCount(Text) > ModulePayloadMaximum then
      raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, CozyText_Api_Report_exceeds_its_bound_b11981a5);
    AddIntegrityBoundSession(ChallengeBody);
    ChallengeBody.AddPair(CozyText_Api_action_a7b64efd, CozyText_Api_challenge_1e1bb128);
    Challenge := PostJSON(CozyText_Api_report_2eb959c9, ChallengeBody, False, Cancelled);
    if Assigned(Cancelled) and Cancelled() then
      raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
    ReportID := JsonString(Challenge, CozyText_Api_reportId_a121727c);
    Nonce := JsonString(Challenge, CozyText_Api_nonce_3c39b97d);
    ExpiresAt := JsonInteger(Challenge, CozyText_Api_expiresAt_519a6450);
    if not TRegEx.IsMatch(ReportID, CozyText_Api_Pattern_23f9cb7d) or
      not TRegEx.IsMatch(Nonce, CozyText_Api_Pattern_9cabc583) or
      (ExpiresAt <= 0) then
      raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, CozyText_Api_Invalid_report_challenge_1b82cf1a);
    Canonical := CozyText_Api_GAME_INTEGRITY_REPORT_V2_25fd5853 + #10 + FBootstrapSessionID + #10 +
      ReportID + #10 + Nonce + #10 + IntToStr(ExpiresAt) + #10 + IntegritySHA512Text(Text);
    SubmitBody := TJSONObject.Create;
    AddIntegrityBoundSession(SubmitBody);
    SubmitBody.AddPair(CozyText_Api_action_a7b64efd, CozyText_Api_submit_b60bb019);
    SubmitBody.AddPair(CozyText_Api_reportId_a121727c, ReportID);
    SubmitBody.AddPair(CozyText_Api_payload_72cc18dd, Text);
    if Assigned(Cancelled) and Cancelled() then
      raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
    SubmitBody.AddPair(CozyText_Api_signature_f5c615b8, FSecurity.Sign(Canonical));
    Reply := PostJSON(CozyText_Api_report_2eb959c9, SubmitBody, True, Cancelled);
    if Assigned(Cancelled) and Cancelled() then
      raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
    if not JsonTrue(Reply, CozyText_Api_accepted_3194d58e) then
      raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, CozyText_Api_Integrity_report_was_not_accepted_3699d2c9);
    if JsonTrue(Reply, CozyText_Api_terminate_67d71b83) or (JsonString(Reply, CozyText_Api_status_5b6d5c76) = CozyText_Api_REJECTED_ed32f000) then
    begin
      FCurrent := Default(TLicenseState);
      FLastErrorCode := CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f;
      raise EGameApi.Create(CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f, CozyText_Api_Server_rejected_image_integrity_9cd6cafb);
    end;
    if (JsonString(Payload, CozyText_Api_check_73cb80a0) = CozyText_Api_MODULE_INVENTORY_6b4ac364) and
      (JsonInteger(Payload, CozyText_Api_batchIndex_10fbd448) + 1 =
       JsonInteger(Payload, CozyText_Api_batchCount_cf30cc7e)) then
      ApplyModuleSnapshotBudget(Reply, StartedAt);
  finally
    { SubmitBody shares the serialized string. Release its reference before
      WipeText: otherwise UniqueString wipes a fresh copy while the JSON owner
      still retains the original plaintext allocation. }
    try
      Reply.Free;
      SubmitBody.Free;
      Challenge.Free;
      ChallengeBody.Free;
    finally
      WipeText(Text);
      WipeText(Canonical);
      WipeText(Nonce);
      WipeText(ReportID);
    end;
  end;
end;

procedure TGameApi.ReportMeasurementFailure(Status: TMeasurementStatus);
var Payload, Own: TJSONObject;
begin
  Payload := TJSONObject.Create;
  try
    Payload.AddPair(CozyText_Api_version_edcaca86, TJSONNumber.Create(1));
    Payload.AddPair(CozyText_Api_check_73cb80a0, CozyText_Api_OWN_IMAGE_a1cda560);
    Payload.AddPair(CozyText_Api_reason_9ed63c85, CozyText_Api_MEASUREMENT_FAILED_5762724e);
    Own := TJSONObject.Create;
    Own.AddPair(CozyText_Api_status_5b6d5c76, MeasurementStatusName(Status));
    Payload.AddPair(CozyText_Api_own_a6da0945, Own);
    try
      SendIntegrityReport(Payload);
    except
      { Network failure cannot turn failed evidence into permission to run. }
    end;
  finally
    Payload.Free;
  end;
end;

procedure TGameApi.ReportOverlayFailure(const Reason: string);
var Payload: TJSONObject;
begin
  { No local log or UI: only bounded codes use the existing signed B session. }
  try
    Payload := TJSONObject.Create;
    try
      Payload.AddPair(CozyText_Api_version_edcaca86, TJSONNumber.Create(1));
      Payload.AddPair(CozyText_Api_check_73cb80a0, CozyText_Api_OVERLAY_START_b6fd3d2d);
      Payload.AddPair(CozyText_Api_reason_9ed63c85, Reason);
      SendIntegrityReport(Payload);
    finally
      Payload.Free;
    end;
  except
    { Best-effort diagnostics must preserve the original startup failure. }
  end;
end;

procedure TGameApi.MeasureOwn(out Image: TImageDigest;
  out Code: TCodeIntegrityMeasurement);
var Budget: TMeasurementBudget;
begin
  Budget := TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
    function: Boolean
    begin Result := (InterlockedCompareExchange(FStopRequested, 0, 0) <> 0) or NHWStopConfirmed; end);
  try
    Image := FImageIntegrity.VerifyNow(Budget);
    Code := FCodeIntegrity.MeasureNow(Budget);
  except
    on E: Exception do
    begin
      ReportMeasurementFailure(MeasurementFailureStatus(E));
      raise EGameApi.Create(CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f, CozyText_Api_Image_measurement_failed_06492857);
    end;
  end;
end;

procedure TGameApi.ClearModuleSnapshot;
begin
  FreeAndNil(FModuleSnapshot);
  FModuleSnapshotID := '';
  FModuleNextIndex := 0;
  FModuleBatchIndex := 0;
  FModuleBatchCount := 0;
  FModuleBatchSize := 0;
end;

procedure TGameApi.RequireModuleSnapshotLease;
begin
  { A complete report grants no license authority. This separate deadline
    only bounds use of the already accepted module observation. }
  if (FModuleDeadlineTick <> 0) and (FModuleDeadlineTick <= CozyTick) then
    raise EGameApi.Create(CozyText_Api_INTEGRITY_SNAPSHOT_STALE_9b2efe72, '');
end;

procedure TGameApi.ApplyModuleSnapshotBudget(Reply: TJSONObject; StartedAt: UInt64);
var Value: TJSONValue; Budget: TJSONObject;
  ServerTime, ExpiresAt, Duration: Int64;
  At, Elapsed, Deadline: UInt64;
  SnapshotID: string;
begin
  Value := Reply.GetValue(CozyText_Api_snapshotBudget_872fe930);
  if not (Value is TJSONObject) then
    raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, '');
  Budget := TJSONObject(Value);
  SnapshotID := JsonString(Budget, CozyText_Api_snapshotId_840c328a);
  ServerTime := JsonInteger(Budget, CozyText_Api_serverTime_ac0470bc);
  ExpiresAt := JsonInteger(Budget, CozyText_Api_expiresAt_519a6450);
  if (JsonInteger(Budget, CozyText_Api_version_edcaca86) <> 1) or
    (SnapshotID = '') or (SnapshotID <> FModuleSnapshotID) or
    (ServerTime <= 0) or (ExpiresAt <= ServerTime) or
    (ExpiresAt - ServerTime > MaxLeaseMilliseconds) then
    raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, '');
  Duration := ExpiresAt - ServerTime;
  At := CozyTick;
  if At < StartedAt then
    raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, '');
  Elapsed := At - StartedAt;
  if Elapsed >= UInt64(Duration) then
    raise EGameApi.Create(CozyText_Api_INTEGRITY_SNAPSHOT_STALE_9b2efe72, '');
  RequireModuleSnapshotLease;
  Deadline := At + UInt64(Duration) - Elapsed;
  if SnapshotID = FModuleReceiptID then
  begin
    { Exact replay can only preserve or shorten the first monotonic mapping. }
    if (ServerTime <> FModuleReceiptServerTime) or
      (ExpiresAt <> FModuleReceiptExpiresAt) then
      raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, '');
    if Deadline < FModuleDeadlineTick then FModuleDeadlineTick := Deadline;
    Exit;
  end;
  if ServerTime < FModuleReceiptServerTime then
    raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, '');
  FModuleReceiptID := SnapshotID;
  FModuleReceiptServerTime := ServerTime;
  FModuleReceiptExpiresAt := ExpiresAt;
  FModuleDeadlineTick := Deadline;
end;

function TGameApi.CreateModulePayload(BatchIndex, BatchCount: Integer): TJSONObject;
var Payload: TJSONObject;
  procedure AddMetadata(const Name: string);
  var Meta: TJSONValue;
  begin
    Meta := FModuleSnapshot.GetValue(Name);
    if Meta <> nil then Payload.AddPair(Name, TJSONValue(Meta.Clone));
  end;
begin
  Payload := TJSONObject.Create;
  try
    Payload.AddPair(CozyText_Api_version_edcaca86, TJSONNumber.Create(1));
    Payload.AddPair(CozyText_Api_check_73cb80a0, CozyText_Api_MODULE_INVENTORY_6b4ac364);
    Payload.AddPair(CozyText_Api_reason_9ed63c85, CozyText_Api_PERIODIC_c91b2405);
    Payload.AddPair(CozyText_Api_snapshotId_840c328a, FModuleSnapshotID);
    Payload.AddPair(CozyText_Api_batchIndex_10fbd448, TJSONNumber.Create(BatchIndex));
    Payload.AddPair(CozyText_Api_batchCount_cf30cc7e, TJSONNumber.Create(BatchCount));
    AddMetadata(CozyText_Api_complete_8da1b623);
    AddMetadata(CozyText_Api_truncated_744f21d1);
    AddMetadata(CozyText_Api_totalModules_e6e48497);
    AddMetadata(CozyText_Api_measuredModules_9b4c96c7);
    AddMetadata(CozyText_Api_scope_fb032832);
    AddMetadata(CozyText_Api_trust_190cf8eb);
    AddMetadata(CozyText_Api_measurementContract_afb97f46);
    AddMetadata(CozyText_Api_measurementPlanVersion_2590335d);
    AddMetadata(CozyText_Api_measurementStartedTick_9c04910f);
    AddMetadata(CozyText_Api_measurementFinishedTick_ae874b0c);
    AddMetadata(CozyText_Api_moduleGenerationStable_bb4b09ef);
    AddMetadata(CozyText_Api_moduleGenerationStatus_722cc8c3);
    AddMetadata(CozyText_Api_threadInventory_267c3eb8);
    AddMetadata(CozyText_Api_deviceSignals_36203103);
    AddMetadata(CozyText_Api_coverage_bd2f2d35);
    Result := Payload;
  except
    Payload.Free;
    raise;
  end;
end;

function TGameApi.ReportModulesIfDue: Boolean;
var
  Payload: TJSONObject;
  Modules: TJSONValue;
  Batch: TJSONArray;
  Total, I, Bytes, LargestModuleBytes, MetadataBytes: Integer;
  LargestEncodedModuleBytes, EncodedMetadataBytes, SubmitOverhead: Integer;
  NowTick, Reserved: UInt64;
  function EncodedStringBytes(const Text: string): Integer;
  var Value: TJSONString;
  begin
    Value := TJSONString.Create(Text);
    try Result := TEncoding.UTF8.GetByteCount(Value.ToJSON);
    finally Value.Free; end;
  end;
begin
  Result := False;
  RequireRunning;
  if (FModuleSnapshot = nil) and (FNHWGuard <> nil) and
    FNHWGuard.ConsumeRevalidationRequest then
  begin
    { The sole API worker owns file readers and inventory state. A coverage
      warning requests a fresh measurement, never grants permission or extends
      the existing lease. Finish any in-flight inventory before consuming it. }
    CheckIntegrityCore;
    FNextModules := 0;
  end;
  if (FModuleSnapshot = nil) and (CozyTick < FNextModules) then Exit;
  RequireModuleSnapshotLease;
  try
    if FModuleSnapshot = nil then
    begin
      NowTick := CozyTick;
      if FModuleGenerationRetries = 0 then FModuleGenerationStarted := NowTick;
      if (NowTick < FModuleGenerationStarted) or
        (NowTick - FModuleGenerationStarted >= ModuleGenerationRetryMilliseconds) then
        raise Exception.Create(CozyText_Api_Module_inventory_unavailable_9b3a2db5);
      FModuleSnapshot := CollectModuleInventoryJSON(
        function: Boolean
        var At: UInt64;
        begin
          { StopAndJoin signals RequestStopCore without entering the API lock.
            The collector observes it between files; Self stays alive until
            the worker is joined. No callback or token is persisted. }
          At := CozyTick;
          Result := (InterlockedCompareExchange(FStopRequested, 0, 0) <> 0) or NHWStopConfirmed or
            (At < FModuleGenerationStarted) or
            (At - FModuleGenerationStarted >= ModuleGenerationRetryMilliseconds) or
            ((FModuleDeadlineTick <> 0) and (At >= FModuleDeadlineTick)) or
            ((FCurrent.LeaseDeadlineTick <> 0) and (At >= FCurrent.LeaseDeadlineTick));
        end, FImageIntegrity, FCodeIntegrity);
      if FModuleSnapshot = nil then
        raise Exception.Create(CozyText_Api_Module_inventory_unavailable_9b3a2db5);
      Modules := FModuleSnapshot.GetValue(CozyText_Api_modules_18634d83);
      if not (Modules is TJSONArray) or (TJSONArray(Modules).Count > 1024) then
        raise Exception.Create(CozyText_Api_Invalid_module_inventory_12dbfc0e);
      Total := TJSONArray(Modules).Count;
      NowTick := CozyTick;
      if (FModuleGenerationRetries < ModuleGenerationRetryLimit) and
        (NowTick >= FModuleGenerationStarted) and
        (NowTick - FModuleGenerationStarted < ModuleGenerationRetryMilliseconds) and
        ModuleInventoryGenerationRetryable(FModuleSnapshot) then
      begin
        { GPU/driver DLLs may finish loading while the first full scan runs.
          A loader race is not a coherent snapshot: discard ALL its hashes and
          remeasure before sending any batch. Real differences/read failures
          are reported unchanged; exhausted retries still report the partial
          inventory and receive the existing fail-closed server decision. }
        Inc(FModuleGenerationRetries);
        FModuleSnapshotCompleted := False;
        ClearModuleSnapshot;
        FNextModules := NowTick;
        Exit(True);
      end;
      FModuleSnapshotID := RequestID;
      FModuleNextIndex := 0;
      FModuleBatchIndex := 0;
      { Use the existing server maximum of 16 rows without guessing at JSON
        size. Reserve the exact metadata, longest possible batch counters,
        UTF-8 bytes of the largest observed row and every separating comma.
        Also reserve JSON-string escaping inside the signed request envelope;
        quotes / Unicode in names cannot exceed the outer transport limit.
        One uniform size fixes batchCount before the first signed request. }
      Payload := CreateModulePayload(255, 256);
      try
        Payload.AddPair(CozyText_Api_hashVersion_6d224b4f, TJSONNumber.Create(3));
        Payload.AddPair(CozyText_Api_modules_18634d83, TJSONArray.Create);
        MetadataBytes := TEncoding.UTF8.GetByteCount(Payload.ToJSON);
        EncodedMetadataBytes := EncodedStringBytes(Payload.ToJSON);
      finally
        Payload.Free;
      end;
      SubmitOverhead := IntegritySubmitOverheadBytes;
      LargestModuleBytes := 0;
      LargestEncodedModuleBytes := 0;
      for I := 0 to Total - 1 do
      begin
        Bytes := TEncoding.UTF8.GetByteCount(TJSONArray(Modules).Items[I].ToJSON);
        if Bytes > LargestModuleBytes then LargestModuleBytes := Bytes;
        Bytes := EncodedStringBytes(TJSONArray(Modules).Items[I].ToJSON) - 2;
        if Bytes > LargestEncodedModuleBytes then LargestEncodedModuleBytes := Bytes;
      end;
      FModuleBatchSize := ModuleBatchMaximum;
      while (FModuleBatchSize > 0) and
        ((Int64(MetadataBytes) + Int64(LargestModuleBytes + 1) * FModuleBatchSize > ModulePayloadMaximum) or
         (Int64(SubmitOverhead) + EncodedMetadataBytes +
          Int64(LargestEncodedModuleBytes + 1) * FModuleBatchSize > ModuleEnvelopeMaximum)) do
        Dec(FModuleBatchSize);
      if FModuleBatchSize < 1 then
        raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, '');
      FModuleBatchCount := (Total + FModuleBatchSize - 1) div FModuleBatchSize;
      if FModuleBatchCount = 0 then FModuleBatchCount := 1;
      if FModuleBatchCount > 256 then
        raise EGameApi.Create(CozyText_Api_DESKTOP_REPORT_INVALID_e5d7008f, '');
    end;
    RequireRunning;
    RequireModuleSnapshotLease;
    Modules := FModuleSnapshot.GetValue(CozyText_Api_modules_18634d83);
    Total := TJSONArray(Modules).Count;
    Payload := CreateModulePayload(FModuleBatchIndex, FModuleBatchCount);
    try
      Batch := TJSONArray.Create;
      Payload.AddPair(CozyText_Api_modules_18634d83, Batch);
      while (FModuleNextIndex < Total) and (Batch.Count < FModuleBatchSize) do
      begin
        Batch.AddElement(TJSONValue(TJSONArray(Modules).Items[FModuleNextIndex].Clone));
        Inc(FModuleNextIndex);
      end;
      { One bounded batch per call. The worker can service key submission and
        renew the own-image/license lease between module report requests. }
      SendIntegrityReport(Payload);
      RequireModuleSnapshotLease;
    finally
      Payload.Free;
    end;
    Inc(FModuleBatchIndex);
    Result := FModuleBatchIndex < FModuleBatchCount;
    if not Result then
    begin
      NowTick := CozyTick;
      if (NowTick < FModuleGenerationStarted) or
        (FModuleDeadlineTick <= NowTick) then
        raise EGameApi.Create(CozyText_Api_INTEGRITY_SNAPSHOT_STALE_9b2efe72, '');
      { Include collection, every signed batch, and interleaved own-image /
        lease checks. Begin the next full cycle before it can consume the
        remaining snapshot budget; never wait for the old fixed 60 s alone. }
      FModuleCycleMilliseconds := NowTick - FModuleGenerationStarted;
      Reserved := FModuleCycleMilliseconds + ModuleSnapshotCheckpointReserve;
      FNextModules := NowTick + ModuleSnapshotInterval;
      if FModuleDeadlineTick - NowTick <= Reserved then FNextModules := NowTick
      else if FModuleDeadlineTick - Reserved < FNextModules then
        FNextModules := FModuleDeadlineTick - Reserved;
      FModuleSnapshotCompleted := True;
      FModuleGenerationRetries := 0;
      FModuleGenerationStarted := 0;
      ClearModuleSnapshot;
    end;
  except
    on E: EGameApi do
    begin
      ClearModuleSnapshot;
      raise;
    end;
    on Exception do
    begin
      ClearModuleSnapshot;
      FNextModules := CozyTick + ModuleSnapshotInterval;
      { Do not silently treat a failed inventory as a completed snapshot. }
      raise EGameApi.Create(CozyText_Api_DESKTOP_MODULE_INVENTORY_INVALID_a6d11253,
        CozyText_Api_Module_inventory_could_not_be_measured_2fc0fe29);
    end;
  end;
end;

function TGameApi.ContinueModuleInventoryCore: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    Result := ReportModulesIfDue;
  finally
    TMonitor.Exit(FLock);
  end;
end;

procedure TGameApi.RequestStopCore;
begin
  { This never waits for the proof lock or touches CNG/network objects. }
  InterlockedExchange(FStopRequested, 1);
end;

function TGameApi.NHWStopConfirmed: Boolean;
begin
  Result := (FNHWGuard <> nil) and FNHWGuard.Confirmed;
end;

procedure TGameApi.RequireRunning;
begin
  if (InterlockedCompareExchange(FStopRequested, 0, 0) <> 0) or NHWStopConfirmed then
    raise EGameApi.Create(CozyText_Api_CLIENT_STOPPING_99bc92f1, CozyText_Api_Session_is_closing_e8e98ec3);
end;

procedure TGameApi.CheckIntegrityCore(const Cancelled: TAuthorityCancelled);
var Image: TImageDigest; Code: TCodeIntegrityMeasurement;
  Payload, Own, Layers, Bundle: TJSONObject; Status: TMeasurementStatus;
begin
  TMonitor.Enter(FLock);
  try
    if Assigned(Cancelled) and Cancelled() then
      raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
    Layers := nil; Bundle := nil; Payload := nil;
    try
      Status := msNotMeasured; Image := Default(TImageDigest);
      Code := Default(TCodeIntegrityMeasurement);
      Bundle := CollectOwnMeasurement(FImageIntegrity, FCodeIntegrity,
        TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
          function: Boolean
          begin Result := FGate.IsClosing or
            (InterlockedCompareExchange(FStopRequested, 0, 0) <> 0) or NHWStopConfirmed or
            (Assigned(Cancelled) and Cancelled()); end),
        Image, Code, Layers, Status, OwnRuntime(FSecurity, FCodeIntegrity));
      if (Status = msMeasured) and not OwnMeasurementComplete(Bundle, Image, Code, Layers, Status) then
      begin Status := msCoverageInsufficient; FreeAndNil(Bundle); end;
      if Assigned(Cancelled) and Cancelled() then
        raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
      Payload := TJSONObject.Create;
      Payload.AddPair(CozyText_Api_version_edcaca86, TJSONNumber.Create(1));
      Payload.AddPair(CozyText_Api_check_73cb80a0, CozyText_Api_OWN_IMAGE_a1cda560);
      if Status = msMeasured then Payload.AddPair(CozyText_Api_reason_9ed63c85, CozyText_Api_PERIODIC_c91b2405)
      else Payload.AddPair(CozyText_Api_reason_9ed63c85, CozyText_Api_MEASUREMENT_FAILED_5762724e);
      Own := TJSONObject.Create; Payload.AddPair(CozyText_Api_own_a6da0945, Own);
      Own.AddPair(CozyText_Api_status_5b6d5c76, MeasurementStatusName(Status));
      if Status = msMeasured then
      begin
        Own.AddPair(CozyText_Api_fileSha512_75b0f42d, Image.SHA512); Own.AddPair(CozyText_Api_fileCrc64_6df83a91, Image.CRC64);
        Own.AddPair(CozyText_Api_codeSha512_dc876766, Code.SHA512); Own.AddPair(CozyText_Api_codeCrc64_edb1d41f, Code.CRC64);
        Own.AddPair(CozyText_Api_fileXxh3_128_776d82de, Image.XXH3_128); Own.AddPair(CozyText_Api_fileBlake3_a9a49431, Image.Blake3);
        Own.AddPair(CozyText_Api_codeXxh3_128_dfad56f5, Code.XXH3_128); Own.AddPair(CozyText_Api_codeBlake3_70bf223e, Code.Blake3);
      end;
      if Layers <> nil then begin Payload.AddPair(CozyText_Api_crcLayers_e725ed1c, Layers); Layers := nil; end;
      if Bundle <> nil then begin Payload.AddPair(CozyText_Api_ownMeasurement_d9d850bd, Bundle); Bundle := nil; end;
      SendIntegrityReport(Payload, Cancelled);
      if Status <> msMeasured then
        raise EGameApi.Create(CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f, CozyText_Api_Image_measurement_failed_06492857);
      { Bootstrap sensors already run independently. Start their authenticated
        report workers after the first accepted proof, before license entry. }
      if FNHWAuthority <> nil then
        FNHWAuthority.ConfigureResponses(FTransport, FSecurity, 'B',
          FBootstrapSessionID, FBootstrapSessionToken);
    finally Bundle.Free; Layers.Free; Payload.Free; end;
  finally TMonitor.Exit(FLock); end;
end;

procedure TGameApi.AddBootstrapSession(Payload: TJSONObject);
var Digest: TImageDigest; Code: TCodeIntegrityMeasurement;
begin
  MeasureOwn(Digest, Code);
  Payload.AddPair(CozyText_Api_bootstrapSessionId_95160bd3, FBootstrapSessionID);
  Payload.AddPair(CozyText_Api_bootstrapSessionToken_8157afed, FBootstrapSessionToken);
  Payload.AddPair(CozyText_Api_machineId_3117889a, FSecurity.MachineID);
  Payload.AddPair(CozyText_Api_binarySha512_f63e79ae, Digest.SHA512);
  Payload.AddPair(CozyText_Api_binaryCrc64_d5a2c3b3, Digest.CRC64);
  Payload.AddPair(CozyText_Api_codeSha512_dc876766, Code.SHA512);
  Payload.AddPair(CozyText_Api_codeCrc64_edb1d41f, Code.CRC64);
end;

procedure TGameApi.ClearPending;
begin
  WipeText(FPendingAction);
  WipeText(FPendingRequestID);
  WipeText(FPendingPayloadJSON);
end;

procedure TGameApi.PreparePending(const Action: string;
  Payload: TJSONObject);
var
  NextID, NextPayload: string;
begin
  if FPendingAction <> '' then
    raise EGameApi.Create(CozyText_Api_PENDING_OPERATION_f345beda,
      CozyText_Api_verify_cfdb221d);
  NextID := RequestID;
  NextPayload := Payload.ToJSON;
  FPendingRequestID := NextID;
  FPendingPayloadJSON := NextPayload;
  FPendingAction := Action;
  // Exact retry data lives only in this process. No receipt is written locally.
end;

function TGameApi.ResumePending: TLicenseState;
var
  Data: TJSONObject;
  Token: string;
begin
  if FPendingAction = '' then
    raise EGameApi.Create(CozyText_Api_PENDING_OPERATION_MISSING_74a69c39,
      CozyText_Api_Text_0832d1c7);
  Data := ExecuteProof(FPendingAction, FPendingPayloadJSON,
    FPendingRequestID);
  try
    if FPendingAction = CozyText_Api_release_dca62424 then
    begin
      if (JsonString(Data, CozyText_Api_status_5b6d5c76) <> CozyText_Api_USED_f24e3598) or
        not JsonTrue(Data, CozyText_Api_released_64258304) or
        (JsonString(Data, CozyText_Api_deviceId_017320c2) <> FSecurity.DeviceID) then
        raise EGameApi.Create(CozyText_Api_RELEASE_RESPONSE_INVALID_4c87df03,
          CozyText_Api_Text_ecd8e220);
      WipeText(FActivationToken);
      ClearPending;
      Result := Default(TLicenseState);
      Result.Status := CozyText_Api_USED_f24e3598;
      FCurrent := Result;
      Exit;
    end;
    // A redemption receipt may be older than its short lease after a lost
    // response. Validate its identity, keep the token in RAM, then obtain a fresh
    // signed verification. A replay never authorizes from an expired lease.
    if (JsonString(Data, CozyText_Api_status_5b6d5c76) <> CozyText_Api_USED_f24e3598) or
      (JsonString(Data, CozyText_Api_deviceId_017320c2) <> FSecurity.DeviceID) or
      not TRegEx.IsMatch(JsonString(Data, CozyText_Api_licenseId_d119b21e), CozyText_Api_Pattern_aee8d3e4) then
      raise EGameApi.Create(CozyText_Api_LICENSE_RESPONSE_INVALID_0053ab4b,
        CozyText_Api_Text_c3f33356);
    Token := JsonString(Data, CozyText_Api_activationToken_43b27685);
    if not TRegEx.IsMatch(Token, CozyText_Api_Pattern_22fd33b1) then
      raise EGameApi.Create(CozyText_Api_TOKEN_INVALID_54eb26e0,
        ErrorDescription(CozyText_Api_TOKEN_INVALID_54eb26e0));
    FActivationToken := Token;
    ClearPending;
    Result := VerifyCore;
  finally
    Data.Free;
    WipeText(Token);
  end;
end;

procedure TGameApi.FailOperation(const Code: string);
begin
  FCurrent := Default(TLicenseState);
  FLastErrorCode := Code;
  if (Code = CozyText_Api_DESKTOP_KEY_INVALID_7368322e) or (Code = CozyText_Api_DESKTOP_KEY_USED_46deffda) or
    (Code = CozyText_Api_DESKTOP_REVOKED_661962ca) or (Code = CozyText_Api_DESKTOP_RELEASED_36e42d39) or
    (Code = CozyText_Api_DESKTOP_EXPIRED_b6b3ee68) or (Code = CozyText_Api_DESKTOP_ACTIVATION_INVALID_797d982e) or
    (Code = CozyText_Api_DESKTOP_DEVICE_MISMATCH_41fd9983) then
  begin
    // Only a definitive server rejection may discard a pending receipt.
    // Transient failures retain it for a fresh proof with the same request ID.
    ClearPending;
    if (Code <> CozyText_Api_DESKTOP_KEY_INVALID_7368322e) and (Code <> CozyText_Api_DESKTOP_KEY_USED_46deffda) then
      WipeText(FActivationToken);
  end;
end;

function TGameApi.PostJSON(const Operation: string;
  Body: TJSONObject; ExactTransportRetry: Boolean;
  const Cancelled: TAuthorityCancelled): TJSONObject;
var
  Response: TJSONObject;
  OkValue, DataValue: TJSONValue;
  Code: string;
  Retryable: Boolean;
  Attempt, Attempts: Integer;
  Deadline, NowTick: UInt64;
  Budget: Cardinal;
begin
  RequireRunning;
  if Assigned(Cancelled) and Cancelled() then
    raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
  RequireServerProfile;
  Response := nil;
  try
    try
      Attempts := 1;
      if ExactTransportRetry then Attempts := 2;
      Deadline := CozyTick + 15000;
      for Attempt := 1 to Attempts do
      begin
        RequireRunning;
        if Assigned(Cancelled) and Cancelled() then
          raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
        NowTick := CozyTick;
        if NowTick >= Deadline then
          raise EConnectTransport.Create(CozyText_Api_CONNECT_TIMEOUT_d0dd2772, CozyText_Api_Request_retry_deadline_expired_f15f3bab);
        Budget := Cardinal(Deadline - NowTick);
        try
          { Reuse the immutable logical request, payload and signature. Only
            the transport envelope nonce changes. Responses are parsed later. }
          Response := FTransport.PostJSON(Operation, Body, Budget);
          if Assigned(Cancelled) and Cancelled() then
            raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
          Break;
        except
          on E: EConnectTransport do
            if (Attempt = Attempts) or
              ((E.Code <> CozyText_Api_CONNECT_TIMEOUT_d0dd2772) and (E.Code <> CozyText_Api_CONNECT_UNAVAILABLE_84dc2a9f) and
               (E.Code <> CozyText_Api_CONNECT_SEND_FAILED_a8fbf652) and (E.Code <> CozyText_Api_CONNECT_RECEIVE_FAILED_0d3884c0) and
               (E.Code <> CozyText_Api_NETWORK_UNAVAILABLE_bad73935)) then raise;
        end;
      end;
    except
      on E: EGameApi do raise;
      on E: EConnectTransport do
        raise EGameApi.Create(E.Code, E.Message,
          (E.Code = CozyText_Api_CONNECT_TIMEOUT_d0dd2772) or
          (E.Code = CozyText_Api_CONNECT_UNAVAILABLE_84dc2a9f) or
          (E.Code = CozyText_Api_NETWORK_UNAVAILABLE_bad73935));
      on E: Exception do
        raise EGameApi.Create(CozyText_Api_NETWORK_UNAVAILABLE_bad73935,
          ErrorDescription(CozyText_Api_NETWORK_UNAVAILABLE_bad73935), True);
    end;
    if Response = nil then
      raise EGameApi.Create(CozyText_Api_SERVER_UNAVAILABLE_218c8e9e,
        ErrorDescription(CozyText_Api_SERVER_UNAVAILABLE_218c8e9e), True);
    OkValue := Response.GetValue(CozyText_Api_ok_23bc0a4e);
    if not (OkValue is TJSONBool) or (OkValue.Value <> CozyText_Api_true_6c21d98e) then
    begin
      Code := JsonString(Response, CozyText_Api_error_86fcd5bb, False);
      if Code = '' then
        Code := JsonString(Response, CozyText_Api_reason_9ed63c85, False);
      if not TRegEx.IsMatch(Code, CozyText_Api_Pattern_da1e7df9) then
        Code := CozyText_Api_SERVER_RESPONSE_INVALID_bc45605f;
      Retryable := (Code = CozyText_Api_DESKTOP_RATE_LIMIT_1b0aaf4c) or
        (Code = CozyText_Api_DESKTOP_CAPACITY_cdec56f4) or (Code = CozyText_Api_STORAGE_SAVE_FAILED_0de27f28) or
        (Code = CozyText_Api_SERVICE_DISABLED_60b15675) or (Code = CozyText_Api_DESKTOP_CHALLENGE_EXPIRED_bd352e6b);
      raise EGameApi.Create(Code, ErrorDescription(Code), Retryable);
    end;
    DataValue := Response.GetValue(CozyText_Api_data_e477ee02);
    if not (DataValue is TJSONObject) then
      raise EGameApi.Create(CozyText_Api_RESPONSE_INVALID_7c33082c,
        CozyText_Api_Text_0bc06c70);
    Result := TJSONObject(DataValue.Clone);
  finally
    Response.Free;
  end;
end;

function TGameApi.ExecuteProof(const Action: string;
  const PayloadText: string; const RetryID: string): TJSONObject;
var
  ChallengeBody, Challenge, ExecuteBody: TJSONObject;
  ID, PayloadHash, ChallengeID, Nonce, Canonical, SecurityIntent: string;
  ExpiresAt: Int64;
  CurrentImage: TImageDigest;
  CurrentCode: TCodeIntegrityMeasurement;
  ParsedPayload: TJSONValue;
begin
  ID := RetryID;
  if ID = '' then
    ID := RequestID;
  { Recheck the held image on every proof, including an idempotent retry.
    CRC is error detection; SHA-512 and server-side session checks enforce it. }
  MeasureOwn(CurrentImage, CurrentCode);
  if (CurrentImage.SHA512 = '') or (CurrentImage.CRC64 = '') then
    raise EGameApi.Create(CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f, CozyText_Api_Image_integrity_unavailable_1d286b86);
  { Never replay an earlier healthy measurement after code or file changes. }
  ParsedPayload := TJSONObject.ParseJSONValue(PayloadText);
  try
    if not (ParsedPayload is TJSONObject) or
      (JsonString(TJSONObject(ParsedPayload), CozyText_Api_binarySha512_f63e79ae) <> CurrentImage.SHA512) or
      (JsonString(TJSONObject(ParsedPayload), CozyText_Api_binaryCrc64_d5a2c3b3) <> CurrentImage.CRC64) or
      (JsonString(TJSONObject(ParsedPayload), CozyText_Api_codeSha512_dc876766) <> CurrentCode.SHA512) or
      (JsonString(TJSONObject(ParsedPayload), CozyText_Api_codeCrc64_edb1d41f) <> CurrentCode.CRC64) then
    begin
      ReportMeasurementFailure(msChanged);
      raise EGameApi.Create(CozyText_Api_DESKTOP_INTEGRITY_INVALID_1875198f, CozyText_Api_Measurement_changed_during_proof_403d04ba);
    end;
  finally
    ParsedPayload.Free;
  end;
  PayloadHash := IntegritySHA512Text(PayloadText);
  SecurityIntent := Action;
  if Action = CozyText_Api_overlay_78ab122b then SecurityIntent := CozyText_Api_verify_b7cb75a0;
  if Action <> CozyText_Api_release_dca62424 then
    RequireServerObservation(FTransport, FSecurity, FCodeIntegrity, 'B',
      FBootstrapSessionID, FBootstrapSessionToken, SecurityIntent,
      AuthorityBinding(ID, PayloadHash), CurrentImage.SHA512, CurrentImage.CRC64,
      function: Boolean
      begin
        Result := (InterlockedCompareExchange(FStopRequested, 0, 0) <> 0) or NHWStopConfirmed;
      end, FImageIntegrity, OwnRuntime(FSecurity, FCodeIntegrity), FNHWAuthority);
  ChallengeBody := TJSONObject.Create;
  Challenge := nil;
  ExecuteBody := nil;
  try
    ChallengeBody.AddPair(CozyText_Api_action_a7b64efd, Action);
    ChallengeBody.AddPair(CozyText_Api_requestId_0cae8d65, ID);
    ChallengeBody.AddPair(CozyText_Api_deviceId_017320c2, FSecurity.DeviceID);
    ChallengeBody.AddPair(CozyText_Api_publicKey_f3142087, FSecurity.PublicKeyBlob);
    ChallengeBody.AddPair(CozyText_Api_payloadHash_db98f451, PayloadHash);
    Challenge := PostJSON(CozyText_Api_challenge_1e1bb128, ChallengeBody);
    ChallengeID := JsonString(Challenge, CozyText_Api_challengeId_61686f91);
    Nonce := JsonString(Challenge, CozyText_Api_nonce_3c39b97d);
    ExpiresAt := JsonInteger(Challenge, CozyText_Api_expiresAt_519a6450);
    if not TRegEx.IsMatch(ChallengeID, CozyText_Api_Pattern_23f9cb7d) or
      not TRegEx.IsMatch(Nonce, CozyText_Api_Pattern_9cabc583) or
      (ExpiresAt <= 0) then
      raise EGameApi.Create(CozyText_Api_CHALLENGE_INVALID_58648ff0,
        CozyText_Api_Text_805f0f69);
    // Reconstruct the exact signed message from this request. Never sign
    // an arbitrary string supplied by the server, even over an authenticated connection.
    Canonical := CozyText_Api_GAME_DESKTOP_V2_7238710e + #10 + Action + #10 +
      ChallengeID + #10 + Nonce + #10 + ID + #10 +
      FSecurity.DeviceID + #10 + PayloadHash + #10 + IntToStr(ExpiresAt);
    if JsonString(Challenge, CozyText_Api_canonical_cc5c5ef4) <> Canonical then
      raise EGameApi.Create(CozyText_Api_CHALLENGE_MISMATCH_c7e4897d,
        CozyText_Api_Text_5ca9d35c);
    ExecuteBody := TJSONObject.Create;
    ExecuteBody.AddPair(CozyText_Api_challengeId_61686f91, ChallengeID);
    ExecuteBody.AddPair(CozyText_Api_requestId_0cae8d65, ID);
    ExecuteBody.AddPair(CozyText_Api_action_a7b64efd, Action);
    ExecuteBody.AddPair(CozyText_Api_deviceId_017320c2, FSecurity.DeviceID);
    ExecuteBody.AddPair(CozyText_Api_publicKey_f3142087, FSecurity.PublicKeyBlob);
    ExecuteBody.AddPair(CozyText_Api_payloadJSON_5d9b8ea1, PayloadText);
    ExecuteBody.AddPair(CozyText_Api_signature_f5c615b8, FSecurity.Sign(Canonical));
    { Exact lost-response retries are backed by the server's durable redeem/
      release receipt, with signature, expiry and session gates rechecked. }
    Result := PostJSON(CozyText_Api_execute_2b208510, ExecuteBody, (Action = CozyText_Api_overlay_78ab122b) or
      (Action = CozyText_Api_redeem_5ba76ca4) or (Action = CozyText_Api_release_dca62424));
  finally
    ExecuteBody.Free;
    Challenge.Free;
    ChallengeBody.Free;
    WipeText(Canonical);
    WipeText(Nonce);
    WipeText(ChallengeID);
    WipeText(PayloadHash);
  end;
end;

function TGameApi.ParseState(Data: TJSONObject;
  StartedAt: UInt64): TLicenseState;
var
  NowTick: UInt64;
  LeaseDuration, Elapsed: Int64;
begin
  Result := Default(TLicenseState);
  Result.LicenseID := JsonString(Data, CozyText_Api_licenseId_d119b21e);
  Result.Status := JsonString(Data, CozyText_Api_status_5b6d5c76);
  Result.DeviceID := JsonString(Data, CozyText_Api_deviceId_017320c2);
  Result.LicenseLabel := JsonString(Data, CozyText_Api_label_ebaa42f0, False);
  Result.IssuedAt := JsonInteger(Data, CozyText_Api_issuedAt_77d618f1);
  Result.ActivatedAt := JsonInteger(Data, CozyText_Api_activatedAt_f231270f);
  Result.ExpiresAt := JsonInteger(Data, CozyText_Api_expiresAt_519a6450);
  Result.LeaseExpiresAt := JsonInteger(Data, CozyText_Api_leaseExpiresAt_82ef4d75);
  Result.ServerTime := JsonInteger(Data, CozyText_Api_serverTime_ac0470bc);
  Result.Revision := JsonInteger(Data, CozyText_Api_revision_5f36f9e0);
  if (Result.DeviceID <> FSecurity.DeviceID) or
    not TRegEx.IsMatch(Result.LicenseID, CozyText_Api_Pattern_aee8d3e4) or
    (Length(Result.LicenseLabel) > 300) or
    (Result.Status <> CozyText_Api_USED_f24e3598) or (Result.ServerTime <= 0) or
    (Result.LeaseExpiresAt <= Result.ServerTime) or
    (Result.IssuedAt > Result.ServerTime) or
    (Result.ActivatedAt > Result.ServerTime) then
    raise EGameApi.Create(CozyText_Api_LICENSE_RESPONSE_INVALID_0053ab4b,
      CozyText_Api_Text_c3f33356);
  LeaseDuration := Result.LeaseExpiresAt - Result.ServerTime;
  if (LeaseDuration > MaxLeaseMilliseconds) or
    ((Result.ExpiresAt <> 0) and
     ((Result.ExpiresAt <= Result.ServerTime) or
      (Result.LeaseExpiresAt > Result.ExpiresAt))) then
    raise EGameApi.Create(CozyText_Api_LICENSE_RESPONSE_INVALID_0053ab4b,
      CozyText_Api_Text_42c513be);
  NowTick := CozyTick;
  if NowTick < StartedAt then
    raise EGameApi.Create(CozyText_Api_CLOCK_INVALID_7c73ca62,
      CozyText_Api_Text_4ecf7ffb);
  // Subtract the entire challenge/execute duration. A delayed response cannot
  // lengthen the server lease, and changing Windows time cannot extend it.
  Elapsed := Int64(NowTick - StartedAt);
  if LeaseDuration <= Elapsed then
    raise EGameApi.Create(CozyText_Api_LEASE_EXPIRED_1390b833,
      CozyText_Api_Text_f1a4f1aa, True);
  Result.VerifiedAtTick := NowTick;
  Result.LeaseDeadlineTick := NowTick + UInt64(LeaseDuration - Elapsed);
end;

function TGameApi.StartOverlayCore(RestrictedPrivileges: Boolean;
  const Progress: TProc<Integer>): Boolean;
var Payload, Reply: TJSONObject; PayloadText, FailureReason: string;
  PreparedOverlayID, PrepareRequestID, AbortOverlayID, AbortPrepareID: string;
  TransferClient: TOverlayClient;
  RecoveredTransfer, ParentWaitingForChild: Boolean;
  ParentRenewalDue, ParentStartupDeadline: UInt64;
  MaintainParent: TProc<Boolean>;
  RenewParent, RequireParentPending: TProc;
begin
  MaintainParent := nil; RenewParent := nil; RequireParentPending := nil;
  ParentWaitingForChild := False;
  ParentRenewalDue := CozyTick;
  { A single upper bound for this synchronous preparation/transfer operation.
    The download's 300 s and handoff's 110 s anchors still apply independently. }
  ParentStartupDeadline := CozyTick + 410000;
  PreparedOverlayID := ''; PrepareRequestID := '';
  TMonitor.Enter(FLock);
  try
    FailureReason := CozyText_Api_OVERLAY_PREPARE_FAILED_e31af1a1;
    try
      RequireRunning;
      if FOverlayStarted then
      begin
        if RestrictedPrivileges <> FOverlayRestrictedPrivileges then
          raise EGameApi.Create(CozyText_Api_OVERLAY_PROFILE_ALREADY_SELECTED_dddc9b9c, CozyText_Api_Overlay_profile_is_already_selected_d190f2de);
        Exit(True);
      end;
      if (FActivationToken = '') or (FCurrent.LeaseDeadlineTick <= CozyTick) then
        raise EGameApi.Create(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394, CozyText_Api_A_live_license_is_required_ec8c1aef);
      RequireParentPending :=
        procedure
        begin
          RequireRunning;
          RequireModuleSnapshotLease;
          if FGate.IsClosing or (CozyTick >= ParentStartupDeadline) then
          begin
            FailOperation(CozyText_Api_OVERLAY_START_TIMEOUT_a2c90d7f);
            RequestStopCore;
            raise EGameApi.Create(CozyText_Api_OVERLAY_START_TIMEOUT_a2c90d7f, CozyText_Api_Overlay_startup_stopped_94aa2ba7);
          end;
          if (FActivationToken = '') or
            (FCurrent.LeaseDeadlineTick <= CozyTick) then
          begin
            FailOperation(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394);
            RequestStopCore;
            raise EGameApi.Create(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394, CozyText_Api_Parent_authorization_expired_25d3018b);
          end;
        end;
      RenewParent :=
        procedure
        var PreviousDeadline: UInt64; Renewed: TLicenseState;
        begin
          RequireParentPending();
          PreviousDeadline := FCurrent.LeaseDeadlineTick;
          { Ordinary fresh, signed verification. A progress event or a local
            deadline assignment never grants more server authority. }
          Renewed := VerifyCore;
          if (CozyTick >= PreviousDeadline) or not Renewed.IsActive then
          begin
            { A late reply cannot leave a fresh local grant behind after this
              transfer has already lost its old permission window. }
            FailOperation(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394);
            RequestStopCore;
            raise EGameApi.Create(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394, CozyText_Api_Parent_renewal_missed_its_lease_99546c89);
          end;
          RequireParentPending();
          ParentRenewalDue := CozyTick + 30000;
        end;
      MaintainParent :=
        procedure(BeforeChild: Boolean)
        var MoreModules: Boolean; At, ReportDeadline, ReportBudget: UInt64;
        begin
          RequireParentPending();
          if BeforeChild and (FModuleSnapshot = nil) then FNextModules := 0;
          At := CozyTick;
          if (FModuleSnapshot <> nil) or (At >= FNextModules) then
          begin
            { A download chunk is NOT a report-batch clock. Finish this owned
              snapshot at the current checkpoint before fetching another
              chunk. Keep the same worker/lock and renew the independent
              license lease between requests while the old snapshot is fresh.
              During child wait, return after each batch so the handoff loop
              can observe ready/cancel/process-exit between report requests. }
            repeat
              RequireParentPending();
              At := CozyTick;
              if (At >= ParentRenewalDue) or
                (FCurrent.LeaseDeadlineTick - At <= 60000) then RenewParent();
              MoreModules := ReportModulesIfDue;
              RequireParentPending();
            until not MoreModules or ParentWaitingForChild;
          end;
          if BeforeChild then
          begin
            { Drain queued B causes before the final fresh parent proof and
              before O starts. A later commit must not spend O's proof lifetime
              waiting on report I/O. The independent paths share this budget. }
            ReportDeadline := ParentStartupDeadline;
            if FCurrent.LeaseDeadlineTick < ReportDeadline then
              ReportDeadline := FCurrent.LeaseDeadlineTick;
            At := CozyTick;
            if At < ReportDeadline then
            begin
              ReportBudget := ReportDeadline - At;
              if ReportBudget > 7000 then ReportBudget := 7000;
              FlushNHWReports(Cardinal(ReportBudget));
            end;
            { A report verdict can confirm a stop while the worker is waiting. }
            RequireParentPending();
          end;
          At := CozyTick;
          if BeforeChild or (At >= ParentRenewalDue) or
            (FCurrent.LeaseDeadlineTick - At <= 60000) then RenewParent();
          if BeforeChild then ParentWaitingForChild := True;
        end;
      CheckIntegrityCore;
      while not FModuleSnapshotCompleted do
      begin
        MaintainParent(False);
      end;
      MaintainParent(False);
      Payload := TJSONObject.Create;
      Reply := nil;
      try
        AddBootstrapSession(Payload);
        Payload.AddPair(CozyText_Api_activationToken_43b27685, FActivationToken);
        Payload.AddPair(CozyText_Api_appVersion_95a577ca, AppVersion);
        PayloadText := Payload.ToJSON;
        PrepareRequestID := RequestID;
        Reply := ExecuteProof(CozyText_Api_overlay_78ab122b, PayloadText, PrepareRequestID);
        PreparedOverlayID := JsonString(Reply, CozyText_Api_overlayId_19d7deba);
        if not TRegEx.IsMatch(PreparedOverlayID, CozyText_Api_Pattern_1e820360) then
          raise EGameApi.Create(CozyText_Api_OVERLAY_RESPONSE_INVALID_66fcc234, CozyText_Api_Invalid_Overlay_identifier_eee9a3c6);
        FNHWOverlayID := PreparedOverlayID;
        if FNHWGuard <> nil then FNHWGuard.SecurityContext.SetPhase('B_HANDOFF_TO_O');
        if Assigned(Progress) then Progress(60);
        FailureReason := CozyText_Api_OVERLAY_LAUNCH_FAILED_51d8326a;
        Result := LaunchOverlay(FOverlayProfile, FSecurity, Reply,
          FBoundImage.SHA512, FBootstrapSessionID, RestrictedPrivileges,
          MaintainParent, Progress);
        if not Result then
          raise EGameApi.Create(CozyText_Api_OVERLAY_START_FAILED_098b973b, CozyText_Api_Overlay_authorization_failed_97ba51f2);
        { Native ready is sent only after O's first authorized visible frame.
          Retire B server-side before the console worker leaves this process. }
        FailureReason := CozyText_Api_OVERLAY_TRANSFER_FAILED_4689b519;
        if FLifecycle <> nil then
          FLifecycle.Prepare('B', FBootstrapSessionID, FBootstrapSessionToken);
        TransferClient := TOverlayClient.Create(FOverlayProfile);
        try
          { Recheck stop and existing deadlines immediately before retirement. }
          RequireParentPending();
          TransferClient.CommitTransfer(FSecurity, FBootstrapSessionID,
            FBootstrapSessionToken, PreparedOverlayID);
          if FLifecycle <> nil then FLifecycle.Note('B', CozyText_Api_CLOSE_RESPONSE_c2e102cf, CozyText_Api_ACKNOWLEDGED_3e71d2a8);
        finally
          TransferClient.Free;
        end;
        FOverlayRestrictedPrivileges := RestrictedPrivileges;
        FOverlayStarted := True;
        FCurrent := Default(TLicenseState);
        WipeText(FActivationToken);
        ClearPending;
        if NHWStopConfirmed then Exit(False);
        if Assigned(Progress) then Progress(100);
      finally
        WipeText(PayloadText);
        Reply.Free;
        Payload.Free;
      end;
    except
      on E: Exception do
      begin
        { Close exactly the prepared O, including an unknown preparation whose
          two responses were lost. The server records a cancellation tombstone
          so the delayed original request cannot publish a new O afterwards. }
        RecoveredTransfer := False;
        { Confirmed detection uses the exact signed cohort stop during owner
          cleanup, even when the ordinary commit response was lost. Retain
          the preparation tombstone path when the child ID is still unknown. }
        if (PrepareRequestID <> '') and
          (not NHWStopConfirmed or (FNHWOverlayID = '')) then
        begin
          AbortOverlayID := PreparedOverlayID;
          AbortPrepareID := '';
          if not TRegEx.IsMatch(AbortOverlayID, CozyText_Api_Pattern_1e820360) then
          begin AbortOverlayID := ''; AbortPrepareID := PrepareRequestID; end;
          try
            TransferClient := TOverlayClient.Create(FOverlayProfile);
            try
              RecoveredTransfer := TransferClient.AbortChild(FSecurity,
                FBootstrapSessionID, FBootstrapSessionToken, AbortOverlayID, AbortPrepareID);
            finally TransferClient.Free; end;
          except
            { Network unavailability cannot make cleanup certain. The server's
              bounded child/session expiry remains authoritative. }
          end;
        end;
        if RecoveredTransfer and (FailureReason = CozyText_Api_OVERLAY_TRANSFER_FAILED_4689b519) then
        begin
          FOverlayRestrictedPrivileges := RestrictedPrivileges;
          FOverlayStarted := True;
          FCurrent := Default(TLicenseState);
          WipeText(FActivationToken);
          ClearPending;
          if NHWStopConfirmed then Exit(False);
          if Assigned(Progress) then Progress(100);
          Exit(True);
        end;
        { Only the closed download failure type supplies a pre-launch code.
          Never upload arbitrary exception text, paths or transport messages. }
        if E is EOverlayDownloadFailure then
          case EOverlayDownloadFailure(E).Kind of
            odfTimeout: FailureReason := CozyText_Api_OVERLAY_DOWNLOAD_TIMEOUT_a34f9d07;
            odfTicketExpired: FailureReason := CozyText_Api_OVERLAY_DOWNLOAD_TICKET_EXPIRED_4fa3e2c5;
          end;
        { Only exact handoff codes can cross the diagnostic boundary. }
        if ((E is EHandoff) or (E is EDeviceSecurity)) and
          ((E.Message = CozyText_Api_HANDOFF_KEY_EXPORT_FAILED_412ca6e9) or
           (E.Message = CozyText_Api_HANDOFF_CIPHER_FAILED_a6983cc2) or
           (E.Message = CozyText_Api_HANDOFF_DELEGATION_INVALID_94f45f94) or
           (E.Message = CozyText_Api_HANDOFF_BOOTSTRAP_INVALID_16d8c760) or
           (E.Message = CozyText_Api_HANDOFF_CHILD_BINDING_INVALID_effd6ca8) or
           (E.Message = CozyText_Api_HANDOFF_PROCESS_CREATE_FAILED_cd404ddf) or
           (E.Message = CozyText_Api_HANDOFF_PIPE_TIMEOUT_f9e14f2f) or
           (E.Message = CozyText_Api_HANDOFF_PIPE_FAILED_8fecb4f4) or
           (E.Message = CozyText_Api_HANDOFF_CHILD_EXITED_93181d3b) or
           (E.Message = CozyText_Api_HANDOFF_READY_TIMEOUT_99fd59d8) or
           (E.Message = CozyText_Api_HANDOFF_WAIT_FAILED_cf9dd5b4)) then
          FailureReason := E.Message;
        if not NHWStopConfirmed then ReportOverlayFailure(FailureReason);
        raise;
      end;
    end;
  finally
    MaintainParent := nil; RenewParent := nil; RequireParentPending := nil;
    WipeText(PreparedOverlayID); WipeText(PrepareRequestID);
    WipeText(AbortOverlayID); WipeText(AbortPrepareID);
    TMonitor.Exit(FLock);
  end;
end;

function TGameApi.RedeemCore(const Key: string): TLicenseState;
var
  Payload: TJSONObject;
  PendingValue: TJSONValue;
  CleanKey: string;
begin
  TMonitor.Enter(FLock);
  try
    FLastErrorCode := '';
    FCurrent := Default(TLicenseState);
    RequireServerProfile;
    Payload := TJSONObject.Create;
    PendingValue := nil;
    try
      try
        CleanKey := UpperCase(Trim(Key));
        if not TRegEx.IsMatch(CleanKey, CozyText_Api_Pattern_67c2fa3e) then
          raise EGameApi.Create(CozyText_Api_LICENSE_KEY_INVALID_6126d5ed,
            ErrorDescription(CozyText_Api_LICENSE_KEY_INVALID_6126d5ed));
        if FPendingAction = CozyText_Api_redeem_5ba76ca4 then
        begin
          PendingValue := TJSONObject.ParseJSONValue(FPendingPayloadJSON);
          if not (PendingValue is TJSONObject) or
            (JsonString(TJSONObject(PendingValue), CozyText_Api_licenseKey_01a73f12) <> CleanKey) then
            raise EGameApi.Create(CozyText_Api_PENDING_OPERATION_f345beda,
              CozyText_Api_verify_cfdb221d);
        end
        else
        begin
          AddBootstrapSession(Payload);
          Payload.AddPair(CozyText_Api_licenseKey_01a73f12, CleanKey);
          Payload.AddPair(CozyText_Api_deviceName_03461804, ComputerLabel);
          Payload.AddPair(CozyText_Api_appVersion_95a577ca, AppVersion);
          PreparePending(CozyText_Api_redeem_5ba76ca4, Payload);
        end;
        Result := ResumePending;
      except
        on E: EGameApi do
        begin
          FailOperation(E.Code);
          raise;
        end;
        on E: Exception do
        begin
          FailOperation(CozyText_Api_AUTHORIZATION_FAILED_dd7fd3f9);
          raise EGameApi.Create(CozyText_Api_AUTHORIZATION_FAILED_dd7fd3f9,
            CozyText_Api_Text_895eea7d);
        end;
      end;
    finally
      PendingValue.Free;
      Payload.Free;
      WipeText(CleanKey);
    end;
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TGameApi.VerifyCore: TLicenseState;
var
  Payload, Data: TJSONObject;
  StartedAt: UInt64;
  PayloadText: string;
begin
  TMonitor.Enter(FLock);
  try
    FLastErrorCode := '';
    FCurrent := Default(TLicenseState);
    RequireServerProfile;
    Payload := TJSONObject.Create;
    Data := nil;
    try
      try
        if FPendingAction <> '' then
        begin
          Result := ResumePending;
          Exit;
        end;
        if FActivationToken = '' then
          raise EGameApi.Create(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394,
            ErrorDescription(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394));
        AddBootstrapSession(Payload);
        Payload.AddPair(CozyText_Api_activationToken_43b27685, FActivationToken);
        Payload.AddPair(CozyText_Api_appVersion_95a577ca, AppVersion);
        StartedAt := CozyTick;
        PayloadText := Payload.ToJSON;
        Data := ExecuteProof(CozyText_Api_verify_b7cb75a0, PayloadText);
        Result := ParseState(Data, StartedAt);
        FCurrent := Result;
      except
        on E: EGameApi do
        begin
          FailOperation(E.Code);
          raise;
        end;
        on E: Exception do
        begin
          FailOperation(CozyText_Api_AUTHORIZATION_FAILED_dd7fd3f9);
          raise EGameApi.Create(CozyText_Api_AUTHORIZATION_FAILED_dd7fd3f9,
            CozyText_Api_Text_13e2c01f);
        end;
      end;
    finally
      WipeText(PayloadText);
      Data.Free;
      Payload.Free;
    end;
  finally
    TMonitor.Exit(FLock);
  end;
end;

procedure TGameApi.ReleaseCore;
var
  Payload: TJSONObject;
  ReleasedState: TLicenseState;
begin
  TMonitor.Enter(FLock);
  try
    FLastErrorCode := '';
    FCurrent := Default(TLicenseState);
    RequireServerProfile;
    Payload := TJSONObject.Create;
    try
      try
        if FPendingAction <> CozyText_Api_release_dca62424 then
        begin
          if FActivationToken = '' then
            raise EGameApi.Create(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394,
              ErrorDescription(CozyText_Api_AUTHORIZATION_REQUIRED_7ba38394));
          AddBootstrapSession(Payload);
          Payload.AddPair(CozyText_Api_activationToken_43b27685, FActivationToken);
          Payload.AddPair(CozyText_Api_appVersion_95a577ca, AppVersion);
          PreparePending(CozyText_Api_release_dca62424, Payload);
        end;
        ReleasedState := ResumePending;
        if (ReleasedState.Status <> CozyText_Api_USED_f24e3598) or ReleasedState.IsActive then
          raise EGameApi.Create(CozyText_Api_RELEASE_RESPONSE_INVALID_4c87df03,
            CozyText_Api_Text_ecd8e220);
      except
        on E: EGameApi do
        begin
          FailOperation(E.Code);
          raise;
        end;
        on E: Exception do
        begin
          FailOperation(CozyText_Api_RELEASE_FAILED_c9e94c85);
          raise EGameApi.Create(CozyText_Api_RELEASE_FAILED_c9e94c85,
            CozyText_Api_Text_77b8608e);
        end;
      end;
    finally
      Payload.Free;
    end;
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TGameApi.GetModuleInventoryReadyCore: Boolean;
var At: UInt64;
begin
  TMonitor.Enter(FLock);
  try
    At := CozyTick;
    Result := FModuleSnapshotCompleted and (FModuleSnapshot = nil) and
      (At < FModuleDeadlineTick);
    if Result then
      Result := FModuleDeadlineTick - At > ModuleSnapshotCheckpointReserve;
    { NextModules is scheduling advice, not an authorization predicate. A
      slow first collection must still let a queued key use its fresh receipt. }
  finally TMonitor.Exit(FLock); end;
end;

function TGameApi.GetOverlayTransferredCore: Boolean;
begin
  TMonitor.Enter(FLock);
  try Result := FOverlayStarted; finally TMonitor.Exit(FLock); end;
end;

function TGameApi.GetLastErrorCodeCore: string;
begin
  TMonitor.Enter(FLock);
  try Result := FLastErrorCode; finally TMonitor.Exit(FLock); end;
end;

function TGameApi.GetServerDisplayNameCore: string;
begin
  TMonitor.Enter(FLock);
  try Result := FServerDisplayName; finally TMonitor.Exit(FLock); end;
end;

function TGameApi.InvokeServerPolicy(FunctionID: Word;
  const Args: array of Integer; const Cancelled: TAuthorityCancelled): Integer;
var LocalArgs: TArray<Integer>; OperationCancelled: TAuthorityCancelled;
  Value: Integer;
  procedure RequirePolicyContext;
  begin
    RequireRunning;
    if FGate.IsClosing or (Assigned(Cancelled) and Cancelled()) then
      raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_CANCELLED_7dc3bcfa, '');
    if FOverlayStarted or (FPendingAction <> '') or
      (FActivationToken = '') or not FCurrent.IsActive then
      raise EGameApi.Create(CozyText_Api_COZY_SERVER_OPERATION_LICENSE_REQUIRED_c843e348, '');
  end;
begin
  { Snapshot BEFORE waiting for the proof lock or doing integrity/network work.
    The caller only has to keep Args stable while this bounded copy is taken. }
  LocalArgs := SnapshotServerOperationArgs(FunctionID, Args);
  try
    FGate.Enter;
    try
      TMonitor.Enter(FLock);
      try
        RequirePolicyContext;
        RequireServerProfile;
        OperationCancelled :=
          function: Boolean
          begin
            Result := FGate.IsClosing or
              (InterlockedCompareExchange(FStopRequested, 0, 0) <> 0) or NHWStopConfirmed or
              FOverlayStarted or (FPendingAction <> '') or
              (FActivationToken = '') or not FCurrent.IsActive or
              (Assigned(Cancelled) and Cancelled());
          end;
        CheckIntegrityCore(OperationCancelled);
        RequirePolicyContext;
        Value := InvokeCozyServerOperation(FTransport, FSecurity, FCodeIntegrity, 'B',
          FBootstrapSessionID, FBootstrapSessionToken, FBoundImage.SHA512,
          FBoundImage.CRC64, FunctionID, LocalArgs, OperationCancelled,
          FImageIntegrity, OwnRuntime(FSecurity, FCodeIntegrity));
        RequirePolicyContext;
        Result := Value;
      finally TMonitor.Exit(FLock); end;
    finally FGate.Leave; end;
  finally
    OperationCancelled := nil;
    ClearServerOperationArgs(LocalArgs);
  end;
end;

function TGameApi.StartOverlay(RestrictedPrivileges: Boolean;
  const Progress: TProc<Integer>): Boolean;
begin
  FGate.Enter;
  try
    RequireRunning;
    Result := StartOverlayCore(RestrictedPrivileges, Progress);
  finally FGate.Leave; end;
end;

function TGameApi.Redeem(const Key: string): TLicenseState;
begin
  FGate.Enter;
  try
    RequireRunning;
    Result := RedeemCore(Key);
  finally FGate.Leave; end;
end;

function TGameApi.Verify: TLicenseState;
begin
  FGate.Enter;
  try
    RequireRunning;
    Result := VerifyCore;
  finally FGate.Leave; end;
end;

procedure TGameApi.Release;
begin
  FGate.Enter;
  try
    RequireRunning;
    ReleaseCore;
  finally FGate.Leave; end;
end;

procedure TGameApi.CheckIntegrity;
begin
  FGate.Enter;
  try
    RequireRunning;
    CheckIntegrityCore;
    if FLifecycle <> nil then
      FLifecycle.Prepare('B', FBootstrapSessionID, FBootstrapSessionToken);
  finally FGate.Leave; end;
end;

procedure TGameApi.FlushNHWReports(TimeoutMS: Cardinal);
begin
  { Best effort on independent report connections. A network failure never
    prevents exact-session cleanup and does not claim report delivery. }
  if TimeoutMS > 7000 then TimeoutMS := 7000;
  try
    if FNHWAuthority <> nil then FNHWAuthority.FlushSecurityReports(TimeoutMS);
  except
    { Session revocation and local disposal must still run. }
  end;
end;

procedure TGameApi.AttachNHW(Guard: TCozyNHWGuard; const Quoter: ICozyTpmQuoter);
begin
  if (Guard = nil) or (FNHWGuard <> nil) then
    raise EInvalidOpException.Create(CozyText_Api_CLIENT_STOPPING_99bc92f1);
  FNHWAuthority := TCozyNHWAuthority.Create(
    function(out State: TCozyNHWKernelState): Boolean
    begin Result := Guard.TryReadKernelState(State); end,
    function(Channel: TResponsePathChannel; out State: TCozyNHWKernelState): Boolean
    begin Result := Guard.TryReadPathState(Channel, State); end,
    procedure begin Guard.ApplyAuthenticatedServerStop; end, Guard);
  FNHWAuthority.SetQuoteProvider(Quoter);
  FNHWGuard := Guard;
end;

procedure TGameApi.FinishNHWStop;
var TransferClient: TOverlayClient;
begin
  if FNHWStopFinished or not NHWStopConfirmed then Exit;
  FNHWStopFinished := True;
  if FNHWOverlayID = '' then Exit;
  { Use a separate cleanup-only connection after the worker has joined.
    A lost or already committed transfer cannot turn this exact stop into
    a new child grant, and a network failure cannot suppress local cleanup. }
  try
    TransferClient := TOverlayClient.Create(FOverlayProfile);
    try
      TransferClient.AbortChild(FSecurity, FBootstrapSessionID,
        FBootstrapSessionToken, FNHWOverlayID, '', True);
    finally TransferClient.Free; end;
  except
    { Existing authenticated Close and bounded leases handle an outage. }
  end;
end;

procedure TGameApi.RetireImagesForShutdown;
begin
  RequestStopCore;
  FGate.CloseAndWait;
  try
    if FRuntimeGraph <> nil then
    begin
      FRuntimeGraph.RetireDependency(5);
      FRuntimeGraph.RetireDependency(6);
    end;
  finally
    FreeAndNil(FImageIntegrity);
    FreeAndNil(FCodeIntegrity);
  end;
end;

function TGameApi.ContinueModuleInventory: Boolean;
begin
  FGate.Enter;
  try
    RequireRunning;
    Result := ContinueModuleInventoryCore;
  finally FGate.Leave; end;
end;

procedure TGameApi.RequestStop;
begin
  FGate.Enter;
  try
    RequestStopCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetDeviceID: string;
begin
  FGate.Enter;
  try
    Result := GetDeviceIDCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetHasAuthorization: Boolean;
begin
  FGate.Enter;
  try
    Result := GetHasAuthorizationCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetCurrent: TLicenseState;
begin
  FGate.Enter;
  try
    Result := GetCurrentCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetHasServerProfile: Boolean;
begin
  FGate.Enter;
  try
    Result := GetHasServerProfileCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetModuleInventoryReady: Boolean;
begin
  FGate.Enter;
  try
    Result := GetModuleInventoryReadyCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetOverlayTransferred: Boolean;
begin
  FGate.Enter;
  try
    Result := GetOverlayTransferredCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetLastErrorCode: string;
begin
  FGate.Enter;
  try
    Result := GetLastErrorCodeCore;
  finally FGate.Leave; end;
end;

function TGameApi.GetServerDisplayName: string;
begin
  FGate.Enter;
  try
    Result := GetServerDisplayNameCore;
  finally FGate.Leave; end;
end;

initialization
  { API binding only; original startup actions follow unchanged. }

  BindApiPointer(ApiSlot_GetComputerName, RequireProcAddressHash64(CozyText_Api_kernel32_dll_bb32e033, HASH_GetComputerNameW));

end.
