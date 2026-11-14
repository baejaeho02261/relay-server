unit Cozy.Lifecycle;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Lifecycle,
 System.SysUtils, System.JSON, System.Generics.Collections, Cozy.Security, Cozy.Server.Profile,
  Cozy.Transport, Cozy.Handoff, Cozy.Lifecycle.Contracts;

type
{$IFDEF GAME_LIFECYCLE_CONTRACT_TESTS}
  TLifecycleTestPost = reference to function(Body: TJSONObject;
    DeadlineTick: UInt64): TJSONObject;
{$ENDIF}
  { Diagnostic-only, one-use server permits. A permit cannot renew a session,
    authorize execution or delete a file. The caller owns Security and joins
    all workers before destroying this reporter or the signing key. }
  TLifecycleReporter = class
  private type
    TChannel = class
      TargetRole, PermitID, Nonce, RequestID: string;
      Deadline, NextPrepare: UInt64;
      Events: TJSONArray;
      Submitted: Boolean;
      EventState: TLifecycleBatchState;
      constructor Create(const Role: string);
      procedure ClearGrant;
      destructor Destroy; override;
    end;
  private
    FRole: string;
    FRoleKind: TLifecycleRole;
    FSecurity: TDeviceSecurity;
    FTransport: TConnectTransport;
    FLock, FRequestLock: TObject;
    FSelf, FParent: TChannel;
{$IFDEF GAME_LIFECYCLE_CONTRACT_TESTS}
    FTestPost: TLifecycleTestPost;
{$ENDIF}
    function Channel(const TargetRole: string): TChannel;
    function Post(Body: TJSONObject; DeadlineTick: UInt64): TJSONObject;
  public
    constructor Create(Profile: TConnectServerProfile; Security: TDeviceSecurity;
      const Role: string);
    destructor Destroy; override;
    { These methods contain their own diagnostic failures. They must never
      replace the authoritative close/cleanup result. No local logs or queue. }
    procedure Prepare(const TargetRole, SessionID, SessionToken: string;
      DeadlineTick: UInt64 = 0);
    procedure Note(const TargetRole, Event, Status: string; PID: Cardinal = 0;
      Win32Error: Cardinal = 0; ElapsedMs: Cardinal = 0);
    procedure ObserveCleanup(const TargetRole: string;
      const Observation: THandoffCleanupObservation; IncludeProcess: Boolean);
    procedure Submit(const TargetRole: string; DeadlineTick: UInt64 = 0);
    class function Tick: UInt64; static;
    class function ProcessID: Cardinal; static;
{$IFDEF GAME_LIFECYCLE_CONTRACT_TESTS}
    constructor CreateForTest(const Role: string;
      const PostHook: TLifecycleTestPost);
    function SnapshotForTest(const TargetRole: string): TJSONArray;
    procedure HoldEventLockForTest(const Body: TProc);
{$ENDIF}
  end;

implementation

uses Cozy.Clock, Winapi.Windows, Cozy.Bootstrap, Cozy.Integrity, Cozy.WinApi,
  Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver;

var
  ApiSlot_GetCurrentProcessId: TEncodedApiPointer;

class function TLifecycleReporter.Tick: UInt64;
begin
  Result := CozyTick;
end;

class function TLifecycleReporter.ProcessID: Cardinal;
var Target: TApiGetCurrentProcessId;
begin
  Target := TApiGetCurrentProcessId(DecodeApiPointer(ApiSlot_GetCurrentProcessId));
  Result := Target();
end;

function LowerHex(const Value: string; Count: Integer): Boolean;
var C: Char;
begin
  Result := Length(Value) = Count;
  if not Result then Exit;
  for C in Value do
    if not CharInSet(C, ['0'..'9', 'a'..'f']) then Exit(False);
end;

function SessionIDValid(const Value: string): Boolean;
var C: Char; ID: string;
begin
  ID := Value;
  if Length(ID) = 27 then
  begin
    if (Copy(ID, 1, 3) <> CozyText_Lifecycle_BF_87a5d425) and (Copy(ID, 1, 3) <> CozyText_Lifecycle_DS_2c64dd0d) and
      (Copy(ID, 1, 3) <> CozyText_Lifecycle_DL_1247c2f0) and (Copy(ID, 1, 3) <> CozyText_Lifecycle_LA_fca587bc) then Exit(False);
    Delete(ID, 1, 3);
  end;
  Result := Length(ID) = 24;
  if not Result then Exit;
  for C in ID do
    if not CharInSet(C, ['0'..'9', 'A'..'F']) then Exit(False);
end;

constructor TLifecycleReporter.TChannel.Create(const Role: string);
begin
  inherited Create;
  TargetRole := Role;
  Events := TJSONArray.Create;
end;

procedure TLifecycleReporter.TChannel.ClearGrant;
begin
  WipeText(PermitID); WipeText(Nonce); WipeText(RequestID);
  Deadline := 0;
end;

destructor TLifecycleReporter.TChannel.Destroy;
begin
  ClearGrant;
  Events.Free;
  inherited;
end;

constructor TLifecycleReporter.Create(Profile: TConnectServerProfile;
  Security: TDeviceSecurity; const Role: string);
begin
  inherited Create;
  FLock := TObject.Create; FRequestLock := TObject.Create;
  if (Security = nil) or ((Role <> 'A') and (Role <> 'B') and (Role <> 'O')) then
    raise EArgumentException.Create(CozyText_Lifecycle_LIFECYCLE_ROLE_INVALID_1e049d52);
  if not ParseLifecycleRole(Role,FRoleKind) then raise EArgumentException.Create(CozyText_Lifecycle_LIFECYCLE_ROLE_INVALID_1e049d52);
  FRole := Role; FSecurity := Security;
  FSelf := TChannel.Create(Role);
  if Role = 'B' then FParent := TChannel.Create('A')
  else if Role = 'O' then FParent := TChannel.Create('B');
  FTransport := TConnectTransport.Create(Profile);
end;

destructor TLifecycleReporter.Destroy;
begin
  FTransport.Free;
  FSelf.Free; FParent.Free;
  FRequestLock.Free; FLock.Free;
  FSecurity := nil;
  inherited;
end;

function TLifecycleReporter.Channel(const TargetRole: string): TChannel;
begin
  Result := nil;
  if (FSelf <> nil) and (FSelf.TargetRole = TargetRole) then Result := FSelf
  else if (FParent <> nil) and (FParent.TargetRole = TargetRole) then Result := FParent;
end;

function TLifecycleReporter.Post(Body: TJSONObject;
  DeadlineTick: UInt64): TJSONObject;
var Reply: TJSONObject; Value: TJSONValue; Attempt: Integer; At: UInt64;
begin
  Result := nil;
  Reply := nil;
{$IFDEF GAME_LIFECYCLE_CONTRACT_TESTS}
  if Assigned(FTestPost) then Exit(FTestPost(Body,DeadlineTick));
{$ENDIF}
  for Attempt := 1 to 2 do
  begin
    At := Tick;
    if At >= DeadlineTick then Exit;
    try
      { Exact same signed body/request ID on the bounded transport retry. }
      Reply := FTransport.PostJSON(CozyText_Lifecycle_bootstrap_8552c876, Body, Cardinal(DeadlineTick - At));
      Break;
    except
      on E: EConnectTransport do
        if (Attempt = 2) or
          ((E.Code <> CozyText_Lifecycle_CONNECT_TIMEOUT_77e9215b) and (E.Code <> CozyText_Lifecycle_CONNECT_UNAVAILABLE_e19cb480) and
           (E.Code <> CozyText_Lifecycle_CONNECT_SEND_FAILED_2d182aac) and (E.Code <> CozyText_Lifecycle_CONNECT_RECEIVE_FAILED_2a042870) and
           (E.Code <> CozyText_Lifecycle_NETWORK_UNAVAILABLE_a1d6743a)) then Exit;
    end;
  end;
  try
    if Reply = nil then Exit;
    Value := Reply.GetValue(CozyText_Lifecycle_ok_9f8ddc4e);
    if not (Value is TJSONBool) or (Value.Value <> CozyText_Lifecycle_true_e253fdaa) then Exit;
    Value := Reply.GetValue(CozyText_Lifecycle_data_7e9ca56c);
    if Value is TJSONObject then Result := TJSONObject(Value.Clone);
  finally Reply.Free; end;
end;

procedure TLifecycleReporter.Prepare(const TargetRole, SessionID,
  SessionToken: string; DeadlineTick: UInt64);
var C: TChannel; Body, Reply: TJSONObject; At, Started, Reserve: UInt64;
  ID, PermitID, Nonce: string; Lease: Int64;
begin
  Body := nil; Reply := nil;
  try
    try
    C := Channel(TargetRole);
    if (C = nil) or (SessionID = '') or (SessionToken = '') then Exit;
    At := Tick;
    if (DeadlineTick = 0) or (DeadlineTick > At + 1500) then DeadlineTick := At + 1500;
    if (At >= DeadlineTick) or
      not TMonitor.Enter(FRequestLock, Cardinal(DeadlineTick - At)) then Exit;
    try
      At := Tick;
      if (C.Deadline <> 0) and (At >= C.Deadline) then C.ClearGrant;
      Reserve := 30000;
      { A new O business lease can last 120s. Retain a diagnostic margin for
        its full duration plus the 5s close budget, even if renewals stop. }
      if (FRole = 'O') and (TargetRole = 'O') then Reserve := 130000;
      if C.Submitted or (At < C.NextPrepare) or
        ((C.Deadline > At) and (C.Deadline - At > Reserve)) then Exit;
      C.NextPrepare := At + 30000;
      if (DeadlineTick = 0) or (DeadlineTick > At + 1500) then DeadlineTick := At + 1500;
      if At >= DeadlineTick then Exit;
      ID := BootstrapRequestID;
      Body := TJSONObject.Create;
      Body.AddPair(CozyText_Lifecycle_action_94e5b110, CozyText_Lifecycle_lifecycleChallenge_8bba9472);
      Body.AddPair(CozyText_Lifecycle_stage_fb16f355, FRole); Body.AddPair(CozyText_Lifecycle_sessionId_664e6044, SessionID);
      Body.AddPair(CozyText_Lifecycle_sessionToken_0c22b110, SessionToken); Body.AddPair(CozyText_Lifecycle_targetRole_460d8a30, TargetRole);
      Body.AddPair(CozyText_Lifecycle_requestId_5f08969f, ID);
      Started := Tick;
      Reply := Post(Body, DeadlineTick);
      if (Reply = nil) or (Tick >= DeadlineTick) then Exit;
      { Optional diagnostic reply never extends its caller's time budget. }
      BootstrapValidateObject(Reply,
        CozyText_Lifecycle_version_permitId_nonce_expiresAt_flowId_reporter_e5b57149, 9);
      if (BootstrapInteger(Reply, CozyText_Lifecycle_version_91dbceef) <> 1) or
        (BootstrapString(Reply, CozyText_Lifecycle_reporterRole_d4a60782, 1) <> FRole) or
        (BootstrapString(Reply, CozyText_Lifecycle_targetRole_460d8a30, 1) <> TargetRole) then Exit;
      if TargetRole = FRole then
        if BootstrapString(Reply, CozyText_Lifecycle_targetSessionId_93fc10dc, 128) <> SessionID then Exit;
      Lease := BootstrapInteger(Reply, CozyText_Lifecycle_expiresAt_e9720486) - BootstrapInteger(Reply, CozyText_Lifecycle_serverTime_1a6fe37b);
      if (Lease <= 0) or (Lease > 180000) or (Started + UInt64(Lease) <= Tick) then Exit;
      PermitID := BootstrapString(Reply, CozyText_Lifecycle_permitId_17b57881, 128);
      Nonce := BootstrapString(Reply, CozyText_Lifecycle_nonce_89f2827e, 256);
      if not LowerHex(PermitID, 32) or not LowerHex(Nonce, 48) or
        not SessionIDValid(BootstrapString(Reply, CozyText_Lifecycle_flowId_0d97d578, 32)) or
        not SessionIDValid(BootstrapString(Reply, CozyText_Lifecycle_targetSessionId_93fc10dc, 32)) then Exit;
      WipeText(C.PermitID); WipeText(C.Nonce); WipeText(C.RequestID);
      C.PermitID := PermitID; C.Nonce := Nonce; C.RequestID := ID;
      C.Deadline := Started + UInt64(Lease);
    finally TMonitor.Exit(FRequestLock); end;
    except
      { Diagnostic availability cannot grant/revoke execution or block cleanup. }
    end;
  finally
    Body.Free; Reply.Free;
    WipeText(ID); WipeText(PermitID); WipeText(Nonce);
  end;
end;

procedure TLifecycleReporter.Note(const TargetRole, Event, Status: string;
  PID, Win32Error, ElapsedMs: Cardinal);
var C: TChannel; Entry: TJSONObject; Target: TLifecycleRole;
  Kind: TLifecycleEvent; Outcome: TLifecycleStatus;
begin
  Entry := nil;
  try
    if not ParseLifecycleRole(TargetRole,Target) or
      not ParseLifecycleEvent(Event,Kind) or not ParseLifecycleStatus(Status,Outcome) then Exit;
    C := Channel(TargetRole);
    if C = nil then Exit;
    { A running process cannot observe its own exit. Invalid combinations
      never enter the wire batch, even through this compatibility overload. }
    if (TargetRole = FRole) and (Event = CozyText_Lifecycle_PROCESS_EXIT_2e101ff4) and (Status = CozyText_Lifecycle_OBSERVED_79916346) then Exit;
    { Diagnostics are optional: contention drops a note rather than blocking
      real shutdown/cleanup behind another thread. No network under FLock. }
    if not TMonitor.Enter(FLock,0) then Exit;
    try
      if C.Submitted or not LifecycleCanAppend(C.EventState,FRoleKind,Target,Kind,Outcome) then Exit;
      if C.Events.Count >= LifecycleMaximumEvents then Exit;
      Entry := TJSONObject.Create;
      Entry.AddPair(CozyText_Lifecycle_event_c9266ecf,LifecycleEventNames[Kind]);
      Entry.AddPair(CozyText_Lifecycle_status_88409a75,LifecycleStatusNames[Outcome]);
      if PID <> 0 then Entry.AddPair(CozyText_Lifecycle_pid_0e3baabc,TJSONNumber.Create(Int64(PID)));
      if Win32Error <> 0 then Entry.AddPair(CozyText_Lifecycle_win32Error_83209d74,TJSONNumber.Create(Int64(Win32Error)));
      if ElapsedMs > 600000 then ElapsedMs := 600000;
      if ElapsedMs <> 0 then Entry.AddPair(CozyText_Lifecycle_elapsedMs_2cd5c90e,TJSONNumber.Create(Int64(ElapsedMs)));
      C.Events.AddElement(Entry); Entry := nil;
      LifecycleAppend(C.EventState,Kind,Outcome);
    finally TMonitor.Exit(FLock); end;
  except
    { No malformed partial entry, error output or local retry queue. }
  end;
  Entry.Free;
end;

procedure TLifecycleReporter.ObserveCleanup(const TargetRole: string;
  const Observation: THandoffCleanupObservation; IncludeProcess: Boolean);
var Status: string;
begin
  if IncludeProcess then
  begin
    if Observation.ExitObserved and not Observation.ExitTimedOut and
      (Observation.ProcessID <> 0) then Status := CozyText_Lifecycle_OBSERVED_79916346
    else if Observation.ExitTimedOut then Status := CozyText_Lifecycle_TIMEOUT_f8941f34
    else Status := CozyText_Lifecycle_UNKNOWN_9d12bba5;
    Note(TargetRole, CozyText_Lifecycle_PROCESS_EXIT_2e101ff4, Status, Observation.ProcessID);
  end;
  if Observation.FileRemoved and Observation.CleanupAttempted and
    (Observation.Win32Error = 0) then Status := CozyText_Lifecycle_REMOVED_021473d3
  else if Observation.DispositionAccepted then Status := CozyText_Lifecycle_SCHEDULED_e048700e
  else if Observation.CleanupAttempted then Status := CozyText_Lifecycle_FAILED_f98968f2
  else Status := CozyText_Lifecycle_NOT_ATTEMPTED_73eac021;
  Note(TargetRole, CozyText_Lifecycle_FILE_CLEANUP_60ece5dc, Status, Observation.ProcessID, Observation.Win32Error);
end;

procedure TLifecycleReporter.Submit(const TargetRole: string; DeadlineTick: UInt64);
var C: TChannel; Body, Reply: TJSONObject; Text, Canonical, Signature: string;
  At: UInt64; Count: Integer;
begin
  Body := nil; Reply := nil; Text := ''; Canonical := ''; Signature := '';
  try
    try
      C := Channel(TargetRole);
      if C = nil then Exit;
      At := Tick;
      if (DeadlineTick = 0) or (DeadlineTick > At + 1500) then DeadlineTick := At + 1500;
      if (At >= DeadlineTick) or
        not TMonitor.Enter(FRequestLock, Cardinal(DeadlineTick - At)) then Exit;
      try
        At := Tick;
        if C.Submitted or (C.PermitID = '') or (At >= C.Deadline) then Exit;
        if (DeadlineTick = 0) or (DeadlineTick > At + 1500) then DeadlineTick := At + 1500;
        if C.Deadline < DeadlineTick then DeadlineTick := C.Deadline;
        if At >= DeadlineTick then Exit;
        if not TMonitor.Enter(FLock,0) then Exit;
        try
          Count := C.Events.Count;
          if Count = 0 then Exit;
          Text := C.Events.ToJSON;
          { Freeze the batch even if its response is lost. The retry inside
            Post uses the identical signature, request ID and event bytes. }
          C.Submitted := True;
          C.EventState.Submitted := True;
        finally TMonitor.Exit(FLock); end;
        Canonical := CozyText_Lifecycle_GAME_LIFECYCLE_REPORT_V1_d6092774 + #10 + C.PermitID + #10 +
          C.Nonce + #10 + C.RequestID + #10 + IntegritySHA512Text(Text);
{$IFDEF GAME_LIFECYCLE_CONTRACT_TESTS}
        if Assigned(FTestPost) then Signature := CozyText_Lifecycle_native_probe_signature_817711f7
        else
{$ENDIF}
          Signature := FSecurity.Sign(Canonical);
        Body := TJSONObject.Create;
        Body.AddPair(CozyText_Lifecycle_action_94e5b110, CozyText_Lifecycle_lifecycleReport_8f83210a); Body.AddPair(CozyText_Lifecycle_permitId_17b57881, C.PermitID);
        Body.AddPair(CozyText_Lifecycle_requestId_5f08969f, C.RequestID); Body.AddPair(CozyText_Lifecycle_eventsJson_970db537, Text);
        Body.AddPair(CozyText_Lifecycle_signature_2578be3d, Signature);
        Reply := Post(Body, DeadlineTick);
        if Reply = nil then Exit;
        BootstrapValidateObject(Reply, CozyText_Lifecycle_version_permitId_status_recordedAt_eventCount_618c9c71, 5);
        if (BootstrapInteger(Reply, CozyText_Lifecycle_version_91dbceef) <> 1) or
          (BootstrapString(Reply, CozyText_Lifecycle_permitId_17b57881, 128) <> C.PermitID) or
          (BootstrapString(Reply, CozyText_Lifecycle_status_88409a75, 32) <> CozyText_Lifecycle_RECORDED_0c520fab) or
          (BootstrapInteger(Reply, CozyText_Lifecycle_eventCount_6c86530d) <> Count) then Exit;
      finally
        try
          { Drop JSON references before wiping channel strings. Otherwise
            copy-on-write would erase a new allocation and leave the shared
            token bytes alive until the JSON objects were later freed. }
          FreeAndNil(Body); FreeAndNil(Reply);
          if C.Submitted or ((C.Deadline <> 0) and (Tick >= C.Deadline)) then
            C.ClearGrant;
        finally TMonitor.Exit(FRequestLock); end;
      end;
    except
      { No retry spool, no persistence of permits/tokens, no claimed PASS. }
    end;
  finally
    Body.Free; Reply.Free;
    WipeText(Text); WipeText(Canonical); WipeText(Signature);
  end;
end;

{$IFDEF GAME_LIFECYCLE_CONTRACT_TESTS}
constructor TLifecycleReporter.CreateForTest(const Role: string;
  const PostHook: TLifecycleTestPost);
begin
  inherited Create;
  FLock := TObject.Create; FRequestLock := TObject.Create;
  if not ParseLifecycleRole(Role,FRoleKind) or not Assigned(PostHook) then
    raise EArgumentException.Create(CozyText_Lifecycle_LIFECYCLE_TEST_CONFIGURATION_a02f214a);
  FRole := Role; FTestPost := PostHook;
  FSelf := TChannel.Create(Role);
  if Role='B' then FParent := TChannel.Create('A')
  else if Role='O' then FParent := TChannel.Create('B');
end;
function TLifecycleReporter.SnapshotForTest(const TargetRole: string): TJSONArray;
var C: TChannel;
begin
  C := Channel(TargetRole);
  if C=nil then raise EArgumentException.Create(CozyText_Lifecycle_LIFECYCLE_TEST_CHANNEL_335f734b);
  TMonitor.Enter(FLock);
  try Result := TJSONArray(C.Events.Clone); finally TMonitor.Exit(FLock); end;
end;
procedure TLifecycleReporter.HoldEventLockForTest(const Body: TProc);
begin TMonitor.Enter(FLock); try Body(); finally TMonitor.Exit(FLock); end; end;
{$ENDIF}

initialization

  BindApiPointer(ApiSlot_GetCurrentProcessId,
    RequireProcAddressHash64(CozyText_Lifecycle_kernel32_dll_61e28b81, HASH_GetCurrentProcessId));
end.
