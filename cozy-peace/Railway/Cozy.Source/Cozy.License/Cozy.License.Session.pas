unit Cozy.License.Session;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{$ALIGN 8}
interface
{ Cozy central text imports. }
uses
  Cozy.Strings.License;

function RunLicenseClient: Integer;
implementation
uses Cozy.Clock, Winapi.Windows, System.SysUtils, System.Classes,
  Cozy.SensitiveText, Cozy.License.Commands, Cozy.License.Window,
  Cozy.Api, Cozy.Api.Types, Cozy.Security, Cozy.Lifecycle, Cozy.Bootstrap,
  Cozy.Handoff, Cozy.Integrity, Cozy.CodeIntegrity, Cozy.WinApi,
  Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer,
  Cozy.NHW.Guard, Cozy.NHW.ClientGuard, Cozy.Overlay.ShutdownGuard;
const HeartbeatMilliseconds = 10000;
type
  TLicenseWorker = class(TThread)
  private
    FApi: TGameApi;
    FWatch: TCozyNHWGuard;
    FCommands: TLicenseCommandMailbox;
    FStopEvent, FWakeEvent, FInitializedEvent: THandle;
    FInitializationSucceeded: LongInt;
    FStarted: Boolean;
    function GetState: LongInt;
    function GetProgress: Integer;
    procedure TakePendingKey(var Key: TCozySensitiveText);
    procedure RedeemPending(var Key: TCozySensitiveText);
  protected
    procedure Execute; override;
  public
    constructor Create(Api: TGameApi; Watch: TCozyNHWGuard);
    destructor Destroy; override;
    procedure StartChecks;
    procedure RequestStop;
    procedure StopAndJoin;
    function SubmitKey(var Key: TCozySensitiveText): Boolean;
    property State: LongInt read GetState;
    property Progress: Integer read GetProgress;
  end;
var
  ApiSlot_CloseHandle, ApiSlot_CreateEvent, ApiSlot_SetEvent,
    ApiSlot_WaitForSingleObject, ApiSlot_WaitForMultipleObjects: TEncodedApiPointer;

function CloseHandle(Handle: THandle): BOOL; stdcall;
var
  ApiTarget: TApiCloseHandle;
begin
  ApiTarget := TApiCloseHandle(DecodeApiPointer(ApiSlot_CloseHandle));
  Result := ApiTarget(Handle);
end;

function CreateEvent(Attributes: PSecurityAttributes; ManualReset, InitialState: BOOL;
    Name: PWideChar): THandle; stdcall;
var
  ApiTarget: TApiCreateEvent;
begin
  ApiTarget := TApiCreateEvent(DecodeApiPointer(ApiSlot_CreateEvent));
  Result := ApiTarget(Attributes, ManualReset, InitialState, Name);
end;

function SetEvent(Event: THandle): BOOL; stdcall;
var
  ApiTarget: TApiSetEvent;
begin
  ApiTarget := TApiSetEvent(DecodeApiPointer(ApiSlot_SetEvent));
  Result := ApiTarget(Event);
end;

function WaitForSingleObject(Handle: THandle; Milliseconds: DWORD): DWORD; stdcall;
var
  ApiTarget: TApiWaitForSingleObject;
begin
  ApiTarget := TApiWaitForSingleObject(DecodeApiPointer(ApiSlot_WaitForSingleObject));
  Result := ApiTarget(Handle, Milliseconds);
end;

function WaitForMultipleObjects(Count: DWORD; Handles: Pointer; WaitAll: BOOL;
    Milliseconds: DWORD): DWORD; stdcall;
var
  ApiTarget: TApiWaitForMultipleObjects;
begin
  ApiTarget := TApiWaitForMultipleObjects(DecodeApiPointer(ApiSlot_WaitForMultipleObjects));
  Result := ApiTarget(Count, Handles, WaitAll, Milliseconds);
end;


constructor TLicenseWorker.Create(Api: TGameApi; Watch: TCozyNHWGuard);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FApi := Api;
  FWatch := Watch;
  FCommands := TLicenseCommandMailbox.Create;
  FStopEvent := CreateEvent(nil, True, False, nil);
  if FStopEvent = 0 then RaiseLastOSError;
  FWakeEvent := CreateEvent(nil, False, False, nil);
  if FWakeEvent = 0 then RaiseLastOSError;
  FInitializedEvent := CreateEvent(nil, True, False, nil);
  if FInitializedEvent = 0 then RaiseLastOSError;
end;

procedure TLicenseWorker.StartChecks;
begin
  if FStarted then raise Exception.Create(CozyText_License_Session_Worker_already_started_7158eaa9);
  { Only the newly created suspended thread reaches this call. }
  FStarted := True;
  try
    Start;
  except
    FStarted := False;
    raise;
  end;
  { Called after hidden GPU initialization. OS measurements and network proof
    execute on this worker; the UI is exposed only after the one-use success
    event. Timeout is unavailable authorization, never a detection. }
  if (WaitForSingleObject(FInitializedEvent, 45000) <> WAIT_OBJECT_0) or
    (InterlockedCompareExchange(FInitializationSucceeded, 0, 0) = 0) then
  begin
    RequestStop;
    raise EInvalidOpException.Create('');
  end;
end;

procedure TLicenseWorker.RequestStop;
begin
  if FCommands <> nil then FCommands.Stop;
  Terminate;
  if FApi <> nil then FApi.RequestStop;
  if FStopEvent <> 0 then SetEvent(FStopEvent);
  if FWakeEvent <> 0 then SetEvent(FWakeEvent);
end;

procedure TLicenseWorker.StopAndJoin;
begin
  RequestStop;
  { Never free the API, CNG key or events while Execute can still use them.
    No forced thread termination; each in-flight request has a bounded timeout. }
  if FStarted then
  begin
    WaitFor;
  end;
end;

destructor TLicenseWorker.Destroy;
begin
  StopAndJoin;
  { RTL destruction also joins a never-started/suspended thread after cancelling
    it. Its Execute finally block still owns the mailbox and events until then. }
  inherited Destroy;
  FCommands.Free;
  if FInitializedEvent <> 0 then CloseHandle(FInitializedEvent);
  if FWakeEvent <> 0 then CloseHandle(FWakeEvent);
  if FStopEvent <> 0 then CloseHandle(FStopEvent);
end;

function TLicenseWorker.GetState: LongInt;
begin
  if FWatch.Confirmed then Exit(WorkerFailed);
  Result := FCommands.State;
end;

function TLicenseWorker.GetProgress: Integer;
begin Result := FCommands.Progress; end;

function TLicenseWorker.SubmitKey(var Key: TCozySensitiveText): Boolean;
begin
  Result := False;
  if Terminated or FWatch.Confirmed then Exit;
  if not FCommands.Submit(Key) then Exit;
  if not SetEvent(FWakeEvent) then
  begin FCommands.Complete(WorkerFailed); Exit; end;
  Result := True;
end;

procedure TLicenseWorker.TakePendingKey(var Key: TCozySensitiveText);
begin
  if Key = nil then Key := FCommands.Take;
end;

procedure TLicenseWorker.RedeemPending(var Key: TCozySensitiveText);
var LicenseState: TLicenseState; BoundaryKey: string;
begin
  try
    try
      if Terminated or FCommands.Stopping or FWatch.Confirmed then Exit;
      FCommands.ReportProgress(22);
      BoundaryKey := Key.CopyText;
      { No input/mailbox copy remains while the request is in flight. The API
        temporarily owns its protocol/JSON strings and wipes its pending data. }
      FreeAndNil(Key);
      try LicenseState := FApi.Redeem(BoundaryKey);
      finally WipeText(BoundaryKey); end;
      if Terminated or FCommands.Stopping or FWatch.Confirmed then Exit;
      if not LicenseState.IsActive then
      begin
        FCommands.Complete(WorkerFailed);
        Exit;
      end;
      FWatch.SecurityContext.SetPhase('B_RUNTIME');
      FCommands.ReportProgress(40);
      { O first obtains a live lease and renders its first frame. StartOverlay
        then commits the authenticated server transfer and retires B's session. }
      if not FApi.StartOverlay(False,
        procedure(Value: Integer) begin FCommands.ReportProgress(Value); end) then
        raise EGameApi.Create(CozyText_License_Session_OVERLAY_START_FAILED_0847dea9, CozyText_License_Session_Overlay_authorization_failed_a112f40c);
      { O holds B's exact image identity and deletes it after this process has
        actually exited. Do not attempt active-image unlink or another B proof. }
      FCommands.Complete(WorkerTransferred);
      Terminate;
    except
      on E: EGameApi do
      begin
        { Only a definitive key rejection allows another key in this same
          authorized process. Network, proof and policy failures close it. }
        if (E.Code = CozyText_License_Session_LICENSE_KEY_INVALID_996d8303) or
          (E.Code = CozyText_License_Session_DESKTOP_KEY_INVALID_b25154ea) or (E.Code = CozyText_License_Session_DESKTOP_KEY_USED_659ae6e2) or
          (E.Code = CozyText_License_Session_DESKTOP_EXPIRED_4aaa9749) or (E.Code = CozyText_License_Session_DESKTOP_REVOKED_50a282cf) or
          (E.Code = CozyText_License_Session_DESKTOP_RELEASED_e511ceec) then
        begin
          if not Terminated and not FCommands.Stopping then
            FCommands.Complete(WorkerIdle);
        end
        else
          FCommands.Complete(WorkerFailed);
      end;
      on Exception do
      begin
        FCommands.Complete(WorkerFailed);
      end;
    end;
  finally
    WipeText(BoundaryKey);
    FreeAndNil(Key);
  end;
end;

procedure TLicenseWorker.Execute;
var
  Handles: array[0..1] of THandle;
  NextCheck, NextModules, NowTick, WaitUntil: UInt64;
  WaitResult, WaitMilliseconds: DWORD;
  QueuedKey: TCozySensitiveText;
  PendingModules: Boolean;
begin
  QueuedKey := nil;
  Handles[0] := FStopEvent;
  Handles[1] := FWakeEvent;
  try
    try
      try
        if Terminated or FCommands.Stopping then Exit;
        FApi.CheckIntegrity;
        if Terminated or FCommands.Stopping then Exit;
        if FWatch <> nil then
        begin
          FWatch.SecurityContext.SetPhase('B_ATTESTED');
          FWatch.Start;
        end;
        NextCheck := CozyTick + HeartbeatMilliseconds;
        NextModules := CozyTick;
        InterlockedExchange(FInitializationSucceeded, 1);
      finally
        if FInitializedEvent <> 0 then SetEvent(FInitializedEvent);
      end;
      while not Terminated and not FCommands.Stopping do
      begin
        if WaitForSingleObject(FStopEvent, 0) = WAIT_OBJECT_0 then Break;
        TakePendingKey(QueuedKey);
        if State = WorkerFailed then Break;
        if (QueuedKey <> nil) and FApi.ModuleInventoryReady then
        begin
          RedeemPending(QueuedKey);
          NextCheck := CozyTick + HeartbeatMilliseconds;
          Continue;
        end;
        NowTick := CozyTick;
        if NowTick >= NextCheck then
        begin
          FApi.CheckIntegrity;
          NextCheck := CozyTick + HeartbeatMilliseconds;
          Continue;
        end;
        if NowTick >= NextModules then
        begin
          PendingModules := FApi.ContinueModuleInventory;
          if PendingModules then NextModules := CozyTick + 50
          else NextModules := CozyTick + 1000;
          Continue;
        end;
        WaitUntil := NextCheck;
        if NextModules < WaitUntil then WaitUntil := NextModules;
        NowTick := CozyTick;
        if WaitUntil <= NowTick then WaitMilliseconds := 0
        else if WaitUntil - NowTick > 1000 then WaitMilliseconds := 1000
        else WaitMilliseconds := DWORD(WaitUntil - NowTick);
        WaitResult := WaitForMultipleObjects(Length(Handles), @Handles[0], False,
          WaitMilliseconds);
        if WaitResult = WAIT_OBJECT_0 then Break;
        if (WaitResult <> WAIT_TIMEOUT) and (WaitResult <> WAIT_OBJECT_0 + 1) then
        begin
          FCommands.Complete(WorkerFailed);
          Break;
        end;
      end;
    except
      { No raw exception text, cross-thread exception or local log. }
      FCommands.Complete(WorkerFailed);
    end;
  finally
    FreeAndNil(QueuedKey);
    if FCommands <> nil then FCommands.Stop;
  end;
end;


function RunLicenseClient: Integer;
var
  Context: THandoffContext;
  Bootstrap: TBootstrapClient;
  Session: TBootstrapSession;
  Api: TGameApi;
  Worker: TLicenseWorker;
  Security: TDeviceSecurity;
  OwnDigest: TImageDigest;
  ImageIntegrity: TImageIntegrity;
  CodeIntegrity: TCodeIntegrity;
  Transferred, SecurityStopped: Boolean;
  Watch: TCozyNHWGuard;
  Lifecycle: TLifecycleReporter;
  DiagnosticDeadline: UInt64;
  ShutdownGuard: TOverlayShutdownGuard;
begin
  ShutdownGuard := nil;
  Context := nil;
  ImageIntegrity := nil;
  CodeIntegrity := nil;
  Session := Default(TBootstrapSession);
  Bootstrap := nil;
  Api := nil;
  Worker := nil;
  Watch := nil;
  Lifecycle := nil; Transferred := False; SecurityStopped := False;
  try
    ShutdownGuard := TOverlayShutdownGuard.Create;
    ShutdownGuard.Start;
  try
    try
      { The ImGui window remains hidden until A handoff and the authenticated
        B claim complete. GPU setup then precedes the first own-image proof. }
      Context := THandoffContext.ReceiveFromCommandLine;
      Watch := TCozyNHWClientGuard.Create(nrClient);
      Watch.SecurityContext.SetParentIdentity(Context.ParentIdentity);
      Watch.Start;
      Bootstrap := TBootstrapClient.Create(Context.Profile);
      OwnDigest := IntegrityHashFile(CurrentImagePath);
      Session := Bootstrap.Claim(Context.FlowID, Context.HandoffToken,
        Context.ClaimCanonical, OwnDigest.SHA512, OwnDigest.CRC64,
        OwnDigest.XXH3_128, OwnDigest.Blake3, Context.Security, Context.CodeIntegrity);
      try Lifecycle := TLifecycleReporter.Create(Context.Profile, Context.Security, 'B');
      except Lifecycle := nil; end;
      if Lifecycle <> nil then
      begin
        DiagnosticDeadline := TLifecycleReporter.Tick + 1500;
        Lifecycle.Prepare('B', Session.SessionID, Session.SessionToken, DiagnosticDeadline);
        DiagnosticDeadline := TLifecycleReporter.Tick + 1500;
        Lifecycle.Prepare('A', Session.SessionID, Session.SessionToken, DiagnosticDeadline);
      end;
      try
        Context.CompleteClaimAndCleanup(Session.Release.CRC64);
      finally
        if Lifecycle <> nil then
        begin
          Lifecycle.ObserveCleanup('A', Context.ParentCleanupObservation, True);
          Lifecycle.Submit('A');
        end;
      end;
      ImageIntegrity := Context.TakeImageIntegrity;
      Security := Context.Security;
      Context.Security := nil;
      CodeIntegrity := Context.CodeIntegrity;
      Context.CodeIntegrity := nil;
      try
        try
          Api := TGameApi.Create(Context.Profile, Security,
            Session.SessionID, Session.SessionToken, ImageIntegrity, CodeIntegrity,
            Session.Release.CodeSHA512, Session.Release.CodeCRC64);
          Api.Lifecycle := Lifecycle;
        except
          { A failed constructor has already freed its owned signing key. }
          FreeAndNil(Lifecycle);
          raise;
        end;
      finally
        { Constructor owns both objects even when it raises. }
        ImageIntegrity := nil;
        CodeIntegrity := nil;
      end;
      Session.ReleaseSecrets;
      Api.AttachNHW(Watch, Bootstrap.NHWQuoter);
      Worker := TLicenseWorker.Create(Api, Watch);
      Result := RunLicenseWindow(
        procedure
        begin
          { The hidden window already owns the GPU; the worker snapshots its
            loaded modules only after this initial authenticated proof. }
          { NHW already observes bootstrap on its own worker. This callback
            waits for the GPU-aware server proof before exposing the UI. }
          Worker.StartChecks;
        end,
        function(var Key: TCozySensitiveText): Boolean
        begin Result := Worker.SubmitKey(Key); end,
        function: Integer
        begin Result := Worker.State; end,
        function: Integer
        begin Result := Worker.Progress; end,
        procedure
        begin
          ShutdownGuard.ArmAfter(15000);
          Worker.RequestStop;
        end,
        procedure
        begin Worker.StopAndJoin; end);

    except
      { Fail closed without GUI dialogs, diagnostic output or local logs. }
      Result := 1;
    end;
  finally
    { Arm before any join, including failure paths before the UI was shown.
      The fallback ends only this process and makes no successful-cleanup claim. }
    if ShutdownGuard <> nil then ShutdownGuard.ArmAfter(15000);
    Worker.Free;
    if Watch <> nil then
    begin
      { Seal the decision without waiting on sensor-owned native calls. }
      Watch.SecurityContext.SetPhase('B_SHUTDOWN');
      Watch.RequestStop;
      Watch.StopChildObservers;
      SecurityStopped := Watch.Confirmed;
    end;
    if Api <> nil then Transferred := Api.OverlayTransferred;
    if Api <> nil then Api.FlushNHWReports;
    if Watch <> nil then SecurityStopped := SecurityStopped or Watch.Confirmed;
    if (Api <> nil) and SecurityStopped then Api.FinishNHWStop;
    if SecurityStopped then Result := 1
    else if Transferred then Result := 0;
    if Lifecycle <> nil then
      Lifecycle.Note('B', CozyText_License_Session_SHUTDOWN_BEGIN_872154f9, CozyText_License_Session_REQUESTED_4c4cdecb, TLifecycleReporter.ProcessID);
    if Api <> nil then Api.RetireImagesForShutdown;
    if (Context <> nil) and (not Transferred or SecurityStopped) then
    begin
      Context.CleanupOwnImageForShutdown;
      if Lifecycle <> nil then
        Lifecycle.ObserveCleanup('B', Context.OwnCleanupObservation, False);
    end;
    { Worker.Free joins the only API worker. A confirmed transfer has already
      retired B server-side; exit without another network request. All failure
      and untransferred paths still attempt the existing authenticated Close. }
    if (Bootstrap <> nil) and not Transferred then
    begin
      try
        Bootstrap.Close;
        if Lifecycle <> nil then Lifecycle.Note('B', CozyText_License_Session_CLOSE_RESPONSE_aa9ed7a0, CozyText_License_Session_ACKNOWLEDGED_0130bd13);
      except
        if Lifecycle <> nil then Lifecycle.Note('B', CozyText_License_Session_CLOSE_RESPONSE_aa9ed7a0, CozyText_License_Session_FAILED_f5087b2d);
        { No local retry token. The server lease bounds abrupt disconnection. }
      end;
    end;
    if Lifecycle <> nil then Lifecycle.Submit('B', TLifecycleReporter.Tick + 1500);
    Lifecycle.Free;
    Api.Free;
    Bootstrap.Free;
    Context.Free;
    ImageIntegrity.Free;
    CodeIntegrity.Free;
    Session.ReleaseSecrets;
    { The independent sensor owns no Cozy transport or integrity reader.
      The authority close and verified file cleanup precede its final join. }
    Watch.Free;
  end;
  finally
    if ShutdownGuard <> nil then
    begin ShutdownGuard.Cancel; ShutdownGuard.Free; end;
  end;
end;

initialization
  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_License_Session_kernel32_dll_89da6709, HASH_CloseHandle));
  BindApiPointer(ApiSlot_CreateEvent, RequireProcAddressHash64(CozyText_License_Session_kernel32_dll_89da6709, HASH_CreateEventW));
  BindApiPointer(ApiSlot_SetEvent, RequireProcAddressHash64(CozyText_License_Session_kernel32_dll_89da6709, HASH_SetEvent));
  BindApiPointer(ApiSlot_WaitForSingleObject, RequireProcAddressHash64(CozyText_License_Session_kernel32_dll_89da6709, HASH_WaitForSingleObject));
  BindApiPointer(ApiSlot_WaitForMultipleObjects, RequireProcAddressHash64(CozyText_License_Session_kernel32_dll_89da6709, HASH_WaitForMultipleObjects));
end.
