unit Cozy.Overlay;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Overlay;

function RunOverlay: Integer;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
procedure OverlayTestTerminalWorker(Guard: TObject);
{$ENDIF}
implementation
uses Cozy.Clock, Winapi.Windows, System.SysUtils, System.Classes, System.SyncObjs, Cozy.ShutdownBudget, Cozy.Overlay.ShutdownGuard,
  Cozy.Lifecycle, Cozy.Security, Cozy.Bootstrap, Cozy.Handoff, Cozy.Integrity,
  Cozy.CodeIntegrity, Cozy.Overlay.Client, Cozy.Overlay.Renderer,
  Cozy.Measurement, Cozy.Overlay.State, Cozy.Transport, Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer
  , Cozy.NHW.Guard, Cozy.NHW.ClientGuard
  {$IFDEF GAME_PRODUCT_FAULT_TESTS}, Cozy.ProductFaults{$ENDIF};
type
  TOverlayWorker = class(TThread)
  private
    FLock: TObject;
    FCompleted: TEvent;
    FStarted: Boolean;
    FFailed: Boolean;
    FReadyForTransfer: Boolean;
    FTransferred, FParentRetirementDone, FCapturePrivacy: Boolean;
    {$IFDEF GAME_PRODUCT_FAULT_TESTS}
    FLeaseRenewalHeld: Boolean;
    {$ENDIF}
    FDeadline, FLastRefreshDuration, FInitialDeadline, FLastSnapshotAt: UInt64;
    FLastSnapshotDuration: UInt64;
    FVisibleReportPending: Boolean;
    FProductCard, FRunProductCard, FProductRunState: Integer;
    FProductRunQueued: Boolean;
    FProductRunQueuedAt, FProductGrantDeadline: UInt64;
    FState: TOverlayState;
    FContext: THandoffContext;
    FClient: TOverlayClient;
    FImage: TImageIntegrity;
    FShutdownGuard: TOverlayShutdownGuard;
    FWatch: TCozyNHWGuard;
    function ConfirmedWatch: Boolean;
    procedure ProcessProductRun;
    function NextRenewal: UInt64;
    procedure Refresh;
    procedure RenewLease(const Image: TImageDigest; RefreshStarted: UInt64);
    procedure MaintainLease(Force: Boolean);
    function AwaitingTransfer: Boolean;
    function RequestCancelled: Boolean;
    function RecoverTransientRenewal(const TransportCode: string; var Retried: Boolean): Boolean;
    procedure NoteRenewalFailure(const TransportCode: string);
  protected
    procedure Execute; override;
  public
    constructor Create(Context: THandoffContext; Client: TOverlayClient; Image: TImageIntegrity; Guard: TOverlayShutdownGuard;
      Watch: TCozyNHWGuard = nil);
    destructor Destroy; override;
    procedure StartAuthorized;
    procedure Stop;
    procedure MarkClosed;
    function JoinBefore(DeadlineTick: UInt64): Boolean;
    procedure FirstFrameReady;
    function ShouldClose: Boolean;
    function CapturePrivacyRequested: Boolean;
    function LicensedCard: Integer;
    function RequestProductRun(Card: Integer): Boolean;
    function ProductRunState: Integer;
  end;

constructor TOverlayWorker.Create(Context: THandoffContext; Client: TOverlayClient;
  Image: TImageIntegrity; Guard: TOverlayShutdownGuard; Watch: TCozyNHWGuard);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FLock := TObject.Create;
  FCompleted := TEvent.Create(nil, True, False, '');
  FState := osCreated;
  FProductCard := -1; FRunProductCard := -1;
  FInitialDeadline := CozyTick + 90000;
  FContext := Context; FClient := Client; FImage := Image;
  FShutdownGuard := Guard;
  FWatch := Watch;
end;
destructor TOverlayWorker.Destroy;
begin
  Stop;
  inherited Destroy;
  FCompleted.Free;
  FLock.Free;
end;
procedure TOverlayWorker.Stop;
begin
  Terminate;
  if FShutdownGuard <> nil then FShutdownGuard.Arm(CozyTick+OverlayShutdownTotalMs);
  if FClient <> nil then FClient.CancelPending;
  if FLock = nil then Exit;
  TMonitor.Enter(FLock);
  try
    if not (FState in [osClosing, osClosed]) then OverlayTransition(FState, osClosing);
    { Closing is sticky: a reply already in flight cannot reopen this lease. }
    FFailed := True;
    FDeadline := 0;
    FProductCard := -1; FProductRunQueued := False;
    FProductRunState := 3; FProductGrantDeadline := 0;
  finally TMonitor.Exit(FLock); end;
end;
function TOverlayWorker.JoinBefore(DeadlineTick: UInt64): Boolean;
var At, Left: UInt64;
begin
  if not FStarted then begin FStarted := True; Start; end;
  At := CozyTick;
  if At >= DeadlineTick then Exit(FCompleted.WaitFor(0) = wrSignaled);
  Left := DeadlineTick - At; if Left > 120000 then Left := 120000;
  Result := FCompleted.WaitFor(Cardinal(Left)) = wrSignaled;
end;
procedure TOverlayWorker.MarkClosed;
begin
  TMonitor.Enter(FLock);
  try
    if FState = osClosing then OverlayTransition(FState, osClosed);
  finally TMonitor.Exit(FLock); end;
end;
function TOverlayWorker.NextRenewal: UInt64;
begin
  TMonitor.Enter(FLock);
  try Result := OverlayNextRenewal(CozyTick, FDeadline, FLastRefreshDuration);
  finally TMonitor.Exit(FLock); end;
end;
function TOverlayWorker.AwaitingTransfer: Boolean;
begin
  TMonitor.Enter(FLock);
  try Result := FReadyForTransfer;
  finally TMonitor.Exit(FLock); end;
end;
function TOverlayWorker.ConfirmedWatch: Boolean;
begin
  Result := (FWatch <> nil) and FWatch.Confirmed;
end;

function TOverlayWorker.RequestCancelled: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    { Zero is permitted only while acquiring the first lease, before any UI.
      A closed lease has FFailed set and cannot re-enter this initial state. }
    Result := Terminated or FFailed or ConfirmedWatch or
      ((FDeadline = 0) and (CozyTick >= FInitialDeadline)) or
      ((FDeadline <> 0) and (CozyTick >= FDeadline)) or
      (not FReadyForTransfer and not FContext.ParentIsAlive);
    if Result then
    begin
      if (FDeadline <> 0) and (CozyTick >= FDeadline) and
        (FClient <> nil) and (FClient.Lifecycle <> nil) then
        FClient.Lifecycle.Note('O', CozyText_Overlay_LEASE_EXPIRED_a465da69, CozyText_Overlay_OBSERVED_ef4305a1);
      FFailed := True;
      FDeadline := 0;
      if FShutdownGuard <> nil then FShutdownGuard.Arm(CozyTick+OverlayShutdownTotalMs);
    end;
  finally TMonitor.Exit(FLock); end;
end;
procedure TOverlayWorker.FirstFrameReady;
begin
  { Called only by the renderer after its first successful authorized frame. }
  TMonitor.Enter(FLock);
  try
    { Recheck authorization under the same lock as the ready signal. A frame
      may finish while the background worker rejects or expires its lease. }
    if Terminated or FFailed or (FDeadline = 0) or
      (CozyTick >= FDeadline) or
      (not FReadyForTransfer and not FContext.ParentIsAlive) then
    begin
      if (FDeadline <> 0) and (CozyTick >= FDeadline) and
        (FClient <> nil) and (FClient.Lifecycle <> nil) then
        FClient.Lifecycle.Note('O', CozyText_Overlay_LEASE_EXPIRED_a465da69, CozyText_Overlay_OBSERVED_ef4305a1);
      FFailed := True;
      FDeadline := 0;
      if FShutdownGuard <> nil then FShutdownGuard.Arm(CozyTick+OverlayShutdownTotalMs);
      raise EBootstrap.Create(CozyText_Overlay_OVERLAY_INITIAL_AUTHORIZATION_FAILED_ab3b97b6);
    end;
    if FReadyForTransfer then Exit;
    { Publish readiness only after the local handoff event has been signaled
      and its handle retired. The worker cannot start parent cleanup midway. }
    try
      FContext.ConfirmOverlayReady;
      OverlayTransition(FState, osVisible);
      FReadyForTransfer := True;
      FVisibleReportPending := True;
    except
      if (FDeadline <> 0) and (CozyTick >= FDeadline) and
        (FClient <> nil) and (FClient.Lifecycle <> nil) then
        FClient.Lifecycle.Note('O', CozyText_Overlay_LEASE_EXPIRED_a465da69, CozyText_Overlay_OBSERVED_ef4305a1);
      FFailed := True;
      FDeadline := 0;
      if FShutdownGuard <> nil then FShutdownGuard.Arm(CozyTick+OverlayShutdownTotalMs);
      raise;
    end;
  finally TMonitor.Exit(FLock); end;
end;
procedure TOverlayWorker.Refresh;
var Image: TImageDigest; RefreshStarted, LeaseStarted: UInt64;
  Budget: TMeasurementBudget;
  IncludeModules: Boolean;
begin
  if RequestCancelled then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_CLOSED_4a2ab4d8);
  RefreshStarted := CozyTick;
  Budget := TMeasurementBudget.Start(64 * 1024 * 1024, 30000,
    function: Boolean begin Result := RequestCancelled; end);
  try
    Image := FImage.VerifyNow(Budget);
  except
    on E: Exception do
    begin
      try
        FClient.ReportIntegrity(FContext.Security, FContext.CodeIntegrity,
          Default(TImageDigest), False,
          function: Boolean begin Result := RequestCancelled; end,
          MeasurementFailureStatus(E));
      except
        { Shutdown/offline diagnostics are best effort, never permission. }
      end;
      raise;
    end;
  end;
  { Schedule from successful COMPLETE report acceptance, not collection start.
    Until the transfer is confirmed, full inventory must not delay retiring B.
    Server RequireSnapshot still enforces the same freshness and completeness. }
  IncludeModules := OverlaySnapshotDue(CozyTick, FLastSnapshotAt, FTransferred,
    FClient.SnapshotDeadlineTick, FLastSnapshotDuration);
  FClient.ReportIntegrity(FContext.Security, FContext.CodeIntegrity, Image,
    IncludeModules,
    function: Boolean begin Result := RequestCancelled; end, msMeasured, FImage,
    procedure(Force: Boolean) begin MaintainLease(Force); end);
  if IncludeModules then
  begin
    FLastSnapshotAt := CozyTick;
    FLastSnapshotDuration := FLastSnapshotAt - RefreshStarted;
  end;
  LeaseStarted := RefreshStarted;
  { Startup/full-inventory duration is NOT a cheap renewal estimate. Mixing
    them made NextRenewal return NOW after a 53-second successful startup. }
  if IncludeModules then LeaseStarted := CozyTick;
  RenewLease(Image, LeaseStarted);
end;

procedure TOverlayWorker.MaintainLease(Force: Boolean);
var Needed, SnapshotLimited: Boolean; Image: TImageDigest; Started, Ceiling: UInt64;
  Budget: TMeasurementBudget;
begin
  if RequestCancelled then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_CLOSED_4a2ab4d8);
  SnapshotLimited := FClient.LeaseSnapshotLimited;
  TMonitor.Enter(FLock);
  try
    Ceiling := 0;
    if SnapshotLimited then Ceiling := FDeadline;
    Needed := OverlayLeaseNeedsMaintenance(CozyTick, FDeadline,
      FLastRefreshDuration, Force, Ceiling);
  finally TMonitor.Exit(FLock); end;
  if not Needed then Exit;
  Started := CozyTick;
  Budget := TMeasurementBudget.Start(64 * 1024 * 1024, 30000,
    function: Boolean begin Result := RequestCancelled; end);
  Image := FImage.VerifyNow(Budget);
  { Verify obtains a new challenge, complete own-image/CRC evidence and server
    authorization. It never promotes an in-progress inventory to success. }
  RenewLease(Image, Started);
end;

procedure TOverlayWorker.RenewLease(const Image: TImageDigest; RefreshStarted: UInt64);
var Deadline: UInt64; Lease: Int64; Attempt: Integer;
  PrivacyRequested, ParentExited, TransferConfirmed, CleanupParent: Boolean;
  ProductCard: Integer;
begin
  if RequestCancelled then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_CLOSED_4a2ab4d8);
  { B may commit/exit after the server prepared a pre-transfer response.
    At most one new verification resolves that race. Never change a response's
    transfer flag locally, replay an old grant, or wait past the old deadline. }
  for Attempt := 1 to 2 do
  begin
    if RequestCancelled then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_CLOSED_4a2ab4d8);
    Lease := FClient.Verify(FContext.Security, FContext.CodeIntegrity, Image,
      function: Boolean begin Result := RequestCancelled; end);
    if (Lease <= 0) or (Lease > 120000) or
      (RefreshStarted > High(UInt64) - UInt64(Lease)) then
      raise EBootstrap.Create(CozyText_Overlay_OVERLAY_LEASE_EXPIRED_910b407b);
    PrivacyRequested := FClient.CapturePrivacy;
    ProductCard := FClient.ProductCard;
    Deadline := FClient.LeaseDeadlineTick;
    if (Deadline <= CozyTick) or RequestCancelled then
      raise EBootstrap.Create(CozyText_Overlay_OVERLAY_LEASE_EXPIRED_910b407b);
    ParentExited := not FContext.ParentIsAlive;
    TransferConfirmed := FClient.TransferConfirmed;
    if not ParentExited or TransferConfirmed then Break;
    if Attempt = 2 then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_TRANSFER_NOT_CONFIRMED_b6ddbda3);
  end;
  TMonitor.Enter(FLock);
  try
    { A late reply cannot revive an expired or stopped lease. Publish the fresh
      bound BEFORE filesystem cleanup and best-effort diagnostic networking. }
    if Terminated or FFailed or (Deadline <= CozyTick) or
      ((FDeadline <> 0) and (CozyTick >= FDeadline)) or ConfirmedWatch then
    begin
      if (FDeadline <> 0) and (CozyTick >= FDeadline) and
        (FClient <> nil) and (FClient.Lifecycle <> nil) then
        FClient.Lifecycle.Note('O', CozyText_Overlay_LEASE_EXPIRED_a465da69, CozyText_Overlay_OBSERVED_ef4305a1);
      FFailed := True;
      FDeadline := 0;
      if FShutdownGuard <> nil then FShutdownGuard.Arm(CozyTick+OverlayShutdownTotalMs);
      raise EBootstrap.Create(CozyText_Overlay_OVERLAY_LEASE_EXPIRED_910b407b);
    end;
    if FState = osCreated then OverlayTransition(FState, osAuthorized);
    FDeadline := Deadline;
    FCapturePrivacy := PrivacyRequested;
    FProductCard := ProductCard;
    FLastRefreshDuration := CozyTick - RefreshStarted;
    { Server transfer and OS process exit are separate facts. Never suppress
      periodic full snapshots just because the retired B is still exiting. }
    if TransferConfirmed and not FTransferred then
    begin
      OverlayTransition(FState, osTransferred);
      FTransferred := True;
    end;
    CleanupParent := ParentExited and FTransferred and not FParentRetirementDone;
  finally TMonitor.Exit(FLock); end;
  FClient.PrepareLifecycle(Deadline);
  if CleanupParent then
  begin
    { Same ownership model as B retiring A: only the authenticated, pinned
      parent file, and only after the exact process handle is signalled. }
    try
      FContext.CleanupTransferredParent;
      FParentRetirementDone := True;
      { An inherited B launch handle is expected until the exact parent exits. }
      if (FWatch <> nil) and not Terminated then FWatch.Start;
    finally
      if FClient.Lifecycle <> nil then
      begin
        FClient.Lifecycle.ObserveCleanup('B', FContext.ParentCleanupObservation, True);
        FClient.Lifecycle.Submit('B');
      end;
    end;
  end;
  {$IFDEF GAME_PRODUCT_FAULT_TESTS}
  if FTransferred then
  begin
    ProductFaultLeaseGranted(FClient.LeaseRequestTick, UInt64(Lease), Deadline);
    if ProductFaultTriggered(CozyText_Overlay_overlay_lease_expiry_c0ded1f7) or
      ProductFaultTriggered(CozyText_Overlay_authority_local_stop_held_55ca47f7) then
      FLeaseRenewalHeld := True;
  end;
  {$ENDIF}
end;
procedure TOverlayWorker.StartAuthorized;
begin
  try
    Refresh;
  except
    FClient.StartupPhase(CozyText_Overlay_FAILED_bb4aeb6f);
    Stop;
    FStarted := True;
    Start; { ensure suspended thread can be joined even on initial rejection }
    raise;
  end;
  FStarted := True;
  Start;
end;
function TOverlayWorker.CapturePrivacyRequested: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    Result := FCapturePrivacy and not Terminated and not FFailed and
      (FDeadline <> 0) and (CozyTick < FDeadline) and
      (FState in [osAuthorized, osVisible, osTransferred]);
  finally TMonitor.Exit(FLock); end;
end;
function TOverlayWorker.LicensedCard: Integer;
begin
  TMonitor.Enter(FLock);
  try
    Result := -1;
    if not Terminated and not FFailed and FTransferred and
      (FDeadline > CozyTick) then Result := FProductCard;
  finally TMonitor.Exit(FLock); end;
end;

function TOverlayWorker.RequestProductRun(Card: Integer): Boolean;
begin
  { UI thread publishes a bounded primitive command only; no transport lock,
    signature operation, network I/O or borrowed API context is used here. }
  TMonitor.Enter(FLock);
  try
    Result := not Terminated and not FFailed and not ConfirmedWatch and FTransferred and
      (FState = osTransferred) and (FDeadline > CozyTick) and
      (FProductRunState = 0) and not FProductRunQueued and
      OverlayProductCanStart(FProductCard, Card);
    if Result then
    begin
      FRunProductCard := Card; FProductRunQueuedAt := CozyTick;
      FProductRunState := 1; FProductRunQueued := True;
      FProductGrantDeadline := 0;
    end;
  finally TMonitor.Exit(FLock); end;
end;

function TOverlayWorker.ProductRunState: Integer;
begin
  TMonitor.Enter(FLock);
  try
    Result := FProductRunState;
    if Result = 2 then
    begin
      { A delayed UI must not resurrect a reply which no longer covers the
        product presentation. Consumed approvals cannot be reused. }
      if Terminated or FFailed or (FDeadline <= CozyTick) or
        (FProductGrantDeadline <= CozyTick +
          OverlayProductRunMilliseconds(FRunProductCard) + OverlayRunGrantMarginMilliseconds) or ConfirmedWatch then Result := 3;
    end;
    if Result in [2,3] then
    begin FProductRunState := 0; FProductGrantDeadline := 0; end;
  finally TMonitor.Exit(FLock); end;
end;

procedure TOverlayWorker.ProcessProductRun;
var Card: Integer; QueuedAt, GrantDeadline: UInt64; Pending: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    Pending := FProductRunQueued;
    FProductRunQueued := False;
    Card := FRunProductCard; QueuedAt := FProductRunQueuedAt;
  finally TMonitor.Exit(FLock); end;
  if not Pending then Exit;
  try
    if RequestCancelled or (CozyTick < QueuedAt) or
      (CozyTick - QueuedAt > 30000) then
      raise EBootstrap.Create(CozyText_Overlay_OVERLAY_START_REQUEST_EXPIRED_0898be5f);
    { Refresh the normal own-image proof if needed. START itself never renews
      authority or supplies a substitute for the periodic integrity pipeline. }
    MaintainLease(False);
    if RequestCancelled then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_START_CANCELLED_0b3ee3d2);
    GrantDeadline := FClient.AuthorizeProductStart(FContext.Security, Card,
      function: Boolean begin Result := RequestCancelled; end);
  except
    on E: Exception do
    begin
      { Denial is a bounded UI result. An immediate ordinary verification in
        Execute below still closes revoked, expired or invalid authority. }
      GrantDeadline := 0;
    end;
  end;
  TMonitor.Enter(FLock);
  try
    if Terminated or FFailed or (FDeadline <= CozyTick) or
      not OverlayProductCanStart(FProductCard, Card) or
      (GrantDeadline <= CozyTick +
        OverlayProductRunMilliseconds(Card) + OverlayRunGrantMarginMilliseconds) or ConfirmedWatch then
    begin
      FProductRunState := 3; FProductGrantDeadline := 0;
      FProductCard := -1;
    end
    else
    begin
      FProductGrantDeadline := GrantDeadline;
      FProductRunState := 2;
    end;
  finally TMonitor.Exit(FLock); end;
end;

function TOverlayWorker.ShouldClose: Boolean;
begin
  TMonitor.Enter(FLock);
  try
    {$IFDEF GAME_PRODUCT_FAULT_TESTS}
    if not Terminated and not FFailed and not ConfirmedWatch and FTransferred and
      ProductFaultHoldLocalStop(FDeadline) then Exit(False);
    {$ENDIF}
    Result := Terminated or FFailed or ConfirmedWatch or (FDeadline = 0) or
      (CozyTick >= FDeadline) or
      (not FReadyForTransfer and not FContext.ParentIsAlive);
    if Result then
    begin
      if (FDeadline <> 0) and (CozyTick >= FDeadline) and
        (FClient <> nil) and (FClient.Lifecycle <> nil) then
        FClient.Lifecycle.Note('O', CozyText_Overlay_LEASE_EXPIRED_a465da69, CozyText_Overlay_OBSERVED_ef4305a1);
      FFailed := True;
      FDeadline := 0;
      if FShutdownGuard <> nil then FShutdownGuard.Arm(CozyTick+OverlayShutdownTotalMs);
    end;
  finally TMonitor.Exit(FLock); end;
end;
function TOverlayWorker.RecoverTransientRenewal(const TransportCode: string;
  var Retried: Boolean): Boolean;
var Allowed: Boolean;
begin
  Result := False;
  TMonitor.Enter(FLock);
  try
    Allowed := not Terminated and not FFailed and FReadyForTransfer and
      OverlayTransientRetryAllowed(CozyTick, FDeadline,
        FLastRefreshDuration, Retried, TransportCode);
    if Allowed then Retried := True;
  finally TMonitor.Exit(FLock); end;
  if not Allowed then Exit;
  { A timeout does not cancel the transport generation. Never reset a user
    stop/cancellation or alter the existing lease to make this retry fit. }
  CozyWaitForDelay(250, function: Boolean begin Result := RequestCancelled; end);
  if RequestCancelled then Exit;
  { Fresh own-image evidence, a fresh challenge/nonce and the normal server
    verification must succeed before the old grant expires. Snapshot freshness,
    revocation and every normal publication guard remain authoritative. }
  MaintainLease(True);
  Result := not RequestCancelled;
end;

procedure TOverlayWorker.NoteRenewalFailure(const TransportCode: string);
var Outcome: string;
begin
  if (FClient = nil) or (FClient.Lifecycle = nil) then Exit;
  if TransportCode = CozyText_Overlay_CONNECT_TIMEOUT_2f9e6659 then Outcome := CozyText_Overlay_TIMEOUT_67fe68e8
  else Outcome := CozyText_Overlay_FAILED_bb4aeb6f;
  { Closed enums only. Exception messages, paths, secrets and raw transport
    responses never enter a lifecycle batch. Submission uses normal cleanup. }
  FClient.Lifecycle.Note('O', CozyText_Overlay_RENEWAL_FAILED_7d91537c, Outcome);
end;

procedure TOverlayWorker.Execute;
var NextCheck: UInt64; ReportVisible, Retried, ProductPending: Boolean;
begin
  try
  try
    NextCheck := NextRenewal;
    Retried := False;
    while not Terminated do
    begin
      if ShouldClose then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_CLOSED_4a2ab4d8);
      { Initial authorization completed before Start. Give the UI its first
        frame; do not race a new full report against ConfirmOverlayReady. }
      if not AwaitingTransfer then
      begin
        CozyWaitForDelay(100, function: Boolean begin Result := Terminated; end);
        Continue;
      end;
      TMonitor.Enter(FLock);
      try
        ReportVisible := FVisibleReportPending;
        FVisibleReportPending := False;
      finally TMonitor.Exit(FLock); end;
      if ReportVisible then FClient.StartupPhase(CozyText_Overlay_VISIBLE_3f892da5);
      {$IFDEF GAME_PRODUCT_FAULT_TESTS}
      if FLeaseRenewalHeld then
      begin
        CozyWaitForDelay(100, function: Boolean begin Result := Terminated; end);
        Continue;
      end;
      {$ENDIF}
      try
      if FParentRetirementDone and (FWatch <> nil) and
        FWatch.ConsumeRevalidationRequest then
      begin
        { Preserve B retirement priority. The O owner then collects a new full
          inventory and the ordinary nonce-bound attestation/lease proof. }
        FLastSnapshotAt := 0;
        NextCheck := CozyTick;
      end;
      if not FParentRetirementDone and not FContext.ParentIsAlive then
      begin
        { Confirm committed transfer and retire B without a full module scan. }
        MaintainLease(True);
        NextCheck := NextRenewal;
        Retried := False;
      end
      else if CozyTick >= NextCheck then
      begin
        Refresh;
        NextCheck := NextRenewal;
        Retried := False;
      end;
      except
        on E: EConnectTransport do
        begin
          if not RecoverTransientRenewal(E.Code, Retried) then raise;
          { Recovery renews only the ordinary current grant. Retry the complete
            periodic transaction once; partial inventory never becomes trusted. }
          NextCheck := CozyTick;
          Continue;
        end;
      end;
      TMonitor.Enter(FLock);
      try ProductPending := FProductRunQueued;
      finally TMonitor.Exit(FLock); end;
      if ProductPending then
      begin
        ProcessProductRun;
        { Refresh after every attempted command, including a server denial.
          The existing authorization/expiry checks remain the only lease. }
        NextCheck := CozyTick;
      end;
      CozyWaitForDelay(100, function: Boolean begin Result := Terminated; end);
    end;
  except
    on E: Exception do
    begin
      if not Terminated and not ConfirmedWatch then
      begin
        if E is EConnectTransport then NoteRenewalFailure(EConnectTransport(E).Code)
        else NoteRenewalFailure('');
      end;
      { Rejected proof, exhausted retry, cancellation or expiry still revokes
        this local window and arms the independent shutdown guard. }
      Stop;
    end;
  end;
  finally if FCompleted <> nil then FCompleted.SetEvent; end;
end;
{$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
procedure OverlayTestTerminalWorker(Guard: TObject);
var Worker: TOverlayWorker;
begin
  if not (Guard is TOverlayShutdownGuard) then raise EArgumentException.Create(CozyText_Overlay_TEST_GUARD_REQUIRED_020520d6);
  { Exercise the same Stop/terminal path from a non-UI owner. No Context,
    network operation or synthetic authorization is needed for terminal Stop. }
  Worker := TOverlayWorker.Create(nil,nil,nil,TOverlayShutdownGuard(Guard));
  try
    Worker.Stop;
    Worker.JoinBefore(CozyTick+1000);
    Worker.WaitFor;
  finally Worker.Free; end;
end;
{$ENDIF}

function RunOverlay: Integer;
var Context: THandoffContext; Client: TOverlayClient;
  Image: TImageIntegrity; Worker: TOverlayWorker; Session: TBootstrapSession;
  ReadySent, ClosingStarted: Boolean; Budget: TShutdownBudget; JoinedInBudget: Boolean;
  Guard: TOverlayShutdownGuard;
  Watch: TCozyNHWGuard;
  BeginShutdown: TProc;
  ReportNow, ReportBudget: UInt64;
begin
  Result := 1;
  ReadySent := False; ClosingStarted := False; Guard := nil; Watch := nil;
  Context := nil; Client := nil; Image := nil; Worker := nil;
  Session := Default(TBootstrapSession);
  BeginShutdown :=
    procedure
    begin
      if ClosingStarted then Exit;
      ClosingStarted := True;
      if (Client <> nil) and (Client.Lifecycle <> nil) then
        Client.Lifecycle.Note('O', CozyText_Overlay_SHUTDOWN_BEGIN_f364965e, CozyText_Overlay_REQUESTED_5d38a35e, TLifecycleReporter.ProcessID);
      Budget.BeginAt(CozyTick);
      if Guard <> nil then
      begin Guard.Arm(Budget.Deadline); Budget.ConstrainTo(Guard.Deadline); end;
      if Watch <> nil then
      begin
        Watch.SecurityContext.SetPhase('O_SHUTDOWN');
        Watch.RequestStop;
      end;
      if Worker <> nil then Worker.Stop;
    end;
  try
    { Reject ordinary command-line execution before making any UI. The role
      is separately checked inside the inherited handoff wire header. }
    if (ParamCount <> 2) or (ParamStr(1) <> CozyText_Overlay_game_overlay_7b974ebd) then Exit;
    Context := THandoffContext.ReceiveOverlayFromCommandLine;
    Watch := TCozyNHWClientGuard.Create(nrOverlay);
    Watch.SecurityContext.SetParentIdentity(Context.ParentIdentity);
    Watch.Start;
    Client := TOverlayClient.Create(Context.Profile);
    Session := Client.Claim(Context.FlowID, Context.HandoffToken,
      Context.ClaimCanonical, Context.Security, Context.CodeIntegrity);
    Context.CompleteOverlayClaim(Session.Release.CRC64);
    Client.StartupPhase(CozyText_Overlay_IMAGE_BOUND_ae52f09d);
    Image := Context.TakeImageIntegrity;
    Guard := TOverlayShutdownGuard.Create;
    Guard.Start;
    Client.AttachNHW(Watch);
    Worker := TOverlayWorker.Create(Context, Client, Image, Guard, Watch);
    try
    Result := RunOverlayUI(
      procedure
      begin
        { Renderer invokes Tick only after its first successful visible D3D11
          Present. B is acknowledged after both authorization and visible UI. }
        if not ReadySent then
        begin
          Worker.FirstFrameReady;
          Watch.SecurityContext.SetPhase('O_RUNTIME');
          ReadySent := True;
        end;
      end,
      function: Boolean begin Result := Worker.ShouldClose; end,
      BeginShutdown,
      procedure
      begin
        Worker.StartAuthorized;
        if Worker.ShouldClose then raise EBootstrap.Create(CozyText_Overlay_OVERLAY_INITIAL_AUTHORIZATION_FAILED_ab3b97b6);
        Watch.SecurityContext.SetPhase('O_ATTESTED');
      end,
      function: Boolean begin Result := Worker.CapturePrivacyRequested; end,
      procedure
      begin
        if (Client <> nil) and (Client.Lifecycle <> nil) then
          Client.Lifecycle.Note('O', CozyText_Overlay_UI_HIDDEN_b4dcf569, CozyText_Overlay_OBSERVED_ef4305a1);
      end,
      procedure(Phase: string)
      begin Client.StartupPhase(Phase); end,
      nil,nil,nil,nil,
      procedure(Stage: string; NativeCode: Integer)
      begin Client.StartupFailure(Stage, NativeCode); end,
      procedure(NativeCode: Integer)
      begin
        { UI-thread callback records bounded primitives only. Ordinary close,
          Escape and authority expiry do not report a graphics failure. }
        if (Client <> nil) and (Client.Lifecycle <> nil) then
          Client.Lifecycle.Note('O', CozyText_Overlay_UI_RUNTIME_FAILURE_8355e80b, CozyText_Overlay_FAILED_bb4aeb6f,
            0, Cardinal(NativeCode));
      end,
      function: Integer begin Result := Worker.LicensedCard; end,
      function(Card: Integer): Boolean begin Result := Worker.RequestProductRun(Card); end,
      function: Integer begin Result := Worker.ProductRunState; end);
    if (Result <> 0) and not Watch.Confirmed then
      Client.StartupPhase(CozyText_Overlay_FAILED_bb4aeb6f);
    except
      Client.StartupPhase(CozyText_Overlay_FAILED_bb4aeb6f);
      raise;
    end;
  finally
    BeginShutdown;
    if Worker <> nil then
    begin
      Worker.Stop;
      JoinedInBudget := Worker.JoinBefore(Budget.JoinDeadline);
      if not JoinedInBudget then
      begin
        try TOverlayClient.CloseSessionSnapshot(Context.Profile, Session,
          Budget.Deadline, CozyTick-Budget.Started);
        except Result := 1; end;
      end;
      { Joining remains ownership-safe. The independently armed process guard
        enforces the total lifetime deadline if an OS/driver call never returns;
        it never terminates one thread or frees live worker-owned objects. }
      Worker.WaitFor;
      Budget.JoinedAt(CozyTick);
      if not JoinedInBudget then Budget.JoinMissed := True;
      Worker.MarkClosed;
      Worker.Free;
    end;
    if Watch <> nil then Watch.StopChildObservers;
    if (Watch <> nil) and Watch.Confirmed then Result := 1;
    { Release image readers only after the worker joined. Cleanup happens
      before network reporting and is tied to this exact claimed file. }
    if Client <> nil then
      try Client.RetireOwnImageForShutdown;
      except Result := 1; end;
    FreeAndNil(Image);
    if Context <> nil then
    begin
      Context.CleanupOwnImageForShutdown;
      if (Client <> nil) and (Client.Lifecycle <> nil) then
        Client.Lifecycle.ObserveCleanup('O', Context.OwnCleanupObservation, False);
    end;
    { Leave at least half the remaining shutdown budget for authenticated
      close/cleanup. Never wait for report delivery on the UI callback. }
    ReportNow := CozyTick;
    if (Client <> nil) and (Budget.Deadline > ReportNow) then
    begin
      ReportBudget := (Budget.Deadline - ReportNow) div 2;
      if ReportBudget > 750 then ReportBudget := 750;
      Client.FlushNHWReports(Cardinal(ReportBudget));
    end;
    if (Watch <> nil) and Watch.Confirmed then Result := 1;
    if Client <> nil then
      try Client.ShutdownClose(Budget.Deadline,Budget.JoinElapsed,Budget.JoinMissed);
      except Result := 1; end;
    {$IFDEF GAME_PRODUCT_FAULT_TESTS}
    ProductFaultLateLifecycleReport(Budget.Deadline);
    {$ENDIF}
    if (Client <> nil) and (Client.Lifecycle <> nil) then
      Client.Lifecycle.Submit('O', Budget.Deadline);
    Budget.ClosedAt(CozyTick);
    if Budget.JoinMissed or Budget.CloseMissed then Result := 1;
    Session.ReleaseSecrets;
    try
      Image.Free; Client.Free; Context.Free;
      Watch.Free;
    finally
      if Guard <> nil then begin Guard.Cancel; Guard.Free; end;
    end;
  end;
end;
end.
