unit Cozy.NHW.Guard;

interface

uses
  System.Classes,
  System.SyncObjs,
  Cozy.NHW.KernelTrust.Native,
  Cozy.NHW.SessionTrustLadder,
  Cozy.NHW.ResponsePath.Dispatch, Cozy.NHW.Logging, Cozy.NHW.DetectionJournal, Cozy.NHW.Context;

type
  TCozyNHWRole = (nrLauncher, nrClient, nrOverlay);

  TCozyNHWKernelState = record
    Tick: UInt64;
    BootIdentity: TBootIdentity;
    BootIdentityValid: Boolean;
    SessionTrust: TKernelSessionTrust;
    VoteMask: Byte;
    TrustDigest, DriverDigest, IntegrityDigest: UInt64;
    CorrelationScore: Word;
    CorrelationFamilies: Byte;
    ResponseQuorum, SessionInvalidated: Boolean;
    ObservationKinds: TDetectionKinds;
    LocalInvalidated: Boolean;
    TrustReceipt, DriverReceipt, IntegrityReceipt: TResponsePathEvent;
    TrustResponse, DriverResponse, IntegrityResponse: TResponsePathEvent;
  end;

  // The owner starts and joins the worker. Only scalar snapshots and a sticky
  // decision leave the worker, so it never closes a Cozy session itself.
  TCozyNHWGuard = class
  private
    FRole: TCozyNHWRole;
    FSecurityContext: TCozySecurityContext;
    FWorker: TThread;
    FLock: TCriticalSection;
    FControl: LongInt;
    FKernelState: TCozyNHWKernelState;
    FPathStates: array[TResponsePathChannel] of TCozyNHWKernelState;
    FDetectionJournals: array[TResponsePathChannel] of TNHWDetectionJournal;
    FAttestationSequence, FLastRevalidation: Int64;
    FRevalidationRequested: LongInt;
    procedure ReportWorkerUnavailable;
  protected
    function Cancelled: Boolean;
    procedure Confirm;
    procedure PublishKernelState(const State: TCozyNHWKernelState);
    procedure PublishTrustState(const State: TCozyNHWKernelState);
    procedure PublishDriverState(const State: TCozyNHWKernelState);
    procedure PublishIntegrityState(const State: TCozyNHWKernelState);
    procedure RunWorker; virtual;
  public
    constructor Create(Role: TCozyNHWRole);
    destructor Destroy; override;
    procedure Start;
    procedure RequestStop; virtual;
    procedure StopChildObservers; virtual;
    procedure StopAndJoin;
    function Confirmed: Boolean;
    { Called only after an exact authenticated server response says that this
      role/session has been revoked. A timeout never calls this transition. }
    procedure ApplyAuthenticatedServerStop;
    function TryReadKernelState(out State: TCozyNHWKernelState): Boolean;
    function TryReadPathState(Channel: TResponsePathChannel;
      out State: TCozyNHWKernelState): Boolean;
    procedure RecordTrustDetections(const Kinds: TDetectionKinds; Tick: UInt64;
      Confidence: Byte; Correlated: Boolean);
    procedure RecordDriverDetections(const Kinds: TDetectionKinds; Tick: UInt64;
      Confidence: Byte; Correlated: Boolean);
    procedure RecordIntegrityDetections(const Kinds: TDetectionKinds; Tick: UInt64;
      Origin: TNHWDetectionOrigin; Families, Confidence: Byte;
      Correlated: Boolean; ObservedOnly: Boolean = False);
    function ConsumeRevalidationRequest: Boolean;
    procedure NoteAttestationSequence(Sequence: UInt64);
    function ReadDetectionBatch(Channel: TResponsePathChannel;
      out Batch: TNHWDetectionBatch): Boolean;
    procedure AcknowledgeDetectionBatch(Channel: TResponsePathChannel;
      const Batch: TNHWDetectionBatch);
    function HasPendingDetections(Channel: TResponsePathChannel): Boolean;
    property Role: TCozyNHWRole read FRole;
    property SecurityContext: TCozySecurityContext read FSecurityContext;
  end;

implementation

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Cancellation,
  Cozy.NHW.Observer.Protocol,
  Cozy.NHW.PECodeIntegrity,
  Cozy.NHW.SensorFaultIsolation,
  Cozy.NHW.WinPointers;

const
  GuardStop = 1;
  GuardConfirmed = 2;

type
  TCozyNHWGuardWorker = class(TThread)
  private
    FGuard: TCozyNHWGuard;
  protected
    procedure Execute; override;
  public
    constructor Create(Guard: TCozyNHWGuard);
  end;

constructor TCozyNHWGuardWorker.Create(Guard: TCozyNHWGuard);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FGuard := Guard;
end;

procedure TCozyNHWGuardWorker.Execute;
begin
  NHWSetCancellationFlag(@FGuard.FControl);
  try
    try
      if not FGuard.Cancelled then FGuard.RunWorker;
    except
      // Probe/bootstrap exceptions do not establish a confirmed incident.
      // Engine-owned handles and resources unwind before this boundary.
    end;
    FGuard.ReportWorkerUnavailable;
  finally
    NHWSetCancellationFlag(nil);
  end;
end;

constructor TCozyNHWGuard.Create(Role: TCozyNHWRole);
var Channel: TResponsePathChannel;
begin
  inherited Create;
  FRole := Role;
  case Role of
    nrLauncher: FSecurityContext := TCozySecurityContext.Create('A');
    nrClient: FSecurityContext := TCozySecurityContext.Create('B');
    nrOverlay: FSecurityContext := TCozySecurityContext.Create('O');
  end;
  FLock := TCriticalSection.Create;
  for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
    FDetectionJournals[Channel] := TNHWDetectionJournal.Create;
end;

destructor TCozyNHWGuard.Destroy;
var Channel: TResponsePathChannel;
begin
  StopAndJoin;
  for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
    FDetectionJournals[Channel].Free;
  FillChar(FKernelState, SizeOf(FKernelState), 0);
  FillChar(FPathStates, SizeOf(FPathStates), 0);
  TInterlocked.Exchange(FAttestationSequence, Int64(0));
  FSecurityContext.Free;
  FLock.Free;
  inherited;
end;

procedure TCozyNHWGuard.Start;
begin
  if (FWorker <> nil) or Cancelled then Exit;
  try
    FWorker := TCozyNHWGuardWorker.Create(Self);
    FWorker.Start;
  except
    // Thread creation can fail; its absence is an unknown observation.
    try
      ReportWorkerUnavailable;
    finally
      RequestStop;
      FreeAndNil(FWorker);
    end;
  end;
end;

procedure TCozyNHWGuard.ReportWorkerUnavailable;
begin
  if Cancelled then Exit;
  FLock.Acquire;
  try
    FKernelState := Default(TCozyNHWKernelState);
    FillChar(FPathStates, SizeOf(FPathStates), 0);
  finally
    FLock.Release;
  end;
  // This is diagnostic availability, with no vote or local stop latch.
  // The observer clock is valid even if ResolveWinPointers never completed.
  RecordIntegrityDetections([dkObservationUncertain], ObserverClockTick,
    ndoGuardCoverage, 0, 0, False);
end;

procedure TCozyNHWGuard.RequestStop;
var
  Before: LongInt;
begin
  // Seal publication without joining or acquiring the snapshot lock.
  repeat
    Before := TInterlocked.CompareExchange(FControl, 0, 0);
  until TInterlocked.CompareExchange(FControl, Before or GuardStop,
    Before) = Before;
  if FWorker <> nil then NHWCancelComCall(FWorker.ThreadID);
end;

procedure TCozyNHWGuard.StopChildObservers;
begin
  // The full guard owns any authenticated observer child.
end;

procedure TCozyNHWGuard.StopAndJoin;
begin
  RequestStop;
  if FWorker = nil then Exit;
  // Retry cancellation across the race where a provider call starts just
  // after RequestStop. Never free a live worker or force-terminate a thread.
  while WaitForSingleObject(FWorker.Handle, 50) = WAIT_TIMEOUT do
    NHWCancelComCall(FWorker.ThreadID);
  FWorker.WaitFor;
  FreeAndNil(FWorker);
end;

function TCozyNHWGuard.Confirmed: Boolean;
begin
  Result := (TInterlocked.CompareExchange(FControl, 0, 0) and GuardConfirmed) <> 0;
end;

function TCozyNHWGuard.Cancelled: Boolean;
begin
  Result := TInterlocked.CompareExchange(FControl, 0, 0) <> 0;
end;

procedure TCozyNHWGuard.Confirm;
var Before: LongInt;
begin
  { A request to stop sensing does not erase an authenticated server revoke
    arriving while independent report workers drain their queues. }
  repeat
    Before := TInterlocked.CompareExchange(FControl, 0, 0);
  until TInterlocked.CompareExchange(FControl, Before or GuardConfirmed,
    Before) = Before;
end;

procedure TCozyNHWGuard.ApplyAuthenticatedServerStop;
begin
  Confirm;
end;

procedure TCozyNHWGuard.PublishKernelState(const State: TCozyNHWKernelState);
begin
  FLock.Acquire;
  try
    FKernelState := State;
  finally
    FLock.Release;
  end;
end;

procedure TCozyNHWGuard.PublishTrustState(const State: TCozyNHWKernelState);
begin
  FLock.Acquire;
  try FPathStates[rpcTrust] := State;
  finally FLock.Release; end;
end;

procedure TCozyNHWGuard.PublishDriverState(const State: TCozyNHWKernelState);
begin
  FLock.Acquire;
  try FPathStates[rpcDriver] := State;
  finally FLock.Release; end;
end;

procedure TCozyNHWGuard.PublishIntegrityState(const State: TCozyNHWKernelState);
begin
  FLock.Acquire;
  try FPathStates[rpcIntegrity] := State;
  finally FLock.Release; end;
end;

function TCozyNHWGuard.TryReadPathState(Channel: TResponsePathChannel;
  out State: TCozyNHWKernelState): Boolean;
begin
  FLock.Acquire;
  try State := FPathStates[Channel];
  finally FLock.Release; end;
  Result := State.Tick <> 0;
end;

function TCozyNHWGuard.TryReadKernelState(out State: TCozyNHWKernelState): Boolean;
begin
  FLock.Acquire;
  try
    State := FKernelState;
  finally
    FLock.Release;
  end;
  Result := State.Tick <> 0;
end;

procedure TCozyNHWGuard.RunWorker;
const
  PECodeSlot = 39;
var
  CodeIntegrity: TPECodeIntegrityMonitor;
  Faults: TSensorFaultIsolation;
  Kinds: TDetectionKinds;
  Tick: UInt64;
  ResetRequired: Boolean;
begin
  // A and O have independent own-image evidence. The original monitor primes
  // on two valid reads and requires two matching changed reads to report.
  ResolveWinPointers;
  CodeIntegrity := TPECodeIntegrityMonitor.Create;
  try
    Faults := TSensorFaultIsolation.Create;
    try
      while not Cancelled do
      begin
        Tick := WinTick64;
        Kinds := [];
        if Faults.TryBegin(PECodeSlot, Tick, ResetRequired) then
        begin
          try
            if ResetRequired then CodeIntegrity.Reset;
            CodeIntegrity.Examine(False, Tick, Kinds);
            // The monitor retains valid baselines through partial reads.
            // Failed observations alone never produce a detection kind.
            Faults.Succeeded(PECodeSlot, Tick);
            if CodeIntegrity.OwnImageChanged then Confirm;
          except
            on E: Exception do
            begin
              Faults.Failed(PECodeSlot, Tick, NHWClassifySensorException(E));
              if NHWFatalSensorException(E) then raise;
            end;
          end;
        end;
        if not Cancelled then WinSleep(50);
      end;
    finally
      Faults.Free;
    end;
  finally
    CodeIntegrity.Free;
  end;
end;

procedure TCozyNHWGuard.RecordTrustDetections(const Kinds: TDetectionKinds;
  Tick: UInt64; Confidence: Byte; Correlated: Boolean);
var Kind: TDetectionKind;
begin
  for Kind := Low(TDetectionKind) to High(TDetectionKind) do
    if Kind in Kinds then
      FDetectionJournals[rpcTrust].AppendContext([Kind], ndoKernelTrust, Tick,
        UInt64(TInterlocked.CompareExchange(FAttestationSequence, Int64(0), Int64(0))),
        $80, Confidence, Correlated,
        NHWReadDetectionContext(Kind, FSecurityContext), False);
end;

procedure TCozyNHWGuard.RecordDriverDetections(const Kinds: TDetectionKinds;
  Tick: UInt64; Confidence: Byte; Correlated: Boolean);
var Kind: TDetectionKind;
begin
  for Kind := Low(TDetectionKind) to High(TDetectionKind) do
    if Kind in Kinds then
      FDetectionJournals[rpcDriver].AppendContext([Kind], ndoKernelTrust, Tick,
        UInt64(TInterlocked.CompareExchange(FAttestationSequence, Int64(0), Int64(0))),
        $80, Confidence, Correlated,
        NHWReadDetectionContext(Kind, FSecurityContext), False);
end;

procedure TCozyNHWGuard.RecordIntegrityDetections(const Kinds: TDetectionKinds;
  Tick: UInt64; Origin: TNHWDetectionOrigin; Families, Confidence: Byte;
  Correlated, ObservedOnly: Boolean);
var Kind: TDetectionKind; Previous: Int64;
begin
  if (Kinds * [dkETWLoss,dkCoverageGap,dkObservationUncertain,dkSensorPressure,
    dkTraceGap,dkKernelTelemetryGap])<>[] then
  begin
    Previous:=TInterlocked.CompareExchange(FLastRevalidation,Int64(0),Int64(0));
    if (Tick<=UInt64(High(Int64))) and
      ((Previous=0) or ((Tick>=UInt64(Previous)) and (Tick-UInt64(Previous)>=30000))) and
      (TInterlocked.CompareExchange(FLastRevalidation,Int64(Tick),Previous)=Previous) then
      TInterlocked.Exchange(FRevalidationRequested,1);
  end;
  for Kind := Low(TDetectionKind) to High(TDetectionKind) do
    if Kind in Kinds then
      FDetectionJournals[rpcIntegrity].AppendContext([Kind], Origin, Tick,
        UInt64(TInterlocked.CompareExchange(FAttestationSequence, Int64(0), Int64(0))),
        Families, Confidence, Correlated,
        NHWReadDetectionContext(Kind, FSecurityContext),
        ObservedOnly);
end;

function TCozyNHWGuard.ConsumeRevalidationRequest: Boolean;
begin Result:=TInterlocked.Exchange(FRevalidationRequested,0)<>0; end;

procedure TCozyNHWGuard.NoteAttestationSequence(Sequence: UInt64);
begin
  if Sequence <= UInt64(High(Int64)) then
    TInterlocked.Exchange(FAttestationSequence, Int64(Sequence));
end;

function TCozyNHWGuard.ReadDetectionBatch(Channel: TResponsePathChannel;
  out Batch: TNHWDetectionBatch): Boolean;
begin Result := FDetectionJournals[Channel].Read(Batch); end;

procedure TCozyNHWGuard.AcknowledgeDetectionBatch(Channel: TResponsePathChannel;
  const Batch: TNHWDetectionBatch);
begin FDetectionJournals[Channel].Acknowledge(Batch); end;

function TCozyNHWGuard.HasPendingDetections(Channel: TResponsePathChannel): Boolean;
begin Result := FDetectionJournals[Channel].Pending; end;

end.
