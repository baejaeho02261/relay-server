unit Cozy.NHW.ClientGuard;

interface

uses
  Cozy.NHW.Guard,
  Cozy.NHW.KernelTrust,
  Cozy.NHW.ResponsePath.Dispatch, Cozy.NHW.DualObserver;

type
  TCozyNHWClientGuard = class(TCozyNHWGuard)
  private
    FObserver: TDualObserver;
    FKernelMonitor: TKernelTrustMonitor;
    FTrustResponse, FDriverResponse, FIntegrityResponse: TResponsePathEvent;
    procedure ReceiveTrust(const Event: TResponsePathEvent);
    procedure ReceiveDriver(const Event: TResponsePathEvent);
    procedure ReceiveIntegrity(const Event: TResponsePathEvent);
    procedure CaptureKernel(Monitor: TKernelTrustMonitor; Tick: UInt64;
      ConfirmedIncident: Boolean);
  protected
    procedure RunWorker; override;
  public
    constructor Create(Role: TCozyNHWRole); reintroduce;
    destructor Destroy; override;
    procedure RequestStop; override;
    procedure StopChildObservers; override;
    function ReadChildShutdownStatus(out Status: TObserverShutdownStatus): Boolean;
  end;

implementation

uses
  Cozy.NHW.Engine, Cozy.NHW.Context,
  Cozy.NHW.DetectionJournal, Cozy.NHW.KernelTrust.CorrelationPolicy,
  Cozy.NHW.Logging,
  Cozy.NHW.Native,
  Cozy.NHW.Options,
  Cozy.NHW.Types,
  Cozy.NHW.WinPointers;

constructor TCozyNHWClientGuard.Create(Role: TCozyNHWRole);
begin
  inherited Create(Role);
  FObserver := TDualObserver.Create;
end;

destructor TCozyNHWClientGuard.Destroy;
begin
  StopAndJoin;
  FObserver.Free;
  FObserver := nil;
  inherited;
end;

procedure TCozyNHWClientGuard.RequestStop;
begin
  inherited;
  if FObserver <> nil then FObserver.RequestStop;
end;

procedure TCozyNHWClientGuard.StopChildObservers;
begin
  if FObserver <> nil then FObserver.Stop;
end;

function TCozyNHWClientGuard.ReadChildShutdownStatus(out Status: TObserverShutdownStatus): Boolean;
begin
  Status := Default(TObserverShutdownStatus);
  if FObserver = nil then Exit(False);
  Result := FObserver.ReadShutdownStatus(Status);
end;

procedure TCozyNHWClientGuard.ReceiveTrust(const Event: TResponsePathEvent);
var State: TCozyNHWKernelState; Eligible: TDetectionKinds;
begin
  if (Event.Channel <> rpcTrust) or (FKernelMonitor = nil) then Exit;
  FTrustResponse := Event;
  State := Default(TCozyNHWKernelState);
  State.Tick := Event.Tick;
  State.SessionTrust := FKernelMonitor.SessionTrust;
  State.ObservationKinds := FKernelMonitor.ObservationKinds;
  FKernelMonitor.ReadLocalReceipts(State.TrustReceipt, State.DriverReceipt,
    State.IntegrityReceipt);
  State.TrustResponse := Event;
  RecordTrustDetections(State.ObservationKinds, Event.Tick, 0, False);
  Eligible := State.ObservationKinds - [dkKernelTelemetryGap,
    dkVulnerableDriver, dkKernelMappingEvidence, dkDriverTimelineKernel,
    dkDriverSignerAttestation, dkDriverLoadProvenance,
    dkDriverServiceTimeline, dkCodeIntegrityPolicy];
  if (Event.Sequence <> 0) and (Event.Digest <> 0) and
    (State.TrustReceipt.Channel = rpcTrust) and
    (State.TrustReceipt.Sequence = Event.Sequence) and
    (State.TrustReceipt.Digest = Event.Digest) and
    (State.TrustReceipt.Tick = Event.Tick) and
    EvaluateKernelCorrelation(Eligible, State.SessionTrust, True).CanInvalidate then
    RecordTrustDetections(Eligible, Event.Tick, 75, True);
  PublishTrustState(State);
end;

procedure TCozyNHWClientGuard.ReceiveDriver(const Event: TResponsePathEvent);
var State: TCozyNHWKernelState; Eligible: TDetectionKinds;
begin
  if (Event.Channel <> rpcDriver) or (FKernelMonitor = nil) then Exit;
  FDriverResponse := Event;
  State := Default(TCozyNHWKernelState);
  State.Tick := Event.Tick;
  State.SessionTrust := FKernelMonitor.SessionTrust;
  State.ObservationKinds := FKernelMonitor.ObservationKinds;
  FKernelMonitor.ReadLocalReceipts(State.TrustReceipt, State.DriverReceipt,
    State.IntegrityReceipt);
  State.DriverResponse := Event;
  RecordDriverDetections(State.ObservationKinds, Event.Tick, 0, False);
  Eligible := State.ObservationKinds - [dkKernelTelemetryGap,
    dkVulnerableDriver, dkKernelMappingEvidence, dkDriverTimelineKernel,
    dkDriverSignerAttestation, dkDriverLoadProvenance,
    dkDriverServiceTimeline, dkCodeIntegrityPolicy];
  if (Event.Sequence <> 0) and (Event.Digest <> 0) and
    (State.DriverReceipt.Channel = rpcDriver) and
    (State.DriverReceipt.Sequence = Event.Sequence) and
    (State.DriverReceipt.Digest = Event.Digest) and
    (State.DriverReceipt.Tick = Event.Tick) and
    EvaluateKernelCorrelation(Eligible, State.SessionTrust, True).CanInvalidate then
    RecordDriverDetections(Eligible, Event.Tick, 75, True);
  PublishDriverState(State);
end;

procedure TCozyNHWClientGuard.ReceiveIntegrity(const Event: TResponsePathEvent);
var State: TCozyNHWKernelState; Eligible: TDetectionKinds;
begin
  if (Event.Channel <> rpcIntegrity) or (FKernelMonitor = nil) then Exit;
  FIntegrityResponse := Event;
  State := Default(TCozyNHWKernelState);
  State.Tick := Event.Tick;
  State.SessionTrust := FKernelMonitor.SessionTrust;
  State.ObservationKinds := FKernelMonitor.ObservationKinds;
  FKernelMonitor.ReadLocalReceipts(State.TrustReceipt, State.DriverReceipt,
    State.IntegrityReceipt);
  State.IntegrityResponse := Event;
  RecordIntegrityDetections(State.ObservationKinds, Event.Tick, ndoKernelTrust,
    $80, 0, False);
  Eligible := State.ObservationKinds - [dkKernelTelemetryGap,
    dkVulnerableDriver, dkKernelMappingEvidence, dkDriverTimelineKernel,
    dkDriverSignerAttestation, dkDriverLoadProvenance,
    dkDriverServiceTimeline, dkCodeIntegrityPolicy];
  if (Event.Sequence <> 0) and (Event.Digest <> 0) and
    (State.IntegrityReceipt.Channel = rpcIntegrity) and
    (State.IntegrityReceipt.Sequence = Event.Sequence) and
    (State.IntegrityReceipt.Digest = Event.Digest) and
    (State.IntegrityReceipt.Tick = Event.Tick) and
    EvaluateKernelCorrelation(Eligible, State.SessionTrust, True).CanInvalidate then
    RecordIntegrityDetections(Eligible, Event.Tick, ndoKernelTrust, $80, 75, True);
  PublishIntegrityState(State);
end;

procedure TCozyNHWClientGuard.CaptureKernel(Monitor: TKernelTrustMonitor;
  Tick: UInt64; ConfirmedIncident: Boolean);
var
  State: TCozyNHWKernelState;
begin
  State := Default(TCozyNHWKernelState);
  State.Tick := Tick;
  State.BootIdentityValid := Monitor.ReadBootIdentity(State.BootIdentity);
  State.SessionTrust := Monitor.SessionTrust;
  State.VoteMask := Monitor.ResponseVoteMask(Tick);
  State.TrustDigest := Monitor.TrustResponseDigest;
  State.DriverDigest := Monitor.DriverResponseDigest;
  State.IntegrityDigest := Monitor.IntegrityResponseDigest;
  State.CorrelationScore := Monitor.CorrelationScore;
  State.CorrelationFamilies := Monitor.CorrelationFamilyCount;
  State.ResponseQuorum := Monitor.ResponseQuorum(Tick);
  State.SessionInvalidated := ConfirmedIncident;
  State.ObservationKinds := Monitor.ObservationKinds;
  State.LocalInvalidated := Monitor.SessionInvalidated;
  Monitor.ReadLocalReceipts(State.TrustReceipt, State.DriverReceipt,
    State.IntegrityReceipt);
  State.TrustResponse := FTrustResponse;
  State.DriverResponse := FDriverResponse;
  State.IntegrityResponse := FIntegrityResponse;
  { Every channel keeps a separate bounded journal and delivery cursor.
    The existing independent receipt sinks above remain live even if this
    aggregate snapshot callback is unavailable. Unconfirmed observations are
    uploaded as local evidence, including unsupported/coverage conditions. }
  RecordTrustDetections(State.ObservationKinds, Tick,
    0, False);
  RecordDriverDetections(State.ObservationKinds, Tick,
    0, False);
  RecordIntegrityDetections(State.ObservationKinds, Tick, ndoKernelTrust,
    $80, 0, False);
  PublishKernelState(State);
end;

procedure TCozyNHWClientGuard.RunWorker;
var
  Options: TOptions;
begin
  ResolveWinPointers;
  SecurityContext.PrepareLocalIdentity;
  NHWEnterSensorContext(SecurityContext);
  try
  ConfigureDefaultMonitoring(Options);
  ResolveNativeAPIs;
  Run(Options,
    function: Boolean
    begin
      Result := Self.Cancelled;
    end,
    procedure(const Kinds: TDetectionKinds; const Confirmed: Boolean)
    begin
      if Confirmed then Confirm;
    end,
    procedure(Monitor: TKernelTrustMonitor; Tick: UInt64; Confirmed: Boolean)
    begin
      CaptureKernel(Monitor, Tick, Confirmed);
    end,
    ReceiveTrust, ReceiveDriver, ReceiveIntegrity, FObserver,
    procedure(Monitor: TKernelTrustMonitor)
    begin FKernelMonitor := Monitor; end,
    procedure(const Kinds: TDetectionKinds; Tick: UInt64;
      Families, Confidence: Byte; Correlated, ObservedOnly: Boolean)
    begin
      RecordIntegrityDetections(Kinds, Tick, ndoEngine, Families, Confidence,
        Correlated, ObservedOnly);
    end,
    procedure(Tick: UInt64)
    begin
      RecordIntegrityDetections([dkObservationUncertain], Tick, ndoHandleCoverage,
        0, 0, False);
    end);
  finally NHWLeaveSensorContext; end;
end;

end.
