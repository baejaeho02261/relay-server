unit Cozy.NHW.Engine;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  Cozy.NHW.Types, Cozy.NHW.Logging, Cozy.NHW.KernelTrust,
  Cozy.NHW.ResponsePath.Dispatch, Cozy.NHW.DualObserver;

type
  TNHWObservationProc = reference to procedure(const Kinds: TDetectionKinds;
    const Confirmed: Boolean);
  TNHWDetectionProc = reference to procedure(const Kinds: TDetectionKinds;
    Tick: UInt64; Families, Confidence: Byte;
    Correlated, ObservedOnly: Boolean);
  TNHWCoverageProc = reference to procedure(Tick: UInt64);
  TNHWKernelReadyProc = reference to procedure(Monitor: TKernelTrustMonitor);
  TNHWKernelCycleProc = reference to procedure(Monitor: TKernelTrustMonitor;
    Tick: UInt64; Confirmed: Boolean);

procedure Run(const Opt: TOptions; const Cancelled: TFunc<Boolean> = nil;
  const OnObservation: TNHWObservationProc = nil;
  const OnKernelCycle: TNHWKernelCycleProc = nil;
  TrustSink: TResponsePathSink = nil; DriverSink: TResponsePathSink = nil;
  IntegritySink: TResponsePathSink = nil;
  SharedObserver: TDualObserver = nil;
  const OnKernelReady: TNHWKernelReadyProc = nil;
  const OnDetection: TNHWDetectionProc = nil;
  const OnHandleCoverageUnavailable: TNHWCoverageProc = nil);

implementation

uses
  Winapi.Windows,
  System.Generics.Collections,
  Cozy.NHW.Native, Cozy.NHW.Context,
  Cozy.NHW.WinPointers,
  Cozy.NHW.Scheduler,
  Cozy.NHW.Process,
  Cozy.NHW.Threads,
  Cozy.NHW.Handles,
  Cozy.NHW.Sampling,
  Cozy.NHW.Behavior,
  Cozy.NHW.Lifecycle,
  Cozy.NHW.Security,
  Cozy.NHW.IPC,
  Cozy.NHW.Job,
  Cozy.NHW.FileGuard,
  Cozy.NHW.Registry,
  Cozy.NHW.Namespace,
  Cozy.NHW.ETW,
  Cozy.NHW.ETWFusion,
  Cozy.NHW.ETWTypes,
  Cozy.NHW.ThreadOrigin,
  Cozy.NHW.StackGuard,
  Cozy.NHW.AllocationGuard,
  Cozy.NHW.MappingGuard,
  Cozy.NHW.ProtectionGuard,
  Cozy.NHW.ReadAccess,
  Cozy.NHW.WriteWatch,
  Cozy.NHW.WaitChain,
  Cozy.NHW.Capture,
  Cozy.NHW.NetworkGuard,
  Cozy.NHW.PathGuard,
  Cozy.NHW.SelfGuard,
  Cozy.NHW.HeapTLS,
  Cozy.NHW.ExceptionGuard,
  Cozy.NHW.AsyncGuard,
  Cozy.NHW.PELoader,
  Cozy.NHW.ExportGuard,
  Cozy.NHW.SignalCorrelation,
  Cozy.NHW.PECodeIntegrity,
  Cozy.NHW.RegionClassifier,
  Cozy.NHW.ETWImageFusion,
  Cozy.NHW.InjectionEvidence,
  Cozy.NHW.ThreadExecutionProvenance,
  Cozy.NHW.ImageCOWIntegrity,
  Cozy.NHW.TemporalHandleGraph,
  Cozy.NHW.ModuleOriginVerification,
  Cozy.NHW.ETWLossHealth,
  Cozy.NHW.AdaptiveInspector,
  Cozy.NHW.EvidenceChain,
  Cozy.NHW.ImportRedirection,
  Cozy.NHW.TLSCallbackIntegrity,
  Cozy.NHW.UnwindConsistency,
  Cozy.NHW.ExecutableLifecycle,
  Cozy.NHW.SectionBackingIdentity,
  Cozy.NHW.ThreadStackProvenance,
  Cozy.NHW.CoverageWindow,
  Cozy.NHW.FalsePositiveControl,
  Cozy.NHW.ExplainableEvidence,
  Cozy.NHW.StableIdentity,
  Cozy.NHW.ProcessSnapshot,
  Cozy.NHW.LoaderCrossView,
  Cozy.NHW.FileAttestation,
  Cozy.NHW.ControlFlowAttestation,
  Cozy.NHW.SnapshotETWReconcile,
  Cozy.NHW.ForensicHashChain,
  Cozy.NHW.RiskConfidence,
  Cozy.NHW.MultiEpochBaseline,
  Cozy.NHW.CodeProvenanceGraph,
  Cozy.NHW.SectionCorrelation,
  Cozy.NHW.IndirectTargets,
  Cozy.NHW.ThreadTimeline,
  Cozy.NHW.CausalGraph,
  Cozy.NHW.ObservationTrust,
  Cozy.NHW.ResourceController,
  Cozy.NHW.IncidentReconstruction,
  Cozy.NHW.FastEventRing,
  Cozy.NHW.HighResolutionClock,
  Cozy.NHW.RealtimeFusion,
  Cozy.NHW.EventDrivenWake,
  Cozy.NHW.FastPipeline,
  Cozy.NHW.MicroburstAccess,
  Cozy.NHW.TriggeredSnapshot,
  Cozy.NHW.MemoryDelta,
  Cozy.NHW.SensorRecovery,
  Cozy.NHW.RealtimeBenchmark,
  Cozy.NHW.EphemeralIdentity,
  Cozy.NHW.PrecisionTimeline,
  Cozy.NHW.BehaviorFingerprint,
  Cozy.NHW.SensorConsensus,
  Cozy.NHW.MemoryEvidenceCapsule,
  Cozy.NHW.AdaptiveAnomaly,
  Cozy.NHW.SensorDisagreement,
  Cozy.NHW.ObserverAttestation,
  Cozy.NHW.PrivacyForensics,
  Cozy.NHW.HandleSharingEvidence,
  Cozy.NHW.APCStyleEvidence,
  Cozy.NHW.SensorTamperHealth,
  Cozy.NHW.SensorFaultIsolation,
  Cozy.NHW.UnifiedEvidence,
  Cozy.NHW.PerformanceBudget,
  Cozy.NHW.RAMLifecycle,
  Cozy.NHW.KernelTrust.CorrelationPolicy;

procedure Run(const Opt: TOptions; const Cancelled: TFunc<Boolean>;
  const OnObservation: TNHWObservationProc;
  const OnKernelCycle: TNHWKernelCycleProc;
  TrustSink, DriverSink, IntegritySink: TResponsePathSink;
  SharedObserver: TDualObserver;
  const OnKernelReady: TNHWKernelReadyProc;
  const OnDetection: TNHWDetectionProc;
  const OnHandleCoverageUnavailable: TNHWCoverageProc);
var
  Target: THandle;
  LivePID, FoundPID: Cardinal;
  MatchCount: Integer;
  Wow64: BOOL;
  Holders: TDictionary<string, TTargetHolder>;
  Tracks: TDictionary<string, TTrackState>;
  Seen: TDictionary<string, Byte>;
  OwnerCache: TDictionary<Cardinal, TTargetHolder>;
  ThreadRefs: TList<THandle>;
  Keys: TList<string>;
  Pair: TPair<string, TTargetHolder>;
  TrackPair: TPair<string, TTrackState>;
  H, Cached: TTargetHolder;
  T: TTrackState;
  Key, Reason, ObjKey, ObjPidKey: string;
  Stats: TScanStats;
  TickStart, LastScanStart, LastSummary, CurrentTick, Elapsed: UInt64;
  TotalHandles: NativeUInt;
  LastHandleCoverageReport: UInt64;
  LocalBaselineRemaining: Integer;
  I, ProcessBaselineRemaining, ThreadBaselineRemaining, Threshold: Integer;
  First, WasInactive, RightsAdded, InBaseline: Boolean;
  HandleSnapshotValid, ThreadRefsComplete, ThreadSnapshotValid: Boolean;
  NewRelevantRights: Cardinal;
  PreviousRightsForRead: Cardinal;
  CountIncreased: Boolean;
  Detected: TDetectionKinds;
  VisibleDetected: TDetectionKinds;
  WaitResult: DWORD;
  SampleHealth: TSamplingHealth;
  Behavior: TBehaviorMonitor;
  Lifecycle: TLifecycleMonitor;
  Security: TSecurityMonitor;
  IPC: TIPCMonitor;
  Job: TJobMonitor;
  Files: TFileMonitor;
  Registry: TRegistryMonitor;
  Scheduler: TSchedulerMonitor;
  Namespace: TNamespaceMonitor;
  KernelTrace: TETWMonitor;
  KernelFusion: TETWFusion;
  OriginGuard: TThreadOriginMonitor;
  StackGuard: TStackGuardMonitor;
  AllocationGuard: TVirtualAllocationGuard;
  SelfAllocationGuard: TVirtualAllocationGuard;
  SelfAllocationKinds: TDetectionKinds;
  MappingGuard: TMappingGuard;
  ProtectionGuard: TProtectionGuard;
  ReadGuard: TReadAccessMonitor;
  WriteGuard: TWriteWatchMonitor;
  WaitGuard: TWaitChainMonitor;
  CaptureGuard: TCaptureMonitor;
  NetworkGuard: TNetworkGuard;
  PathGuard: TPathGuard;
  SelfGuard: TSelfGuardMonitor;
  HeapTLS: THeapTLSMonitor;
  ExceptionGuard: TExceptionGuardMonitor;
  AsyncGuard: TAsyncGuardMonitor;
  PEGuard: TPELoaderMonitor;
  ExportGuard: TExportGuardMonitor;
  SignalCorrelation: TSignalCorrelationMonitor;
  CodeIntegrity: TPECodeIntegrityMonitor;
  RegionClassifier: TMemoryRegionClassifier;
  ImageFusion: TETWImageFusionMonitor;
  InjectionEvidence: TInjectionEvidenceMonitor;
  ExecutionProvenance: TThreadExecutionProvenance;
  ImageCOW: TImageCOWMonitor;
  TemporalGraph: TTemporalHandleGraph;
  ModuleOrigin: TModuleOriginMonitor;
  TraceHealth: TETWLossHealth;
  Adaptive: TAdaptiveInspector;
  Evidence: TEvidenceChain;
  ImportRedirect: TImportRedirectionMonitor;
  TLSCallback: TTLSCallbackMonitor;
  UnwindConsistency: TUnwindConsistencyMonitor;
  ExecLifecycle: TExecutableLifecycle;
  SectionBacking: TSectionBackingMonitor;
  StackProvenance: TThreadStackProvenanceMonitor;
  Coverage: TCoverageWindowMonitor;
  FalsePositive: TNewSignalSuppressor;
  Explainable: TExplainableEvidence;
  StableIdentity: TStableObjectIdentity;
  ProcessSnapshots: TProcessSnapshotMonitor;
  CrossViewLoader: TLoaderCrossViewMonitor;
  FileAttest: TFileAttestationMonitor;
  ControlAttest: TControlFlowAttestation;
  ETWReconciler: TSnapshotETWReconciler;
  DualObserver: TDualObserver;
  RAMHashChain: TForensicHashChain;
  RiskEngine: TRiskConfidenceMonitor;
  RiskFamilies: TRiskFamilies;
  // v71-v79 optional sensors. Their observations remain in bounded RAM.
  V80Epoch: TMultiEpochBaseline;
  V80Code: TCodeProvenanceGraph;
  V80Sections: TSectionCorrelation;
  V80Indirect: TIndirectTargetMonitor;
  V80ThreadHistory: TThreadTimeline;
  V80Causal: TCausalAttackGraph;
  V80Trust: TObservationTrust;
  V80Controller: TResourceAwareController;
  V80Incidents: TIncidentReconstruction;
  // v81-v90: optional, bounded, RAM-only real-time observation pipeline.
  FastEvents: TFastKernelSampleList;
  RealtimeFusion: TRealtimeFusion;
  RealtimeWake: TEventDrivenWake;
  DeferredPipeline: TFastDeferredPipeline;
  AccessMicroburst: TMicroburstAccess;
  SnapshotTrigger: TTriggeredSnapshot;
  MemoryDelta: TIncrementalMemoryDelta;
  SensorRecovery: TSensorCoverageRecovery;
  RealtimeBenchmark: TRealtimeBenchmark;
  // v91-v99 metadata-only, bounded in-memory analyzers.
  ActorIdentity: TSessionActorIdentity;
  PrecisionTimeline: TPrecisionTimeline;
  BehaviorFingerprint: TBehaviorFingerprint;
  SensorConsensus: TSensorConsensus;
  EvidenceCapsule: TMemoryEvidenceCapsule;
  AdaptiveAnomaly: TAdaptiveAnomaly;
  SensorDisagreement: TSensorDisagreement;
  ObserverAttestation: TObserverAttestation;
  PrivacyForensics: TPrivacyForensics;
  HandleSharing: THandleSharingEvidence;
  APCStyle: TAPCStyleEvidence;
  SensorTamper: TSensorTamperHealth;
  AllowedCreated: TCreationTimeMap;
  ActorAlias: UInt64;
  NewAccessEdges: Cardinal;
  FastLost, RealtimeRelevant, RealtimeCorrelated: Boolean;
  RealtimeHeavy, RapidAccess, SnapshotKick: Boolean;
  V80Grade: TObservationGrade;
  V80Kinds, V80NewKinds: TDetectionKinds;
  V80SectionList: TList<TIPCObservation>;
  V80Heavy: Boolean;
  NewRiskKinds: TDetectionKinds;
  RiskScore: Integer;
  StableTarget: Boolean;
  ObserverMismatch: Boolean;
  Corroborated: Boolean;
  TraceRecordCallback, TraceBufferCallback: NativeUInt;
  LastChainVerification: UInt64;
  EvidenceFlags: TEvidenceFlags;
  NewMonitorBaseline: Boolean;
  NewMonitorTrigger: Boolean;
  ConsoleCallbackTarget: Pointer;
  HighExternalAccess: Boolean;
  KernelEvents: TKernelEventList;
  TraceLost: Boolean;
  IPCTypes: TDictionary<Word, TIPCObjectKind>;
  IPCObserved: TList<TIPCObservation>;
  IPCSnapshotValid: Boolean;
  NativeThreads: TThreadSampleMap;
  ParentMap: TProcessParentMap;
  OwnerCreated: TCreationTimeMap;
  ObservedHandles: TList<TObservedHandle>;
  ObservedTokenHandles: TList<TObservedTokenHandle>;
  TokenReference: THandle;
  TokenSnapshotValid: Boolean;
  NativeThreadValid, ExternalEvent, FreshCreateThreadAccess: Boolean;
  ObjectOwners: TDictionary<string, TList<Cardinal>>;
  ObjectOwnerSeen: TDictionary<string, Byte>;
  ObjectStates: TDictionary<string, TObjectState>;
  OwnerList: TList<Cardinal>;
  ObjectState: TObjectState;
  NeedObjectNotify, ValidObjectType: Boolean;
  Faults: TSensorFaultIsolation;
  Unified: TUnifiedEvidence;
  Budget: TPerformanceBudget;
  RAM: TRAMLifecycle;
  KernelTrust: TKernelTrustMonitor;
  ProbeStarted: Int64;
  ProbeReset: Boolean;
  ProbeKinds: TDetectionKinds;
  InspectionTick, SnapshotRequestTick, DispatchUS: UInt64;
  InspectionPerformed, SnapshotAttempted: Boolean;
  CorrelationCoverageValid, OwnImageChanged: Boolean;

  function StopRequested: Boolean;
  begin
    Result := False;
    if Assigned(Cancelled) then Result := Cancelled();
  end;

  procedure SleepInterruptible(MS: Cardinal);
  var
    Remaining, Chunk: Cardinal;
  begin
    Remaining := MS;
    while (Remaining > 0) and not StopRequested do
    begin
      Chunk := Remaining;
      if Chunk > 50 then Chunk := 50;
      WinSleep(Chunk);
      Dec(Remaining, Chunk);
    end;
  end;

  procedure BreakCorrelationCoverage;
  begin
    CorrelationCoverageValid := False;
    if SignalCorrelation <> nil then SignalCorrelation.ObservationGap;
    if InjectionEvidence <> nil then InjectionEvidence.ObservationGap;
    if V80Causal <> nil then V80Causal.ObservationGap;
  end;

  function IsCorrelationSource(Slot: TSensorSlot): Boolean;
  begin
    // Expected producer failures invalidate correlation, not merely output.
    // Include the memory/thread families also consumed by v69/v71.
    Result := Slot in [5, 9, 16, 17, 23, 24, 25, 27, 28, 39, 40, 41,
      46, 47, 48, 49, 50, 51, 53, 54, 60, 61, 63];
  end;

  function BeginProbe(Slot: TSensorSlot; out Started: Int64;
    out ResetRequired: Boolean): Boolean;
  begin
    Started := 0;
    ResetRequired := False;
    if StopRequested then Exit(False);
    Result := Faults.TryBegin(Slot, WinTick64, ResetRequired);
    if Result then
    begin
      Started := NHWQpcNow;
      if ResetRequired and IsCorrelationSource(Slot) then BreakCorrelationCoverage;
    end
    else
    begin
      Unified.MarkIncomplete;
      if IsCorrelationSource(Slot) then BreakCorrelationCoverage;
    end;
  end;

  procedure CompleteProbe(Slot: TSensorSlot; Started: Int64;
    Root: TObservationRoot; const BeforeKinds, AfterKinds: TDetectionKinds);
  var ElapsedUS: UInt64;
  begin
    Faults.Succeeded(Slot, WinTick64);
    if (Started > 0) and NHWTryQpcElapsedUS(Started, NHWQpcNow, ElapsedUS) then
      Budget.RecordCost(Slot, ElapsedUS)
    else Unified.MarkIncomplete;
    Unified.Add(Root, AfterKinds - BeforeKinds);
  end;

  procedure RejectProbe(Slot: TSensorSlot; Started: Int64; E: Exception);
  var ElapsedUS: UInt64;
  begin
    Faults.Failed(Slot, WinTick64, NHWClassifySensorException(E));
    if IsCorrelationSource(Slot) then BreakCorrelationCoverage;
    if (Started > 0) and NHWTryQpcElapsedUS(Started, NHWQpcNow, ElapsedUS) then
      Budget.RecordCost(Slot, ElapsedUS);
    Unified.MarkIncomplete;
  end;

  procedure RunKernelTrustIndependent;
  var
    Kinds, AuthorityKinds: TDetectionKinds;
    ResetRequired, Confirmed: Boolean;
    Tick: UInt64;
  begin
    // System trust monitoring is deliberately independent from target/game
    // discovery. It continues even when no target process is running.
    Tick := WinTick64;
    Kinds := [];
    ResetRequired := False;
    if not Faults.TryBegin(90, Tick, ResetRequired) then Exit;
    try
      if ResetRequired then KernelTrust.Reset;
      KernelTrust.Examine(Tick, Kinds);
      Faults.Succeeded(90, Tick);
    except
      on E: Exception do
      begin
        Faults.Failed(90, Tick, NHWClassifySensorException(E));
        if NHWFatalSensorException(E) then raise;
        Exit;
      end;
    end;
    // Keep all upstream observations. An unauthenticated policy file or a
    // telemetry gap cannot supply the evidence that closes a Cozy session.
    AuthorityKinds := Kinds - [dkKernelTelemetryGap, dkVulnerableDriver,
      dkKernelMappingEvidence, dkDriverTimelineKernel, dkDriverSignerAttestation,
      dkDriverLoadProvenance, dkDriverServiceTimeline, dkCodeIntegrityPolicy];
    Confirmed := KernelTrust.SessionInvalidated and
      EvaluateKernelCorrelation(AuthorityKinds, KernelTrust.SessionTrust,
        KernelTrust.ResponseQuorum(Tick)).CanInvalidate;
    if Assigned(OnKernelCycle) then OnKernelCycle(KernelTrust, Tick, Confirmed);
    if Assigned(OnObservation) and (Kinds <> []) then
      OnObservation(Kinds, Confirmed);
  end;

  procedure RegisterRAMStores;
  begin
    // Fixed-capacity objects only: InstanceSize includes their inline rings.
    // This is not a claim that the complete Delphi heap fits this budget.
    if not RAM.RegisterStore(0, NativeUInt(Evidence.InstanceSize), Evidence.Prune) or
       not RAM.RegisterStore(1, NativeUInt(Explainable.InstanceSize), Explainable.Prune) or
       not RAM.RegisterStore(2, NativeUInt(RAMHashChain.InstanceSize), RAMHashChain.Prune) or
       not RAM.RegisterStore(3, NativeUInt(EvidenceCapsule.InstanceSize), EvidenceCapsule.Prune) or
       not RAM.RegisterStore(4, NativeUInt(PrivacyForensics.InstanceSize), PrivacyForensics.Prune) or
       not RAM.RegisterStore(5, NativeUInt(V80Incidents.InstanceSize), V80Incidents.Prune) or
       not RAM.RegisterStore(6, NativeUInt(Unified.InstanceSize), Unified.Prune) then
      raise Exception.Create('RAM evidence registration failed');
  end;


  procedure InitializeSessionReferences;
  begin
    Target := 0;
    TokenReference := 0;
    LivePID := 0;
    Holders := nil;
    Tracks := nil;
    Seen := nil;
    OwnerCache := nil;
    ThreadRefs := nil;
    Keys := nil;
    ObjectOwners := nil;
    ObjectOwnerSeen := nil;
    ObjectStates := nil;
    Behavior := nil;
    Lifecycle := nil;
    Security := nil;
    IPC := nil;
    Job := nil;
    Files := nil;
    Registry := nil;
    Scheduler := nil;
    Namespace := nil;
    KernelTrace := nil;
    KernelFusion := nil;
    OriginGuard := nil;
    StackGuard := nil;
    MappingGuard := nil;
    ProtectionGuard := nil;
    ReadGuard := nil;
    WriteGuard := nil;
    WaitGuard := nil;
    CaptureGuard := nil;
    NetworkGuard := nil;
    PathGuard := nil;
    SelfGuard := nil;
    HeapTLS := nil;
    ExceptionGuard := nil;
    AsyncGuard := nil;
    PEGuard := nil;
    ExportGuard := nil;
    SignalCorrelation := nil;
    CodeIntegrity := nil;
    RegionClassifier := nil;
    ImageFusion := nil;
    InjectionEvidence := nil;
    ExecutionProvenance := nil;
    ImageCOW := nil;
    TemporalGraph := nil;
    ModuleOrigin := nil;
    TraceHealth := nil;
    Adaptive := nil;
    Evidence := nil;
    ImportRedirect := nil;
    TLSCallback := nil;
    UnwindConsistency := nil;
    ExecLifecycle := nil;
    SectionBacking := nil;
    StackProvenance := nil;
    Coverage := nil;
    FalsePositive := nil;
    Explainable := nil;
    StableIdentity := nil;
    ProcessSnapshots := nil;
    CrossViewLoader := nil;
    FileAttest := nil;
    ControlAttest := nil;
    ETWReconciler := nil;
    DualObserver := nil;
    RAMHashChain := nil;
    RiskEngine := nil;
    V80Epoch := nil;
    V80Code := nil;
    V80Sections := nil;
    V80Indirect := nil;
    V80ThreadHistory := nil;
    V80Causal := nil;
    V80Trust := nil;
    V80Controller := nil;
    V80Incidents := nil;
    FastEvents := nil;
    RealtimeFusion := nil;
    RealtimeWake := nil;
    DeferredPipeline := nil;
    AccessMicroburst := nil;
    SnapshotTrigger := nil;
    MemoryDelta := nil;
    SensorRecovery := nil;
    RealtimeBenchmark := nil;
    ActorIdentity := nil;
    PrecisionTimeline := nil;
    BehaviorFingerprint := nil;
    SensorConsensus := nil;
    EvidenceCapsule := nil;
    AdaptiveAnomaly := nil;
    SensorDisagreement := nil;
    ObserverAttestation := nil;
    PrivacyForensics := nil;
    HandleSharing := nil;
    APCStyle := nil;
    SensorTamper := nil;
    AllowedCreated := nil;
    AllocationGuard := nil;
    SelfAllocationGuard := nil;
    KernelEvents := nil;
    IPCTypes := nil;
    IPCObserved := nil;
    NativeThreads := nil;
    ParentMap := nil;
    OwnerCreated := nil;
    ObservedHandles := nil;
    ObservedTokenHandles := nil;
    Faults := nil;
    Unified := nil;
    Budget := nil;
    RAM := nil;
    KernelTrust := nil;
  end;

  procedure CreateSessionComponents;
  begin
      // All owned references are nil before construction; partial startup
      // failures run the same finalizer as normal shutdown.
      Faults := TSensorFaultIsolation.Create;
      Unified := TUnifiedEvidence.Create;
      Budget := TPerformanceBudget.Create;
      RAM := TRAMLifecycle.Create;
      KernelTrust := TKernelTrustMonitor.Create;
    Holders := TDictionary<string, TTargetHolder>.Create;
    Tracks := TDictionary<string, TTrackState>.Create;
    Seen := TDictionary<string, Byte>.Create;
    OwnerCache := TDictionary<Cardinal, TTargetHolder>.Create;
    ThreadRefs := TList<THandle>.Create;
    Keys := TList<string>.Create;
    ObjectOwners := TDictionary<string, TList<Cardinal>>.Create;
    ObjectOwnerSeen := TDictionary<string, Byte>.Create;
    ObjectStates := TDictionary<string, TObjectState>.Create;
    Behavior := TBehaviorMonitor.Create;
    Lifecycle := TLifecycleMonitor.Create;
    Security := TSecurityMonitor.Create;
    IPC := TIPCMonitor.Create;
    Job := TJobMonitor.Create;
    Files := TFileMonitor.Create;
    Registry := TRegistryMonitor.Create;
    Scheduler := TSchedulerMonitor.Create;
    Namespace := TNamespaceMonitor.Create;
    KernelTrace := TETWMonitor.Create;
    KernelFusion := TETWFusion.Create;
    OriginGuard := TThreadOriginMonitor.Create;
    StackGuard := TStackGuardMonitor.Create;
    MappingGuard := TMappingGuard.Create;
    ProtectionGuard := TProtectionGuard.Create;
    ReadGuard := TReadAccessMonitor.Create;
    WriteGuard := TWriteWatchMonitor.Create;
    WaitGuard := TWaitChainMonitor.Create;
    CaptureGuard := TCaptureMonitor.Create;
    NetworkGuard := TNetworkGuard.Create;
    PathGuard := TPathGuard.Create;
    SelfGuard := TSelfGuardMonitor.Create;
    HeapTLS := THeapTLSMonitor.Create;
    ExceptionGuard := TExceptionGuardMonitor.Create;
    AsyncGuard := TAsyncGuardMonitor.Create;
    PEGuard := TPELoaderMonitor.Create;
    ExportGuard := TExportGuardMonitor.Create;
    SignalCorrelation := TSignalCorrelationMonitor.Create;
    CodeIntegrity := TPECodeIntegrityMonitor.Create;
    RegionClassifier := TMemoryRegionClassifier.Create;
    ImageFusion := TETWImageFusionMonitor.Create;
    InjectionEvidence := TInjectionEvidenceMonitor.Create;
    ExecutionProvenance := TThreadExecutionProvenance.Create;
    ImageCOW := TImageCOWMonitor.Create;
    TemporalGraph := TTemporalHandleGraph.Create;
    ModuleOrigin := TModuleOriginMonitor.Create;
    TraceHealth := TETWLossHealth.Create;
    Adaptive := TAdaptiveInspector.Create;
    Evidence := TEvidenceChain.Create;
    ImportRedirect := TImportRedirectionMonitor.Create;
    TLSCallback := TTLSCallbackMonitor.Create;
    UnwindConsistency := TUnwindConsistencyMonitor.Create;
    ExecLifecycle := TExecutableLifecycle.Create;
    SectionBacking := TSectionBackingMonitor.Create;
    StackProvenance := TThreadStackProvenanceMonitor.Create;
    Coverage := TCoverageWindowMonitor.Create;
    FalsePositive := TNewSignalSuppressor.Create;
    Explainable := TExplainableEvidence.Create;
    StableIdentity := TStableObjectIdentity.Create;
    ProcessSnapshots := TProcessSnapshotMonitor.Create;
    CrossViewLoader := TLoaderCrossViewMonitor.Create;
    FileAttest := TFileAttestationMonitor.Create;
    ControlAttest := TControlFlowAttestation.Create;
    ETWReconciler := TSnapshotETWReconciler.Create;
    if SharedObserver <> nil then DualObserver := SharedObserver
    else DualObserver := TDualObserver.Create;
    RAMHashChain := TForensicHashChain.Create;
    RiskEngine := TRiskConfidenceMonitor.Create;
    V80Epoch := TMultiEpochBaseline.Create;
    V80Code := TCodeProvenanceGraph.Create;
    V80Sections := TSectionCorrelation.Create;
    V80Indirect := TIndirectTargetMonitor.Create;
    V80ThreadHistory := TThreadTimeline.Create;
    V80Causal := TCausalAttackGraph.Create;
    V80Trust := TObservationTrust.Create;
    V80Controller := TResourceAwareController.Create;
    V80Incidents := TIncidentReconstruction.Create;
    FastEvents := TFastKernelSampleList.Create;
    RealtimeFusion := TRealtimeFusion.Create;
    RealtimeWake := TEventDrivenWake.Create;
    DeferredPipeline := TFastDeferredPipeline.Create;
    AccessMicroburst := TMicroburstAccess.Create;
    SnapshotTrigger := TTriggeredSnapshot.Create;
    MemoryDelta := TIncrementalMemoryDelta.Create;
    SensorRecovery := TSensorCoverageRecovery.Create;
    RealtimeBenchmark := TRealtimeBenchmark.Create;
    ActorIdentity := TSessionActorIdentity.Create;
    PrecisionTimeline := TPrecisionTimeline.Create;
    BehaviorFingerprint := TBehaviorFingerprint.Create;
    SensorConsensus := TSensorConsensus.Create;
    EvidenceCapsule := TMemoryEvidenceCapsule.Create;
    AdaptiveAnomaly := TAdaptiveAnomaly.Create;
    SensorDisagreement := TSensorDisagreement.Create;
    ObserverAttestation := TObserverAttestation.Create;
    PrivacyForensics := TPrivacyForensics.Create;
    HandleSharing := THandleSharingEvidence.Create;
    APCStyle := TAPCStyleEvidence.Create;
    SensorTamper := TSensorTamperHealth.Create;
    AllowedCreated := TCreationTimeMap.Create;
    AllocationGuard := TVirtualAllocationGuard.Create;
    SelfAllocationGuard := TVirtualAllocationGuard.Create;
    AllocationGuard.MappingObserver := MappingGuard;
    AllocationGuard.ProtectionObserver := ProtectionGuard;
    KernelEvents := TKernelEventList.Create;
    IPCTypes := TDictionary<Word, TIPCObjectKind>.Create;
    IPCObserved := TList<TIPCObservation>.Create;
    NativeThreads := TThreadSampleMap.Create;
    ParentMap := TProcessParentMap.Create;
    OwnerCreated := TCreationTimeMap.Create;
    ObservedHandles := TList<TObservedHandle>.Create;
    ObservedTokenHandles := TList<TObservedTokenHandle>.Create;
    RegisterRAMStores;
  end;

  procedure ResetTargetSession;
  begin
    Tracks.Clear;
    Seen.Clear;
    ObjectStates.Clear;
    Behavior.Reset;
    Lifecycle.Reset;
    Security.Reset;
    IPC.Reset;
    Job.Reset;
    Scheduler.Reset;
    Namespace.Reset(LivePID);
    KernelFusion.Reset;
    OriginGuard.Reset;
    StackGuard.Reset;
    AllocationGuard.Reset;
    SelfAllocationGuard.Reset;
    ReadGuard.Reset(LivePID);
    WriteGuard.Reset(LivePID);
    WaitGuard.Reset(LivePID);
    CaptureGuard.Reset;
    NetworkGuard.Reset;
    PathGuard.Reset;
    AllocationGuard.ExcludedAddress := ReadGuard.CanaryAddress;
    AllocationGuard.ExcludedWriteAddress := WriteGuard.RegionAddress;
    KernelTrace.SetTarget(LivePID);
    KernelTrace.TryStart;
    SelfGuard.Reset(KernelTrace.Ready);
    HeapTLS.Reset;
    ExceptionGuard.Reset;
    AsyncGuard.Reset;
    PEGuard.Reset;
    SignalCorrelation.Reset;
    CodeIntegrity.Reset;
    RegionClassifier.Reset;
    ImageFusion.Reset;
    InjectionEvidence.Reset;
    ExecutionProvenance.Reset;
    ImageCOW.Reset;
    TemporalGraph.Reset;
    ModuleOrigin.Reset;
    TraceHealth.Reset;
    Adaptive.Reset;
    Evidence.Reset;
    ImportRedirect.Reset;
    TLSCallback.Reset;
    UnwindConsistency.Reset;
    ExecLifecycle.Reset;
    SectionBacking.Reset;
    StackProvenance.Reset;
    Coverage.Reset;
    FalsePositive.Reset;
    Explainable.Reset;
    // v61-v69: RAM-only forensic state; no files or registry writes.
    StableIdentity.Reset;
    StableIdentity.ObserveTarget(Target, LivePID);
    ProcessSnapshots.Reset;
    CrossViewLoader.Reset;
    FileAttest.Reset;
    ControlAttest.Reset;
    ETWReconciler.Reset;
    RAMHashChain.Reset;
    RiskEngine.Reset;
    V80Epoch.Reset;
    V80Code.Reset;
    V80Sections.Reset;
    V80Indirect.Reset;
    V80ThreadHistory.Reset;
    V80Causal.Reset;
    V80Trust.Reset;
    V80Controller.Reset;
    V80Incidents.Reset;
    FastEvents.Clear;
    RealtimeFusion.Reset;
    RealtimeWake.Reset;
    DeferredPipeline.Reset;
    AccessMicroburst.Reset;
    SnapshotTrigger.Reset;
    MemoryDelta.Reset;
    SensorRecovery.Reset;
    RealtimeBenchmark.Reset;
    ActorIdentity.Reset;
    PrecisionTimeline.Reset;
    BehaviorFingerprint.Reset;
    SensorConsensus.Reset;
    EvidenceCapsule.Reset;
    AdaptiveAnomaly.Reset;
    SensorDisagreement.Reset;
    ObserverAttestation.Reset;
    PrivacyForensics.Reset;
    HandleSharing.Reset;
    APCStyle.Reset;
    SensorTamper.Reset;
    Faults.Reset;
    Unified.Reset;
    Budget.Reset;
    LastChainVerification := 0;
    DualObserver.Stop;
    { Missing privileges/resources leave the independent observation UNKNOWN.
      The inherited capability permits no license or overlay operations. }
    if not StopRequested then DualObserver.Start;
    Files.Reset(Target);
    try
      Registry.Reset;
    except
      // Registry monitoring is optional; preserve the v15 pipeline.
    end;
    IPCTypes.Clear;
    LastScanStart := 0;
    LastSummary := 0;
    LocalBaselineRemaining := Opt.BaselineScans;
    ProcessBaselineRemaining := Opt.BaselineScans;
    ThreadBaselineRemaining := Opt.BaselineScans;
    LastHandleCoverageReport := 0;
    // Retain the last warning tick across target restarts (30s dedupe).
    SampleHealth.WarningPending := False;
    SampleHealth.PreviousScanMS := 0;
    SampleHealth.HasPreviousScan := False;
  end;

  procedure InspectSecurityAndConfiguration;
  begin
    // v13: exact target token-object handle comparison, privilege-state
    // changes, DACL changes, and thread impersonation-token transitions.
    // Failed queries are UNKNOWN and never interpreted as disappearances.
    // Stabilization boundary: Security.ExamineTokenHandles (slot 10).
    if BeginProbe(10, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Security.Reset;
        end;
        Security.ExamineTokenHandles(ObservedTokenHandles,
          TokenSnapshotValid, LivePID, OwnerCreated,
          ProcessBaselineRemaining > 0, Detected);
        CompleteProbe(10, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(10, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: Security.ExamineLocalState (slot 10).
    if BeginProbe(10, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Security.Reset;
        end;
        Security.ExamineLocalState(Target, LivePID, NativeThreads,
          NativeThreadValid, TickStart,
          NewMonitorBaseline, Detected);
        CompleteProbe(10, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(10, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v14: IPC object watches share the same exact native handle snapshot.
    // Stabilization boundary: IPC.Examine (slot 11).
    if BeginProbe(11, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          IPC.Reset;
        end;
        IPC.Examine(IPCObserved, IPCSnapshotValid, TickStart, Detected);
        CompleteProbe(11, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(11, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // A membership transition is a state change, not evidence of coercion.
    // Stabilization boundary: Job.Examine (slot 12).
    if BeginProbe(12, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Job.Reset;
        end;
        Job.Examine(Target, TickStart, Detected);
        CompleteProbe(12, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(12, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v15: executable-file metadata, read-only, own unit and lifecycle.
    // Stabilization boundary: Files.Examine (slot 13).
    if BeginProbe(13, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Files.Reset(Target);
        end;
        Files.Examine(TickStart, Detected);
        CompleteProbe(13, ProbeStarted, orModuleFile,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(13, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v16: read-only native registry notifications and validated snapshots.
    // Stabilization boundary: Registry.Examine (slot 14).
    if BeginProbe(14, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Registry.Reset;
        end;
        Registry.Examine(TickStart, Detected);
        CompleteProbe(14, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(14, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v17: fixed scheduling settings, explicit affinities and mitigation
    // policy snapshots. Never classify dynamic scheduler boosts as changes.
    // Stabilization boundary: Scheduler.Examine (slot 15).
    if BeginProbe(15, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Scheduler.Reset;
        end;
        Scheduler.Examine(Target, LivePID, NativeThreads, NativeThreadValid,
          TickStart, NewMonitorBaseline, Detected);
        CompleteProbe(15, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(15, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v18: bounded NT Object Manager namespace, link targets, and DACL.
    // Read-only snapshots; failures never become change events.
    // Stabilization boundary: Namespace.Examine (slot 16).
    if BeginProbe(16, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Namespace.Reset(LivePID);
        end;
        Namespace.Examine(TickStart, Detected);
        CompleteProbe(16, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(16, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
  end;

  procedure CollectAndFuseKernelEvents;
  var
    FastSample: TFastKernelSample;
  begin
    // v19 optional ETW: bounded real-time queue and conservative fusion.
    // A missing ETW privilege/session never disables the NT snapshot path.
    KernelEvents.Clear;
    TraceLost := True;
    // Stabilization boundary: KernelTrace.Drain (slot 17).
    if BeginProbe(17, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        KernelTrace.TryRecover(WinTick64);
        KernelTrace.Drain(KernelEvents, TraceLost);
        CompleteProbe(17, ProbeStarted, orETW,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          KernelEvents.Clear;
          TraceLost := True;
          RejectProbe(17, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v84: an independent SPSC mirror of ETW callbacks is drained
    // without replacing or bypassing the original v19 ETW queue.
    FastEvents.Clear;
    FastLost := True;
    // Stabilization boundary: KernelTrace.DrainFast (slot 17).
    if BeginProbe(17, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        KernelTrace.DrainFast(FastEvents, FastLost);
        CompleteProbe(17, ProbeStarted, orETW,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          FastEvents.Clear;
          FastLost := True;
          RejectProbe(17, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    RealtimeRelevant := False;
    // Stabilization boundary: RealtimeFusion.Observe (slot 18).
    if BeginProbe(18, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          RealtimeFusion.Reset;
        end;
        RealtimeFusion.Observe(FastEvents, LivePID, RealtimeRelevant);
        CompleteProbe(18, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RealtimeRelevant := False;
          RejectProbe(18, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    for FastSample in FastEvents do
    begin
      if (FastSample.ArrivalQpc > 0) and
         NHWTryQpcElapsedUS(FastSample.ArrivalQpc, NHWQpcNow, DispatchUS) then
        RealtimeBenchmark.ObserveDispatch(DispatchUS, Cardinal(FastEvents.Count));
      if (FastSample.Event.PID = LivePID) or
         (FastSample.Event.ParentPID = LivePID) then
        // Stabilization boundary: PrecisionTimeline.Observe (slot 19).
        if BeginProbe(19, ProbeStarted, ProbeReset) then
        begin
          ProbeKinds := Detected;
          try
            PrecisionTimeline.Observe(0, Byte(Ord(FastSample.Event.Kind)),
              FastSample.ArrivalQpc, NHWQpcNow, TickStart);
            CompleteProbe(19, ProbeStarted, orDerived,
              ProbeKinds, Detected);
          except
            on E: Exception do
            begin
              Detected := ProbeKinds;
              RejectProbe(19, ProbeStarted, E);
              if NHWFatalSensorException(E) then raise;
            end;
          end;
        end;
    end;
    if FastLost then TraceLost := True;
    // v47: missing ETW data is visibility loss, not a confirmed attack.
    // Stabilization boundary: TraceHealth.Examine (slot 20).
    if BeginProbe(20, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          TraceHealth.Reset;
        end;
        TraceHealth.Examine(KernelTrace, TraceLost, WinTick64, Detected);
        CompleteProbe(20, ProbeStarted, orCoverage,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(20, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    if dkETWLoss in Detected then TraceLost := True;
    // v89: coverage problems are warnings, not proof of intrusion.
    // Stabilization boundary: SensorRecovery.Observe (slot 21).
    if BeginProbe(21, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          SensorRecovery.Reset;
        end;
        SensorRecovery.Observe(KernelTrace.Ready, TraceLost,
          KernelTrace.FastDropTotal, Stats.GapMS, Opt.IntervalMS,
          WinTick64, Detected);
        CompleteProbe(21, ProbeStarted, orCoverage,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(21, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v109: optional sensor unavailability and sustained loss are
    // coverage warnings only; never attributed to malicious tampering.
    // Stabilization boundary: SensorTamper.Observe (slot 22).
    if BeginProbe(22, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          SensorTamper.Reset;
        end;
        SensorTamper.Observe(KernelTrace.Ready, TraceLost,
          Opt.ThreadWatch and HandleSnapshotValid, ThreadSnapshotValid,
          NewMonitorBaseline, KernelTrace.FastDropTotal,
          Stats.GapMS, Opt.IntervalMS, WinTick64, Detected);
        CompleteProbe(22, ProbeStarted, orCoverage,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(22, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: KernelFusion.Examine (slot 23).
    if BeginProbe(23, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          KernelFusion.Reset;
        end;
        KernelFusion.Examine(KernelEvents, LivePID, NativeThreads,
          NativeThreadValid, ExternalEvent,
          NewMonitorBaseline, TraceLost, TickStart, Detected);
        CompleteProbe(23, ProbeStarted, orETW,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(23, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
  end;

  procedure InspectThreadAndMemoryState;
  begin
    // v20: inspect thread-start ADDRESS METADATA only; no remote reads.
    // Correlate new non-image starts with newly observed CREATE_THREAD
    // capabilities, not with any assumed CreateRemoteThread API call.
    // Stabilization boundary: OriginGuard.Examine (slot 24).
    if BeginProbe(24, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          OriginGuard.Reset;
        end;
        OriginGuard.Examine(LivePID, NativeThreads, NativeThreadValid,
          KernelEvents, WinTick64,
          NewMonitorBaseline, FreshCreateThreadAccess, Detected);
        if OriginGuard.ObservationFailed then BreakCorrelationCoverage;
        CompleteProbe(24, ProbeStarted, orThreadSnapshot,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(24, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v43: confirm self-process thread-start provenance in two distinct
    // complete native snapshots; never use unknown/partial snapshots.
    // Stabilization boundary: ExecutionProvenance.Examine (slot 25).
    if BeginProbe(25, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          ExecutionProvenance.Reset;
        end;
        ExecutionProvenance.Examine(LivePID = WinCurrentProcessId,
          NativeThreads, NativeThreadValid,
          NewMonitorBaseline, WinTick64, Detected);
        CompleteProbe(25, ProbeStarted, orThreadSnapshot,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(25, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v21: read-only x64 TEB stack-boundary and bounded page metadata
    // inspection.  Changes require comparable successful observations.
    // Stabilization boundary: StackGuard.Examine (slot 26).
    if BeginProbe(26, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          StackGuard.Reset;
        end;
        StackGuard.Examine(LivePID, NativeThreads, NativeThreadValid,
          WinTick64, NewMonitorBaseline, ExternalEvent, Detected);
        CompleteProbe(26, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(26, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v24: the same completed sweep now also observes page protection
    // transition history without reading target memory contents.
    // v22: bounded read-only virtual allocation METADATA sampling.
    // No page content reads, VirtualProtect, or target modification.
    // Stabilization boundary: AllocationGuard.Examine (slot 27).
    if BeginProbe(27, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          AllocationGuard.Reset;
          AllocationGuard.ExcludedAddress := ReadGuard.CanaryAddress;
          AllocationGuard.ExcludedWriteAddress := WriteGuard.RegionAddress;
        end;
        AllocationGuard.Examine(LivePID, WinTick64, Detected);
        if AllocationGuard.ObservationFailed then BreakCorrelationCoverage;
        CompleteProbe(27, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(27, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    if LivePID <> WinCurrentProcessId then
    begin
      // The target guard continues all original mapping, protection and
      // other allocation-derived analyses. These two kinds are self-only.
      Exclude(Detected, dkAllocation);
      Exclude(Detected, dkAllocationBurst);
      SelfAllocationKinds := [];
      // Stabilization boundary: SelfAllocationGuard.Examine (slot 28).
      if BeginProbe(28, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := SelfAllocationKinds;
        try
          if ProbeReset then
          begin
            SelfAllocationGuard.Reset;
          end;
          SelfAllocationGuard.Examine(WinCurrentProcessId, WinTick64,
            SelfAllocationKinds);
          if SelfAllocationGuard.ObservationFailed then BreakCorrelationCoverage;
          CompleteProbe(28, ProbeStarted, orSelfMemory,
            ProbeKinds, SelfAllocationKinds);
        except
          on E: Exception do
          begin
            SelfAllocationKinds := ProbeKinds;
            RejectProbe(28, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      Detected := Detected +
        (SelfAllocationKinds * [dkAllocation, dkAllocationBurst]);
    end;
    // v25: a protected, isolated self-test page is observed by metadata.
    // Guard loss is an access hint, not proof or attribution of RPM.
    // Stabilization boundary: ReadGuard.ExamineCanary (slot 4).
    if BeginProbe(4, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          ReadGuard.Reset(LivePID);
          AllocationGuard.ExcludedAddress := ReadGuard.CanaryAddress;
        end;
        ReadGuard.ExamineCanary(LivePID, WinTick64, Detected);
        CompleteProbe(4, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(4, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v26: independent self-owned write-watch region, no target writes.
    // Stabilization boundary: WriteGuard.Examine (slot 5).
    if BeginProbe(5, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          WriteGuard.Reset(LivePID);
          AllocationGuard.ExcludedWriteAddress := WriteGuard.RegionAddress;
        end;
        WriteGuard.Examine(LivePID, WinTick64, Detected);
        if WriteGuard.ObservationFailed then BreakCorrelationCoverage;
        CompleteProbe(5, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(5, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v27: asynchronous WCT. No WCT callbacks output to the console;
    // only complete, supported wait chains contribute to detection kinds.
    // Stabilization boundary: WaitGuard.Examine (slot 29).
    if BeginProbe(29, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          WaitGuard.Reset(LivePID);
        end;
        WaitGuard.Examine(NativeThreads, NativeThreadValid, LivePID,
          NewMonitorBaseline,
          WinTick64, Detected);
        CompleteProbe(29, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(29, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
  end;

  procedure InspectSystemAndSelfState;
  begin
    // v28: conservative packet-analysis telemetry. Existing capture
    // drivers alone are not detections; require library/proxy evidence.
    // Stabilization boundary: CaptureGuard.Examine (slot 30).
    if BeginProbe(30, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          CaptureGuard.Reset;
        end;
        CaptureGuard.Examine(WinTick64, Detected);
        CompleteProbe(30, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(30, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v29 WFP/network-state telemetry: no process-name or PE-based signal.
    // A state change is not evidence of packet interception.
    // Stabilization boundary: NetworkGuard.Examine (slot 31).
    if BeginProbe(31, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          NetworkGuard.Reset;
        end;
        NetworkGuard.Examine(WinTick64, Detected);
        CompleteProbe(31, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(31, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: PathGuard.Examine (slot 32).
    if BeginProbe(32, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          PathGuard.Reset;
        end;
        PathGuard.Examine(WinTick64, Detected);
        CompleteProbe(32, ProbeStarted, orObjectState,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(32, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v31: current-process IAT, actual native/Win32 function pointer
    // cells, callback registration, process parameters, and conservative
    // thread provenance. All reads are local, guarded and bounded.
    // Stabilization boundary: SelfGuard.Examine (slot 33).
    if BeginProbe(33, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          SelfGuard.Reset(KernelTrace.Ready);
        end;
        SelfGuard.Examine(KernelTrace, NativeThreads, NativeThreadValid,
          NewMonitorBaseline, WinTick64,
          HighExternalAccess, NativeUInt(ConsoleCallbackTarget), Detected);
        CompleteProbe(33, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(33, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v32: current-thread TLS/FLS slot references, an owned private heap
    // canary, and stable process heap-set snapshots. No remote reads or
    // unsupported inspection of Windows' private FLS callback table.
    // Stabilization boundary: HeapTLS.Examine (slot 34).
    if BeginProbe(34, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          HeapTLS.Reset;
        end;
        HeapTLS.Examine(NewMonitorBaseline, WinTick64,
          HighExternalAccess, Detected);
        CompleteProbe(34, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(34, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v33: self .pdata/.xdata unwind metadata, loader-registered function
    // table resolution and our OWN pass-through callback reference.
    // Read-only; neither stack unwind execution nor exception injection.
    // Stabilization boundary: ExceptionGuard.Examine (slot 35).
    if BeginProbe(35, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          ExceptionGuard.Reset;
        end;
        ExceptionGuard.Examine(NewMonitorBaseline, WinTick64,
          HighExternalAccess, Detected);
        CompleteProbe(35, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(35, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v34: only our self-owned completion port, work and timer are
    // inspected. No system-wide callback/table access is claimed.
    // A delayed worker callback is not itself an anomaly.
    // Stabilization boundary: AsyncGuard.Examine (slot 36).
    if BeginProbe(36, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          AsyncGuard.Reset;
        end;
        AsyncGuard.Examine(NewMonitorBaseline, WinTick64,
          HighExternalAccess, Detected);
        CompleteProbe(36, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(36, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v35: bounded read-only PE32+ loader metadata, excluding IAT and
    // .pdata already monitored by v31/v33. No memory-content scan.
    // Stabilization boundary: PEGuard.Examine (slot 37).
    if BeginProbe(37, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          PEGuard.Reset;
        end;
        PEGuard.Examine(NewMonitorBaseline, WinTick64, Detected);
        CompleteProbe(37, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(37, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v36: read-only EAT/forwarder/API-set metadata, resolved APIs,
    // and legitimate delay-import transitions. No new module loads.
    // Stabilization boundary: ExportGuard.Examine (slot 38).
    if BeginProbe(38, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          ExportGuard.Reset;
        end;
        ExportGuard.Examine(NewMonitorBaseline, WinTick64, Detected);
        CompleteProbe(38, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(38, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
  end;

  procedure InspectCodeAndInitialCorrelations;
  begin
    // v38/v39 inspect only the OWN process. Do not correlate observations
    // from different PIDs (e.g. external target + local PE state).
    if LivePID = WinCurrentProcessId then
    begin
      // Stabilization boundary: CodeIntegrity.Examine (slot 39).
      if BeginProbe(39, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            CodeIntegrity.Reset;
          end;
          CodeIntegrity.Examine(NewMonitorBaseline, WinTick64, Detected);
          OwnImageChanged := CodeIntegrity.OwnImageChanged;
          if CodeIntegrity.ObservationFailed then BreakCorrelationCoverage;
          CompleteProbe(39, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(39, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: RegionClassifier.Examine (slot 40).
      if BeginProbe(40, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            RegionClassifier.Reset;
          end;
          RegionClassifier.Examine(NewMonitorBaseline, WinTick64, Detected);
          if RegionClassifier.ObservationFailed then BreakCorrelationCoverage;
          CompleteProbe(40, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(40, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
    end;
    // v40: ordinary image-load events are never detections in isolation.
    // Stabilization boundary: ImageFusion.Examine (slot 41).
    if BeginProbe(41, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          ImageFusion.Reset;
        end;
        ImageFusion.Examine(KernelEvents, LivePID,
          NewMonitorBaseline, TraceLost,
          HighExternalAccess, WinTick64, Detected);
        CompleteProbe(41, ProbeStarted, orETW,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(41, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v44 and v46 are optional self-PID inspections with adaptive
    // cadence. v48 never throttles or changes the existing v1-v42 path.
    NewMonitorTrigger := HighExternalAccess or
      ((Detected * [dkPrivateThread, dkRemoteThread,
        dkExecutionProvenance, dkPECodeIntegrity,
        dkPrivateExecRegion, dkETWImageFusion]) <> []);
    if LivePID = WinCurrentProcessId then
      if Budget.AllowOptional(owImageVerification, WinTick64,
        NewMonitorBaseline, NewMonitorTrigger) then
      begin
        InspectionTick := WinTick64;
        if Adaptive.ShouldInspect(NewMonitorBaseline, NewMonitorTrigger,
          InspectionTick, 0) then
        begin
          InspectionPerformed := False;
          try
            // Separate acknowledgment for optional sensor 0.
            if BeginProbe(42, ProbeStarted, ProbeReset) then
            begin
              ProbeKinds := Detected;
              try
                if ProbeReset then ImageCOW.Reset;
                try
                  ImageCOW.Examine(NewMonitorBaseline, WinTick64, Detected);
                finally
                  InspectionPerformed := ImageCOW.InspectionAttempted;
                end;
                CompleteProbe(42, ProbeStarted, orSelfMemory, ProbeKinds, Detected);
              except
                on E: Exception do
                begin
                  Detected := ProbeKinds;
                  RejectProbe(42, ProbeStarted, E);
                  if NHWFatalSensorException(E) then raise;
                end;
              end;
            end;
          finally
            Adaptive.CompleteInspection(0, InspectionTick, InspectionPerformed);
          end;
        end;
        InspectionTick := WinTick64;
        if Adaptive.ShouldInspect(NewMonitorBaseline, NewMonitorTrigger,
          InspectionTick, 1) then
        begin
          InspectionPerformed := False;
          try
            // Separate acknowledgment for optional sensor 1.
            if BeginProbe(43, ProbeStarted, ProbeReset) then
            begin
              ProbeKinds := Detected;
              try
                if ProbeReset then ModuleOrigin.Reset;
                try
                  ModuleOrigin.Examine(NewMonitorBaseline,
                  HighExternalAccess, WinTick64, Detected);
                finally
                  InspectionPerformed := ModuleOrigin.InspectionAttempted;
                end;
                CompleteProbe(43, ProbeStarted, orModuleFile, ProbeKinds, Detected);
              except
                on E: Exception do
                begin
                  Detected := ProbeKinds;
                  RejectProbe(43, ProbeStarted, E);
                  if NHWFatalSensorException(E) then raise;
                end;
              end;
            end;
          finally
            Adaptive.CompleteInspection(1, InspectionTick, InspectionPerformed);
          end;
        end;
      end;
    // Do not infer validity from a quiet sensor. Only explicit failures,
    // isolation boundaries and observed ETW loss break these timelines.
    if TraceLost then BreakCorrelationCoverage;
    // v37: conservatively combine independent families of signals.
    // Stabilization boundary: SignalCorrelation.Examine (slot 44).
    if BeginProbe(44, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          SignalCorrelation.Reset;
        end;
        SignalCorrelation.Examine((ProcessBaselineRemaining > 0) or
          (ThreadBaselineRemaining > 0), HighExternalAccess,
          WinTick64, Detected, CorrelationCoverageValid);
        CompleteProbe(44, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(44, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v42: injection EVIDENCE, not a claim of proved injection.
    // Stabilization boundary: InjectionEvidence.Examine (slot 45).
    if BeginProbe(45, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          InjectionEvidence.Reset;
        end;
        InjectionEvidence.Examine(LivePID = WinCurrentProcessId,
          (ProcessBaselineRemaining > 0) or
          (ThreadBaselineRemaining > 0), HighExternalAccess,
          WinTick64, Detected, CorrelationCoverageValid);
        CompleteProbe(45, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(45, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
  end;

  procedure InspectImageAndForensicState;
  begin
    // v51-v56: only self-process memory and current-thread stack.
    // Never combine an external target's ID with our own memory state.
    if LivePID = WinCurrentProcessId then
    begin
      // Stabilization boundary: ImportRedirect.Examine (slot 46).
      if BeginProbe(46, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            ImportRedirect.Reset;
          end;
          ImportRedirect.Examine(NewMonitorBaseline,
            HighExternalAccess, WinTick64, Detected);
          CompleteProbe(46, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(46, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: TLSCallback.Examine (slot 47).
      if BeginProbe(47, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            TLSCallback.Reset;
          end;
          TLSCallback.Examine(NewMonitorBaseline,
            HighExternalAccess, WinTick64, Detected);
          CompleteProbe(47, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(47, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: UnwindConsistency.Examine (slot 48).
      if BeginProbe(48, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            UnwindConsistency.Reset;
          end;
          UnwindConsistency.Examine(NewMonitorBaseline,
            HighExternalAccess, WinTick64, Detected);
          CompleteProbe(48, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(48, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: ExecLifecycle.Examine (slot 49).
      if BeginProbe(49, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            ExecLifecycle.Reset;
          end;
          ExecLifecycle.Examine(NewMonitorBaseline,
            HighExternalAccess, WinTick64, Detected);
          CompleteProbe(49, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(49, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: SectionBacking.Examine (slot 50).
      if BeginProbe(50, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            SectionBacking.Reset;
          end;
          SectionBacking.Examine(NewMonitorBaseline,
            HighExternalAccess, WinTick64, Detected);
          CompleteProbe(50, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(50, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: StackProvenance.Examine (slot 51).
      if BeginProbe(51, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            StackProvenance.Reset;
          end;
          StackProvenance.Examine(NewMonitorBaseline,
            HighExternalAccess, WinTick64, Detected);
          CompleteProbe(51, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(51, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
    end;
    // Native10O: keep the full evidence set through all correlation and
    // recording. Output suppression applies only to presentation.
    // v67: the target has to match the kernel's PID+creation epoch.
    // A query failure makes correlation UNKNOWN, never confirmed.
    StableTarget := StableIdentity.ObserveTarget(Target, LivePID);
    Corroborated := HighExternalAccess or
      ((Detected * [dkPrivateThread, dkRemoteThread,
        dkPECodeIntegrity, dkImageCOWIntegrity, dkWriteIntegrity,
        dkInjectionEvidence, dkModuleOrigin, dkTLSCallbackIntegrity,
        dkImportRedirect]) <> []);
    RealtimeCorrelated := RealtimeFusion.CorrelatedWithExternal(
      HighExternalAccess, WinTick64);
    if RealtimeRelevant then DeferredPipeline.NotifyRelevant(WinTick64);
    if RealtimeCorrelated or (RapidAccess and HighExternalAccess) then
      SnapshotTrigger.SignalRelevant(WinTick64);
    SnapshotRequestTick := WinTick64;
    SnapshotKick := SnapshotTrigger.CorroboratedTrigger(
      Corroborated or RealtimeCorrelated, SnapshotRequestTick);
    SnapshotAttempted := False;
    if SnapshotKick and ((LivePID <> WinCurrentProcessId) or not StableTarget) then
      SnapshotTrigger.CompleteAttempt(SnapshotRequestTick, False);
    ObserverMismatch := False;
    if (LivePID = WinCurrentProcessId) and StableTarget then
    begin
      // v61: PSS handles/threads/VA metadata only, no dumps or clones.
      try
      // Stabilization boundary: ProcessSnapshots.Examine (slot 52).
      if BeginProbe(52, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            ProcessSnapshots.Reset;
          end;
          try
            ProcessSnapshots.Examine(True, NewMonitorBaseline,
              Corroborated or SnapshotKick, WinTick64, Detected,
              SnapshotKick);
          finally
            SnapshotAttempted := ProcessSnapshots.CaptureAttempted;
          end;
          CompleteProbe(52, ProbeStarted, orDerived,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(52, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      finally
        if SnapshotKick then
          SnapshotTrigger.CompleteAttempt(SnapshotRequestTick, SnapshotAttempted);
      end;
      // v62/v63: independent module enumeration and file identity.
      // Stabilization boundary: CrossViewLoader.Examine (slot 53).
      if BeginProbe(53, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            CrossViewLoader.Reset;
          end;
          CrossViewLoader.Examine(NewMonitorBaseline,
            Corroborated, WinTick64, Detected);
          CompleteProbe(53, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(53, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: FileAttest.Examine (slot 54).
      if BeginProbe(54, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            FileAttest.Reset;
          end;
          FileAttest.Examine(NewMonitorBaseline,
            Corroborated, WinTick64, Detected);
          CompleteProbe(54, ProbeStarted, orModuleFile,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(54, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // v64: registered callbacks, not arbitrary process memory.
      TraceRecordCallback := 0;
      TraceBufferCallback := 0;
      KernelTrace.GetCallbackTargets(TraceRecordCallback,
        TraceBufferCallback);
      // Stabilization boundary: ControlAttest.Examine (slot 55).
      if BeginProbe(55, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            ControlAttest.Reset;
          end;
          ControlAttest.Examine(NewMonitorBaseline,
            Corroborated, NativeUInt(ConsoleCallbackTarget),
            TraceRecordCallback, TraceBufferCallback, WinTick64, Detected);
          CompleteProbe(55, ProbeStarted, orSelfMemory,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(55, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // v66: optional second observer is the SAME executable in a
      // separate normal Windows process; all coordination is RAM-backed.
      // Stabilization boundary: DualObserver.Examine (slot 56).
      if BeginProbe(56, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            DualObserver.Stop;
            if not StopRequested then DualObserver.Start;
          end;
          ObserverMismatch := DualObserver.Examine(Corroborated,
            WinTick64, Detected);
          CompleteProbe(56, ProbeStarted, orObserver,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(56, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
      // Stabilization boundary: ObserverAttestation.Examine (slot 57).
      if BeginProbe(57, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            ObserverAttestation.Reset;
          end;
          ObserverAttestation.Examine(DualObserver, True,
            StableTarget, WinTick64);
          CompleteProbe(57, ProbeStarted, orObserver,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(57, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
    end;
    // v65: missing ETW events are not proof of a malicious action;
    // trace gaps and invalid native snapshots always invalidate fusion.
    // Stabilization boundary: ETWReconciler.Examine (slot 58).
    if BeginProbe(58, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          ETWReconciler.Reset;
        end;
        ETWReconciler.Examine(LivePID, NativeThreads,
          NativeThreadValid, KernelTrace.Ready, TraceLost,
          NewMonitorBaseline, Corroborated,
          KernelEvents, WinTick64, Detected);
        CompleteProbe(58, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(58, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
  end;

  procedure InspectTemporalReconstruction;
  begin
    // v71-v79: optional self-PID sensors and temporal evidence fusion.
    // Never replace v1-v70 detections or infer actor identity.
    V80Grade := ogUnknown;
    if (LivePID = WinCurrentProcessId) and StableTarget then
    try
      V80Heavy := Budget.AllowOptional(owV80Analysis, WinTick64,
        NewMonitorBaseline, Corroborated or NewMonitorTrigger) and
        V80Controller.ShouldRunHeavy(
          Corroborated or NewMonitorTrigger, WinTick64);
      if V80Heavy then
        // Stabilization boundary: V80Epoch.Observe (slot 59).
        if BeginProbe(59, ProbeStarted, ProbeReset) then
        begin
          ProbeKinds := Detected;
          try
            if ProbeReset then
            begin
              V80Epoch.Reset;
            end;
            V80Epoch.Observe(True, NewMonitorBaseline, WinTick64);
            CompleteProbe(59, ProbeStarted, orDerived,
              ProbeKinds, Detected);
          except
            on E: Exception do
            begin
              Detected := ProbeKinds;
              RejectProbe(59, ProbeStarted, E);
              if NHWFatalSensorException(E) then raise;
            end;
          end;
        end;
      V80Grade := V80Trust.Examine(NativeThreadValid,
        StableTarget, V80Epoch.Stable, KernelTrace.Ready,
        TraceLost, Stats.GapMS, Opt.IntervalMS,
        WinTick64, Detected);
      if V80Heavy then
      begin
        V80NewKinds := [];
        // Stabilization boundary: V80Code.Examine (slot 60).
        if BeginProbe(60, ProbeStarted, ProbeReset) then
        begin
          ProbeKinds := V80NewKinds;
          try
            if ProbeReset then
            begin
              V80Code.Reset;
            end;
            V80Code.Examine(True, NativeThreadValid,
              NewMonitorBaseline, V80Epoch.Stable,
              HighExternalAccess, NativeThreads,
              WinTick64, V80NewKinds);
            CompleteProbe(60, ProbeStarted, orDerived,
              ProbeKinds, V80NewKinds);
          except
            on E: Exception do
            begin
              V80NewKinds := ProbeKinds;
              RejectProbe(60, ProbeStarted, E);
              if NHWFatalSensorException(E) then raise;
            end;
          end;
        end;
        V80Kinds := Detected + V80NewKinds;
        V80SectionList := nil;
        if IPCSnapshotValid then V80SectionList := IPCObserved;
        // Stabilization boundary: V80Sections.Examine (slot 61).
        if BeginProbe(61, ProbeStarted, ProbeReset) then
        begin
          ProbeKinds := V80NewKinds;
          try
            if ProbeReset then
            begin
              V80Sections.Reset;
            end;
            V80Sections.Examine(True, NativeThreadValid,
              NewMonitorBaseline, V80Epoch.Stable,
              HighExternalAccess, LivePID, NativeThreads,
              V80SectionList, V80Kinds, WinTick64, V80NewKinds);
            CompleteProbe(61, ProbeStarted, orDerived,
              ProbeKinds, V80NewKinds);
          except
            on E: Exception do
            begin
              V80NewKinds := ProbeKinds;
              RejectProbe(61, ProbeStarted, E);
              if NHWFatalSensorException(E) then raise;
            end;
          end;
        end;
        V80Kinds := Detected + V80NewKinds;
        // Stabilization boundary: V80Indirect.Examine (slot 62).
        if BeginProbe(62, ProbeStarted, ProbeReset) then
        begin
          ProbeKinds := V80NewKinds;
          try
            if ProbeReset then
            begin
              V80Indirect.Reset;
            end;
            V80Indirect.Examine(True, NewMonitorBaseline,
              V80Epoch.Stable, V80Epoch.Epoch,
              NativeUInt(ConsoleCallbackTarget),
              TraceRecordCallback, TraceBufferCallback,
              V80Kinds, WinTick64, V80NewKinds);
            CompleteProbe(62, ProbeStarted, orDerived,
              ProbeKinds, V80NewKinds);
          except
            on E: Exception do
            begin
              V80NewKinds := ProbeKinds;
              RejectProbe(62, ProbeStarted, E);
              if NHWFatalSensorException(E) then raise;
            end;
          end;
        end;
        V80Kinds := Detected + V80NewKinds;
        // Stabilization boundary: V80ThreadHistory.Examine (slot 63).
        if BeginProbe(63, ProbeStarted, ProbeReset) then
        begin
          ProbeKinds := V80NewKinds;
          try
            if ProbeReset then
            begin
              V80ThreadHistory.Reset;
            end;
            V80ThreadHistory.Examine(True, NativeThreadValid,
              NewMonitorBaseline, V80Epoch.Stable,
              HighExternalAccess, NativeThreads, V80Kinds,
              WinTick64, V80NewKinds);
            CompleteProbe(63, ProbeStarted, orDerived,
              ProbeKinds, V80NewKinds);
          except
            on E: Exception do
            begin
              V80NewKinds := ProbeKinds;
              RejectProbe(63, ProbeStarted, E);
              if NHWFatalSensorException(E) then raise;
            end;
          end;
        end;
        Detected := Detected + V80NewKinds;
      end;
      V80Kinds := Detected;
      // Stabilization boundary: V80Causal.Examine (slot 64).
      if BeginProbe(64, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            V80Causal.Reset;
          end;
          V80Causal.Examine(True, NewMonitorBaseline,
            StableTarget, V80Grade = ogReliable,
            LivePID, V80Epoch.Epoch, HighExternalAccess,
            V80Kinds, WinTick64, Detected, CorrelationCoverageValid);
          CompleteProbe(64, ProbeStarted, orDerived,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(64, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
    except
      on E: Exception do
      begin
      RejectProbe(120, 0, E);
      if NHWFatalSensorException(E) then raise;
      // A failure in an OPTIONAL v71-v79 sensor cannot bring down
      // the original v1-v70 monitoring pipeline.
      V80Epoch.Reset;
      V80Code.Reset;
      V80Sections.Reset;
      V80Indirect.Reset;
      V80ThreadHistory.Reset;
      V80Causal.Reset;
      V80Trust.Reset;
      V80Grade := ogUnknown;
      end;
    end;
    // v83/v88: deferred, limited self-memory metadata reads. No new
    // remote scanning or changes to the legacy v1-v80 scan cadence.
    if LivePID = WinCurrentProcessId then
    try
      RealtimeHeavy := Budget.AllowOptional(owMemoryDelta, WinTick64,
        NewMonitorBaseline, RealtimeCorrelated) and
        DeferredPipeline.AllowDeferred(WinTick64,
          NewMonitorBaseline, SensorRecovery.Degraded(WinTick64));
      // Stabilization boundary: MemoryDelta.Examine (slot 65).
      if BeginProbe(65, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          if ProbeReset then
          begin
            MemoryDelta.Reset;
          end;
          MemoryDelta.Examine(True, NewMonitorBaseline,
            RealtimeHeavy, WinTick64);
          CompleteProbe(65, ProbeStarted, orDerived,
            ProbeKinds, Detected);
          if RealtimeHeavy then DeferredPipeline.CompleteDeferred(True);
        except
          on E: Exception do
          begin
            if RealtimeHeavy then DeferredPipeline.CompleteDeferred(False);
            Detected := ProbeKinds;
            RejectProbe(65, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end
      else if RealtimeHeavy then DeferredPipeline.CompleteDeferred(False);
    except
      on E: Exception do
      begin
        DeferredPipeline.CompleteDeferred(False);
        RejectProbe(121, 0, E);
        if NHWFatalSensorException(E) then raise;
        MemoryDelta.Reset;
      end;
    end;
  end;

  procedure EvaluateRiskAndConsensus;
  begin
    // v104: correlate a fresh external thread-context capability
    // with independent self-process execution/memory evidence.
    // Never call this a confirmed APC injection.
    // Stabilization boundary: APCStyle.Examine (slot 66).
    if BeginProbe(66, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          APCStyle.Reset;
        end;
        APCStyle.Examine(LivePID = WinCurrentProcessId,
          ThreadSnapshotValid and NativeThreadValid, NewMonitorBaseline,
          WinTick64, Detected);
        CompleteProbe(66, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(66, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v69: multiple independent families are required; a score is
    // evidence quality, not attribution or a security decision.
    NewRiskKinds := Detected;
    RiskFamilies := [];
    RiskScore := 0;
    // Stabilization boundary: RiskEngine.Evaluate (slot 67).
    if BeginProbe(67, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := NewRiskKinds;
      try
        if ProbeReset then
        begin
          RiskEngine.Reset;
        end;
        RiskFamilies := RiskEngine.Evaluate(Detected,
          HighExternalAccess, TraceLost, ObserverMismatch, StableTarget,
          WinTick64, RiskScore, NewRiskKinds, CorrelationCoverageValid);
        CompleteProbe(67, ProbeStarted, orDerived,
          ProbeKinds, NewRiskKinds);
      except
        on E: Exception do
        begin
          NewRiskKinds := ProbeKinds;
          RejectProbe(67, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    Detected := NewRiskKinds;
    // v79: incident grouping is bounded and never assigns an actor.
    // New signal labels are added only after existing v69 assessment.
    if LivePID = WinCurrentProcessId then
    begin
      V80Kinds := Detected;
      // Stabilization boundary: V80Incidents.RecordFrame (slot 68).
      if BeginProbe(68, ProbeStarted, ProbeReset) then
      begin
        ProbeKinds := Detected;
        try
          V80Incidents.RecordFrame(LivePID, V80Epoch.Epoch,
            WinTick64, V80Kinds, HighExternalAccess,
            V80Grade = ogReliable, RiskScore, Detected);
          CompleteProbe(68, ProbeStarted, orDerived,
            ProbeKinds, Detected);
        except
          on E: Exception do
          begin
            Detected := ProbeKinds;
            RejectProbe(68, ProbeStarted, E);
            if NHWFatalSensorException(E) then raise;
          end;
        end;
      end;
    end;
    // v92/v96/v97: quality, rights-pattern and visibility models
    // are metadata only. They never overwrite v1-v90 detection kinds.
    // Stabilization boundary: SensorConsensus.Evaluate (slot 69).
    if BeginProbe(69, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          SensorConsensus.Reset;
        end;
        SensorConsensus.Evaluate(Detected, HighExternalAccess,
          ObserverMismatch, StableTarget, KernelTrace.Ready,
          TraceLost, WinTick64);
        CompleteProbe(69, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(69, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: AdaptiveAnomaly.Observe (slot 70).
    if BeginProbe(70, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          AdaptiveAnomaly.Reset;
        end;
        AdaptiveAnomaly.Observe(NewAccessEdges, NewMonitorBaseline,
          NativeThreadValid and ThreadSnapshotValid,
          WinTick64);
        CompleteProbe(70, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(70, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: SensorDisagreement.Observe (slot 71).
    if BeginProbe(71, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          SensorDisagreement.Reset;
        end;
        SensorDisagreement.Observe(StableTarget, NativeThreadValid,
          KernelTrace.Ready, TraceLost, RealtimeRelevant,
          HighExternalAccess, WinTick64);
        CompleteProbe(71, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(71, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    if Faults.CycleIncomplete or TraceLost or not StableTarget or
       not NativeThreadValid or not KernelTrace.Ready or
       not HandleSnapshotValid or (ProcessBaselineRemaining > 0) or
       (ThreadBaselineRemaining > 0) then
      Unified.MarkIncomplete;
    SensorConsensus.ConstrainToObservedRoots(Unified.PrimaryRootCount,
      Unified.CurrentComplete);
  end;

  procedure RecordCycleEvidence;
  var
    Confirmed, KindCorrelated: Boolean;
    Frame: TUnifiedFrame;
    Kind: TDetectionKind;
    Root: TObservationRoot;
    Families: Byte;
    ReportKinds: TDetectionKinds;
  begin
    // v95/v99: actor-unattributed evidence is stored without raw PIDs.
    // Stabilization boundary: EvidenceCapsule.Append (slot 72).
    if BeginProbe(72, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        EvidenceCapsule.Append(WinTick64, 0,
          SensorConsensus.Last.Confidence, TraceLost, Detected);
        CompleteProbe(72, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(72, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: PrivacyForensics.Prune (slot 3).
    if BeginProbe(3, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        PrivacyForensics.Prune(WinTick64);
        CompleteProbe(3, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(3, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v68: verify the in-RAM cryptographic chain periodically; no
    // persistence or telemetry upload. Unavailable crypto is UNKNOWN.
    if HashingAvailable and (RAMHashChain.Count > 0) and
      ((LastChainVerification = 0) or
       (WinTick64 - LastChainVerification >= 30000)) then
    begin
      LastChainVerification := WinTick64;
      if not RAMHashChain.Verify then
        Include(Detected, dkEvidenceIntegrity);
    end;
    // Stabilization boundary: RAMHashChain.Append (slot 73).
    if BeginProbe(73, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        RAMHashChain.Append(WinTick64, LivePID, Detected,
          Byte(RiskScore), TraceLost);
        CompleteProbe(73, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(73, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v49: bounded, in-memory, actor-unattributed evidence timeline.
    EvidenceFlags := [];
    if HighExternalAccess then Include(EvidenceFlags, efExternalCapability);
    if TraceLost then Include(EvidenceFlags, efETWGap);
    if (Detected * [dkPrivateThread, dkRemoteThread,
      dkExecutionProvenance]) <> [] then
      Include(EvidenceFlags, efThreadOrigin);
    if (Detected * [dkPECodeIntegrity, dkPrivateExecRegion,
      dkImageCOWIntegrity, dkModuleOrigin]) <> [] then
      Include(EvidenceFlags, efMemoryChange);
    // Stabilization boundary: Evidence.RecordFrame (slot 74).
    if BeginProbe(74, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        Evidence.RecordFrame(WinTick64, LivePID, Detected, EvidenceFlags);
        CompleteProbe(74, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(74, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v59: bounded per-event explanation, actor remains unattributed.
    // Stabilization boundary: Explainable.RecordFrame (slot 75).
    if BeginProbe(75, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        Explainable.RecordFrame(WinTick64, LivePID, Detected, EvidenceFlags);
        CompleteProbe(75, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(75, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    if Faults.TakeCoverageWarning(WinTick64) then
      Include(Detected, dkObservationUncertain);
    Unified.Add(orDerived, Detected);
    Unified.Commit;
    VisibleDetected := FalsePositive.FilterForOutput(Detected,
      NewMonitorBaseline, WinTick64);
    // The PE monitor already requires a stable baseline and two matching
    // complete changed reads. Other user-mode indicators need independent
    // reliable acquisition roots and a strong execution/integrity finding.
    Confirmed := not NewMonitorBaseline and
      (OwnImageChanged or
       (SensorConsensus.Last.Corroborated and
        ((VisibleDetected * [dkInjectionEvidence, dkRemoteThread,
          dkPrivateThread, dkWriteIntegrity, dkImportRedirect,
          dkTLSCallbackIntegrity, dkImageCOWIntegrity, dkPECodeIntegrity]) <> [])));
    { Reporting is fed from the typed evidence before diagnostics and before
      the local stop latch. Its provenance mask contains observed acquisition
      roots only; derived correlators never manufacture a second root. }
    if Assigned(OnDetection) then
    begin
      if not Unified.Recent(0, Frame) then Frame := Default(TUnifiedFrame);
      ReportKinds := VisibleDetected + NHWContextObservations;
      for Kind := Low(TDetectionKind) to High(TDetectionKind) do
        if Kind in ReportKinds then
        begin
          Families := 0;
          for Root := orHandleSnapshot to orObserver do
            if Kind in Frame.RootKinds[Root] then
              Families := Families or Byte(1 shl Ord(Root));
          KindCorrelated := not NewMonitorBaseline and
            SensorConsensus.Last.Corroborated and
            (Kind in [dkInjectionEvidence, dkRemoteThread, dkPrivateThread,
              dkWriteIntegrity, dkImportRedirect, dkTLSCallbackIntegrity,
              dkImageCOWIntegrity, dkPECodeIntegrity]);
          if KindCorrelated then
          begin
            { A derived incident names its actual contributing acquisition
              roots. These roots were constrained by complete frame coverage
              above; a derived kind alone contributes no additional root. }
            Families := 0;
            for Root := orHandleSnapshot to orObserver do
              if Root in Frame.Roots then
                Families := Families or Byte(1 shl Ord(Root));
          end;
          OnDetection([Kind], WinTick64, Families,
            SensorConsensus.Last.Confidence, KindCorrelated,
            not (Kind in VisibleDetected));
        end;
      FillChar(Frame, SizeOf(Frame), 0);
    end;
    if Assigned(OnObservation) and (Confirmed or (Detected <> [])) then
      OnObservation(Detected, Confirmed);
  end;

  procedure FinalizeSamplingAndReport;
  begin
    CurrentTick := WinTick64;
    Stats.ScanMS := CurrentTick - TickStart;
    // v90: all timing statistics remain in bounded RAM, not the console.
    RealtimeBenchmark.ObserveScan(Stats.ScanMS,
      KernelTrace.FastDropTotal, CurrentTick);
    UpdateSampling(SampleHealth, Stats, Opt.IntervalMS, CurrentTick);
    Detected := [];
    // Stabilization boundary: ReadGuard.ExamineSampling (slot 4).
    if BeginProbe(4, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          ReadGuard.Reset(LivePID);
          AllocationGuard.ExcludedAddress := ReadGuard.CanaryAddress;
        end;
        ReadGuard.ExamineSampling(Stats, Opt.IntervalMS, CurrentTick, Detected);
        CompleteProbe(4, ProbeStarted, orSelfMemory,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(4, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v57: track sustained polling uncertainty, never claim attack.
    // Stabilization boundary: Coverage.Examine (slot 76).
    if BeginProbe(76, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          Coverage.Reset;
        end;
        Coverage.Examine(Stats.ScanMS, Stats.GapMS, Opt.IntervalMS,
          TraceLost, CurrentTick, Detected);
        CompleteProbe(76, ProbeStarted, orCoverage,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(76, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // v78: only the optional new sensors adapt to scan load.
    // Existing v1-v70 loops and sampling warnings are unchanged.
    // Stabilization boundary: V80Controller.ObserveScan (slot 77).
    if BeginProbe(77, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        if ProbeReset then
        begin
          V80Controller.Reset;
        end;
        V80Controller.ObserveScan(Stats.ScanMS, Stats.GapMS,
          Opt.IntervalMS, CurrentTick, Detected);
        CompleteProbe(77, ProbeStarted, orCoverage,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(77, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: Evidence.RecordFrame (slot 74).
    if BeginProbe(74, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        Evidence.RecordFrame(CurrentTick, LivePID, Detected, []);
        CompleteProbe(74, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(74, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Stabilization boundary: Explainable.RecordFrame (slot 75).
    if BeginProbe(75, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        Explainable.RecordFrame(CurrentTick, LivePID, Detected, []);
        CompleteProbe(75, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(75, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    // Preserve the v57 sampling warning in the new RAM-only chain.
    // Stabilization boundary: RAMHashChain.Append (slot 73).
    if BeginProbe(73, ProbeStarted, ProbeReset) then
    begin
      ProbeKinds := Detected;
      try
        RAMHashChain.Append(CurrentTick, LivePID, Detected, 0, False);
        CompleteProbe(73, ProbeStarted, orDerived,
          ProbeKinds, Detected);
      except
        on E: Exception do
        begin
          Detected := ProbeKinds;
          RejectProbe(73, ProbeStarted, E);
          if NHWFatalSensorException(E) then raise;
        end;
      end;
    end;
    if Faults.TakeCoverageWarning(CurrentTick) then
      Include(Detected, dkObservationUncertain);
    VisibleDetected := FalsePositive.FilterForOutput(Detected,
      NewMonitorBaseline, WinTick64);
    { Coverage/timing findings remain observable without becoming attacks. }
    if Assigned(OnDetection) and (VisibleDetected <> []) then
      OnDetection(VisibleDetected, CurrentTick, 0, 0, False, False);
    if Assigned(OnObservation) and (VisibleDetected <> []) then
      OnObservation(VisibleDetected, False);
    if (LastSummary = 0) or (CurrentTick - LastSummary >= Opt.SummaryMS) or not Opt.Watch then
    begin
      EmitPendingSamplingWarning(SampleHealth);
      LastSummary := CurrentTick;
    end;
  end;

  procedure ReleaseSessionComponents;
  var
    ObjKey: string;
  begin
    if RAM <> nil then RAM.Clear;
    if ObjectOwners <> nil then
      for ObjKey in ObjectOwners.Keys do
        ObjectOwners[ObjKey].Free;
    IPCObserved.Free;
    IPCTypes.Free;
    // Stop only our owned ETW session and join the callback worker first.
    KernelTrace.Free;
    OriginGuard.Free;
    RiskEngine.Free;
    RealtimeBenchmark.Free;
    AllowedCreated.Free;
    SensorTamper.Free;
    APCStyle.Free;
    HandleSharing.Free;
    PrivacyForensics.Free;
    ObserverAttestation.Free;
    SensorDisagreement.Free;
    AdaptiveAnomaly.Free;
    EvidenceCapsule.Free;
    SensorConsensus.Free;
    BehaviorFingerprint.Free;
    PrecisionTimeline.Free;
    ActorIdentity.Free;
    SensorRecovery.Free;
    MemoryDelta.Free;
    SnapshotTrigger.Free;
    AccessMicroburst.Free;
    DeferredPipeline.Free;
    RealtimeWake.Free;
    RealtimeFusion.Free;
    FastEvents.Free;
    V80Incidents.Free;
    V80Controller.Free;
    V80Trust.Free;
    V80Causal.Free;
    V80ThreadHistory.Free;
    V80Indirect.Free;
    V80Sections.Free;
    V80Code.Free;
    V80Epoch.Free;
    RAMHashChain.Free;
    if SharedObserver = nil then DualObserver.Free
    else if DualObserver <> nil then DualObserver.Stop;
    ETWReconciler.Free;
    ControlAttest.Free;
    FileAttest.Free;
    CrossViewLoader.Free;
    ProcessSnapshots.Free;
    StableIdentity.Free;
    Explainable.Free;
    FalsePositive.Free;
    Coverage.Free;
    StackProvenance.Free;
    SectionBacking.Free;
    ExecLifecycle.Free;
    UnwindConsistency.Free;
    TLSCallback.Free;
    ImportRedirect.Free;
    Evidence.Free;
    Adaptive.Free;
    TraceHealth.Free;
    ModuleOrigin.Free;
    TemporalGraph.Free;
    ImageCOW.Free;
    ExecutionProvenance.Free;
    InjectionEvidence.Free;
    ImageFusion.Free;
    RegionClassifier.Free;
    CodeIntegrity.Free;
    SignalCorrelation.Free;
    ExportGuard.Free;
    PEGuard.Free;
    AsyncGuard.Free;
    ExceptionGuard.Free;
    HeapTLS.Free;
    SelfGuard.Free;
    PathGuard.Free;
    NetworkGuard.Free;
    CaptureGuard.Free;
    WaitGuard.Free;
    WriteGuard.Free;
    ReadGuard.Free;
    SelfAllocationGuard.Free;
    AllocationGuard.Free;
    ProtectionGuard.Free;
    MappingGuard.Free;
    StackGuard.Free;
    KernelEvents.Free;
    KernelFusion.Free;
    Namespace.Free;
    Scheduler.Free;
    Registry.Free;
    Files.Free;
    Job.Free;
    IPC.Free;
    ObservedTokenHandles.Free;
    ObservedHandles.Free;
    OwnerCreated.Free;
    ParentMap.Free;
    NativeThreads.Free;
    Security.Free;
    Lifecycle.Free;
    Behavior.Free;
    ObjectStates.Free;
    ObjectOwnerSeen.Free;
    ObjectOwners.Free;
    if ThreadRefs <> nil then ReleaseThreadReferences(ThreadRefs);
    CloseNativeProcess(TokenReference);
    if Target <> 0 then CloseNativeProcess(Target);
    Keys.Free;
    ThreadRefs.Free;
    OwnerCache.Free;
    Seen.Free;
    Tracks.Free;
    Holders.Free;
    if Assigned(OnKernelReady) then OnKernelReady(nil);
    KernelTrust.Free;
    RAM.Free;
    Budget.Free;
    Unified.Free;
    Faults.Free;
  end;


begin
  InitializeSessionReferences;
  try
    CreateSessionComponents;
    KernelTrust.ConfigureResponseSinks(TrustSink, DriverSink, IntegritySink);
    if Assigned(OnKernelReady) then OnKernelReady(KernelTrust);
    LastSummary := 0;
    LastChainVerification := 0;
    LastScanStart := 0;
    SampleHealth := Default(TSamplingHealth);
    LocalBaselineRemaining := Opt.BaselineScans;
    ProcessBaselineRemaining := Opt.BaselineScans;
    ThreadBaselineRemaining := Opt.BaselineScans;
    LastHandleCoverageReport := 0;
    // GUI hosts have ETW callbacks but no console callback.
    ConsoleCallbackTarget := nil;
    repeat
        if StopRequested then Break;
        RunKernelTrustIndependent;
        if StopRequested then Break;
        if Target = 0 then
        begin
          if Opt.TargetName <> '' then
          begin
            if not FindTargetByName(Opt.TargetName, FoundPID, MatchCount, Reason) then
            begin
              if not Opt.Watch then Break;
              SleepInterruptible(Opt.IntervalMS);
              Continue;
            end;
            if FoundPID = 0 then
            begin
              if not Opt.Watch then Break;
              SleepInterruptible(Opt.IntervalMS);
              Continue;
            end;
            LivePID := FoundPID;
          end
          else
            LivePID := Opt.TargetPID;

          Target := OpenNativeProcess(LivePID,
            NATIVE_PROCESS_QUERY_LIMITED_INFORMATION or ACCESS_SYNCHRONIZE);
          if Target = 0 then
          begin
            if Opt.TargetName = '' then Break;
            SleepInterruptible(Opt.IntervalMS);
            Continue;
          end;
          Wow64 := False;
          if (not WinIsWow64Process(Target, Wow64)) or Wow64 then Break;
          ResetTargetSession;
        end;

        WaitResult := WinWaitForSingleObject(Target, 0);
        if WaitResult = WAIT_OBJECT_0 then
        begin
          CloseNativeProcess(Target);
          if Opt.TargetName = '' then Break;
          SleepInterruptible(Opt.IntervalMS);
          Continue;
        end;
        if WaitResult <> WAIT_TIMEOUT then Break;

        TickStart := WinTick64;
        NHWBeginContextCycle(LocalBaselineRemaining > 0);
        CorrelationCoverageValid := True;
        Faults.BeginCycle;
        Budget.BeginCycle(TickStart, Opt.IntervalMS);
        Unified.BeginFrame(TickStart, LivePID, StableIdentity.TargetCreation);
        RAM.Maintain(TickStart);
        if RAM.CycleFailure then Unified.MarkIncomplete;
        Stats := Default(TScanStats);
        if LastScanStart <> 0 then
          Stats.GapMS := TickStart - LastScanStart;

        NativeThreadValid := ReadSystemThreadSnapshot(LivePID,
          ParentMap, NativeThreads);
        if not NativeThreadValid then
        begin
          Lifecycle.InvalidateThreadBaseline;
          Unified.MarkIncomplete;
          BreakCorrelationCoverage;
        end;
        ThreadRefsComplete := False;
        try
          if Opt.ThreadWatch then
            ThreadRefsComplete := CaptureThreadReferences(LivePID, ThreadRefs);
          TokenReference := OpenNativeProcessToken(Target, TOKEN_QUERY_RIGHT);
          HandleSnapshotValid := CollectHolders(Target, LivePID, ThreadRefs,
            ThreadRefsComplete, Holders, ObservedHandles, TokenReference,
            ObservedTokenHandles, IPCTypes, IPCObserved, IPCSnapshotValid,
            TokenSnapshotValid, ThreadSnapshotValid, TotalHandles, Reason);
        finally
          CloseNativeProcess(TokenReference);
          ReleaseThreadReferences(ThreadRefs);
        end;

        if not HandleSnapshotValid then
        begin
          // A failed inventory does not describe an empty set of handles.
          // Keep the independent probes live and prevent cross-gap consensus.
          Lifecycle.InvalidateThreadBaseline;
          Unified.MarkIncomplete;
          BreakCorrelationCoverage;
          if Assigned(OnHandleCoverageUnavailable) and
             ((LastHandleCoverageReport = 0) or
              (TickStart < LastHandleCoverageReport) or
              (TickStart - LastHandleCoverageReport >= 30000)) then
          begin
            LastHandleCoverageReport := TickStart;
            OnHandleCoverageUnavailable(TickStart);
          end;
        end
        else if Opt.ThreadWatch and not ThreadSnapshotValid then
          BreakCorrelationCoverage;
        LastScanStart := TickStart;
        Seen.Clear;
        ReadGuard.BeginSnapshot;
        OwnerCache.Clear;
        OwnerCreated.Clear;
        AllowedCreated.Clear;
        Detected := [];
        OwnImageChanged := False;
        FreshCreateThreadAccess := False;
        HighExternalAccess := False;
        NewAccessEdges := 0;
        RapidAccess := False;
        NewMonitorBaseline := LocalBaselineRemaining > 0;
        if HandleSnapshotValid then
        begin
          Behavior.BeginSnapshot(TickStart, ProcessBaselineRemaining > 0,
            ThreadBaselineRemaining > 0, ThreadSnapshotValid);
          for ObjKey in ObjectOwners.Keys do
            ObjectOwners[ObjKey].Free;
          ObjectOwners.Clear;
          ObjectOwnerSeen.Clear;

          for Pair in Holders do
          begin
            H := Pair.Value;
            if H.IsThread and not ThreadSnapshotValid then Continue;
            // The v66 cooperating observer opens only a query-only handle.
            // Ignore that benign self-generated handle, but NEVER ignore
            // its VM_READ/VM_WRITE/VM_OPERATION/CREATE_THREAD escalation.
            if (DualObserver.ObserverPID <> 0) and
               (H.PID = DualObserver.ObserverPID) and (not H.IsThread) and
               ((H.RightsUnion and (ACCESS_VM_READ or ACCESS_VM_WRITE or
                 ACCESS_VM_OPERATION or ACCESS_CREATE_THREAD)) = 0) then
              Continue;
            if (Opt.IgnorePID <> 0) and (H.PID = Opt.IgnorePID) then Continue;

            if OwnerCache.TryGetValue(H.PID, Cached) then
            begin
              H.ImagePath := Cached.ImagePath;
              H.CreateTime := Cached.CreateTime;
            end
            else
            begin
              QueryOwnerInfo(H);
              OwnerCache.AddOrSetValue(H.PID, H);
              if H.CreateTime <> 0 then
                OwnerCreated.AddOrSetValue(H.PID, H.CreateTime);
            end;
            if (Opt.IgnorePathPrefix <> '') and
               SameText(Copy(H.ImagePath, 1, Length(Opt.IgnorePathPrefix)), Opt.IgnorePathPrefix) then Continue;

            if H.CreateTime <> 0 then
              AllowedCreated.AddOrSetValue(H.PID, H.CreateTime);
            // Stabilization boundary: StableIdentity.ObserveHolder (slot 1).
            if BeginProbe(1, ProbeStarted, ProbeReset) then
            begin
              ProbeKinds := Detected;
              try
                if ProbeReset then
                begin
                  StableIdentity.Reset;
                end;
                StableIdentity.ObserveHolder(H, TickStart);
                CompleteProbe(1, ProbeStarted, orDerived,
                  ProbeKinds, Detected);
              except
                on E: Exception do
                begin
                  Detected := ProbeKinds;
                  RejectProbe(1, ProbeStarted, E);
                  if NHWFatalSensorException(E) then raise;
                end;
              end;
            end;
            Key := IdentityKey(H);
            Seen.AddOrSetValue(Key, 1);
            First := not Tracks.TryGetValue(Key, T);
            WasInactive := False;
            RightsAdded := False;
            NewRelevantRights := 0;
            CountIncreased := False;
            if First then PreviousRightsForRead := 0
            else PreviousRightsForRead := T.LastRightsUnion;
            if First then
            begin
              T := Default(TTrackState);
              T.PID := H.PID;
              T.CreateTime := H.CreateTime;
            end
            else
            begin
              WasInactive := not T.Active;
              CountIncreased := H.HandleCount > T.LastHandleCount;
              // New rights are capability changes in observed handles, not proof
              // that Windows changed an existing handle's granted access.
              NewRelevantRights := H.RightsUnion and (not T.LastRightsUnion) and
                (SignificantRights(H) or QueryRights(H));
              RightsAdded := T.Active and
                ((H.Level > T.LastLevel) or (NewRelevantRights <> 0));
            end;

            T.PID := H.PID;
            T.CreateTime := H.CreateTime;
            T.LastSeenTick := TickStart;
            T.MissingScans := 0;
            T.LastLevel := H.Level;
            T.LastRightsUnion := H.RightsUnion;
            T.LastHandleCount := H.HandleCount;
            T.Active := True;
            T.IsThread := H.IsThread;
            Tracks.AddOrSetValue(Key, T);

            if H.IsThread then
            begin
              InBaseline := ThreadBaselineRemaining > 0;
              Threshold := Opt.ThreadMinLevel;
            end
            else
            begin
              InBaseline := ProcessBaselineRemaining > 0;
              Threshold := Opt.MinLevel;
            end;

            // v91/v94/v99: only verified PID+creation epochs get random
            // RAM-only aliases. Never copy an owner name/path into new state.
            if (not InBaseline) and (First or WasInactive or RightsAdded) then
            begin
              if NewAccessEdges < High(Cardinal) then Inc(NewAccessEdges);
              ActorAlias := ActorIdentity.Observe(H.PID, H.CreateTime,
                TickStart);
              if ActorAlias <> 0 then
              begin
                // Stabilization boundary: BehaviorFingerprint.Observe (slot 2).
                if BeginProbe(2, ProbeStarted, ProbeReset) then
                begin
                  ProbeKinds := Detected;
                  try
                    if ProbeReset then
                    begin
                      BehaviorFingerprint.Reset;
                    end;
                    BehaviorFingerprint.Observe(ActorAlias, H.RightsUnion,
                      H.IsThread, True, TickStart);
                    CompleteProbe(2, ProbeStarted, orDerived,
                      ProbeKinds, Detected);
                  except
                    on E: Exception do
                    begin
                      Detected := ProbeKinds;
                      RejectProbe(2, ProbeStarted, E);
                      if NHWFatalSensorException(E) then raise;
                    end;
                  end;
                end;
                // Stabilization boundary: PrivacyForensics.Observe (slot 3).
                if BeginProbe(3, ProbeStarted, ProbeReset) then
                begin
                  ProbeKinds := Detected;
                  try
                    PrivacyForensics.Observe(ActorAlias, TickStart,
                      NHWRightsCategory(H.RightsUnion, H.IsThread),
                      False, False);
                    CompleteProbe(3, ProbeStarted, orDerived,
                      ProbeKinds, Detected);
                  except
                    on E: Exception do
                    begin
                      Detected := ProbeKinds;
                      RejectProbe(3, ProbeStarted, E);
                      if NHWFatalSensorException(E) then raise;
                    end;
                  end;
                end;
              end;
            end;

            if First or WasInactive or RightsAdded then
            begin
              if H.IsThread then
              begin
                NHWNoteAccessContext(dkThread, H.PID, H.CreateTime, LivePID,
                  'THREAD_ACCESS', H.RightsUnion, InBaseline);
                if RightsAdded then NHWNoteAccessContext(dkEscalation, H.PID, H.CreateTime, LivePID,
                  'THREAD_ACCESS', H.RightsUnion, InBaseline);
                if WasInactive then NHWNoteAccessContext(dkReappearance, H.PID, H.CreateTime, LivePID,
                  'THREAD_ACCESS', H.RightsUnion, InBaseline);
                { Bootstrap rights are observations, not evidence of a
                  thread context change. Report via NHWNoteAccessContext. }
              end
              else
              begin
                NHWNoteAccessContext(dkProcess, H.PID, H.CreateTime, LivePID,
                  'PROCESS_ACCESS', H.RightsUnion, InBaseline);
                if RightsAdded then NHWNoteAccessContext(dkEscalation, H.PID, H.CreateTime, LivePID,
                  'PROCESS_ACCESS', H.RightsUnion, InBaseline);
                if WasInactive then NHWNoteAccessContext(dkReappearance, H.PID, H.CreateTime, LivePID,
                  'PROCESS_ACCESS', H.RightsUnion, InBaseline);
                { Bootstrap high-rights handles are observations, not
                  proof of an external write or thread creation. }
              end;
            end;

            // v104: a newly observed THREAD_SET_CONTEXT capability is
            // only a possible APC prerequisite, never proof of QueueUserAPC.
            APCStyle.ObserveThreadRights(H,
              First or WasInactive or
              ((NewRelevantRights and THREAD_SET_CONTEXT_RIGHT) <> 0),
              InBaseline, TickStart);

            // v86: newly observed access edges only, not every held handle.
            // Sampled snapshots cannot prove microsecond OpenProcess timing.
            if (not InBaseline) and (First or WasInactive or RightsAdded) then
            begin
              if H.IsThread then
              begin
                if (H.RightsUnion and (THREAD_SET_CONTEXT_RIGHT or
                  THREAD_SUSPEND_RESUME_RIGHT)) <> 0 then
                  AccessMicroburst.ObserveNewEdge(H.PID, H.RightsUnion,
                    TickStart, H.CreateTime);
              end
              else if (H.RightsUnion and (ACCESS_VM_READ or ACCESS_VM_WRITE or
                ACCESS_VM_OPERATION or ACCESS_CREATE_THREAD)) <> 0 then
                AccessMicroburst.ObserveNewEdge(H.PID, H.RightsUnion,
                  TickStart, H.CreateTime);
            end;

            // High-rights capability newly observed; not an actual memory write,
            // thread creation or attribution of a later self-integrity change.
            if (not InBaseline) and (First or WasInactive or RightsAdded) then
            begin
              if H.IsThread then
              begin
                if (H.RightsUnion and
                   (THREAD_SET_CONTEXT_RIGHT or THREAD_SUSPEND_RESUME_RIGHT)) <> 0 then
                  HighExternalAccess := True;
              end
              else if (H.RightsUnion and (ACCESS_VM_WRITE or
                   ACCESS_VM_OPERATION or ACCESS_CREATE_THREAD)) <> 0 then
                HighExternalAccess := True;
            end;

            if (not InBaseline) and (not H.IsThread) and
               ((H.RightsUnion and ACCESS_CREATE_THREAD) <> 0) and
               (First or WasInactive or
                ((NewRelevantRights and ACCESS_CREATE_THREAD) <> 0)) then
              FreshCreateThreadAccess := True;

            if (not InBaseline) and (H.Level >= Threshold) then
            begin
              if First then
              begin
                if H.IsThread then Include(Detected, dkThread)
                else Include(Detected, dkProcess);
              end
              else if WasInactive then
                Include(Detected, dkReappearance)
              else if RightsAdded then
                Include(Detected, dkEscalation)
              else if Opt.ReportHandleCount and CountIncreased then
              begin
                // Count changes are off by default. Preserve this optional
                // diagnostic without conflating it with rights escalation.
                if H.IsThread then Include(Detected, dkThread)
                else Include(Detected, dkProcess);
              end;
            end;

            // v25: PROCESS_VM_READ capability is separate from actual reads.
            // Observe the OLD rights from the prior track before emitting events.
            // Stabilization boundary: ReadGuard.ObserveHolder (slot 4).
            if BeginProbe(4, ProbeStarted, ProbeReset) then
            begin
              ProbeKinds := Detected;
              try
                if ProbeReset then
                begin
                  ReadGuard.Reset(LivePID);
                  AllocationGuard.ExcludedAddress := ReadGuard.CanaryAddress;
                end;
                ReadGuard.ObserveHolder(H, First, WasInactive, InBaseline,
                  PreviousRightsForRead, TickStart, Detected);
                CompleteProbe(4, ProbeStarted, orSelfMemory,
                  ProbeKinds, Detected);
              except
                on E: Exception do
                begin
                  Detected := ProbeKinds;
                  RejectProbe(4, ProbeStarted, E);
                  if NHWFatalSensorException(E) then raise;
                end;
              end;
            end;
            // Stabilization boundary: WriteGuard.ObserveHolder (slot 5).
            if BeginProbe(5, ProbeStarted, ProbeReset) then
            begin
              ProbeKinds := Detected;
              try
                if ProbeReset then
                begin
                  WriteGuard.Reset(LivePID);
                  AllocationGuard.ExcludedWriteAddress := WriteGuard.RegionAddress;
                end;
                WriteGuard.ObserveHolder(H, First, WasInactive, InBaseline,
                  PreviousRightsForRead, TickStart);
                CompleteProbe(5, ProbeStarted, orSelfMemory,
                  ProbeKinds, Detected);
              except
                on E: Exception do
                begin
                  Detected := ProbeKinds;
                  RejectProbe(5, ProbeStarted, E);
                  if NHWFatalSensorException(E) then raise;
                end;
              end;
            end;
            // Stabilization boundary: Behavior.Observe (slot 6).
            if BeginProbe(6, ProbeStarted, ProbeReset) then
            begin
              ProbeKinds := Detected;
              try
                if ProbeReset then
                begin
                  Behavior.Reset;
                end;
                Behavior.Observe(H, First, WasInactive, RightsAdded, InBaseline);
                CompleteProbe(6, ProbeStarted, orHandleSnapshot,
                  ProbeKinds, Detected);
              except
                on E: Exception do
                begin
                  Detected := ProbeKinds;
                  RejectProbe(6, ProbeStarted, E);
                  if NHWFatalSensorException(E) then raise;
                end;
              end;
            end;
            // v45 keeps per-actor capability sequence. A handle is not proof
            // of a memory operation, and PID reuse is separated by create time.
            // Stabilization boundary: TemporalGraph.Observe (slot 7).
            if BeginProbe(7, ProbeStarted, ProbeReset) then
            begin
              ProbeKinds := Detected;
              try
                if ProbeReset then
                begin
                  TemporalGraph.Reset;
                end;
                TemporalGraph.Observe(H, InBaseline, TickStart, Detected);
                CompleteProbe(7, ProbeStarted, orHandleSnapshot,
                  ProbeKinds, Detected);
              except
                on E: Exception do
                begin
                  Detected := ProbeKinds;
                  RejectProbe(7, ProbeStarted, E);
                  if NHWFatalSensorException(E) then raise;
                end;
              end;
            end;

            // Multi-owner is meaningful only for high-impact holders.
            // Query/read-only and ordinary control handles are common during
            // long idle runs and must not create Ownership Detect by themselves.
            if H.Level >= 3 then
            begin
              ObjKey := ObjectKey(H);
              if not ObjectOwners.TryGetValue(ObjKey, OwnerList) then
              begin
                OwnerList := TList<Cardinal>.Create;
                ObjectOwners.Add(ObjKey, OwnerList);
              end;
              ObjPidKey := ObjKey + '#' + IntToStr(H.PID);
              if not ObjectOwnerSeen.ContainsKey(ObjPidKey) then
              begin
                ObjectOwnerSeen.AddOrSetValue(ObjPidKey, 1);
                OwnerList.Add(H.PID);
              end;
            end;
          end;

          // v101: snapshot-based cross-owner handle appearance patterns.
          // No DuplicateHandle API calls are intercepted or inferred as fact.
          // Stabilization boundary: HandleSharing.Examine (slot 8).
          if BeginProbe(8, ProbeStarted, ProbeReset) then
          begin
            ProbeKinds := Detected;
            try
              if ProbeReset then
              begin
                HandleSharing.Reset;
              end;
              HandleSharing.Examine(ObservedHandles, AllowedCreated,
                ThreadSnapshotValid, ProcessBaselineRemaining > 0,
                ThreadBaselineRemaining > 0, TickStart, Detected);
              CompleteProbe(8, ProbeStarted, orHandleSnapshot,
                ProbeKinds, Detected);
            except
              on E: Exception do
              begin
                Detected := ProbeKinds;
                RejectProbe(8, ProbeStarted, E);
                if NHWFatalSensorException(E) then raise;
              end;
            end;
          end;
          TemporalGraph.Expire(TickStart);
          // Ownership = 2+ distinct external PIDs with handles to the same
          // target process/thread object. This is NOT proof of duplication/hijack.
          for ObjKey in ObjectOwners.Keys do
          begin
            OwnerList := ObjectOwners[ObjKey];
            if not ObjectStates.TryGetValue(ObjKey, ObjectState) then
              ObjectState := Default(TObjectState);

            ValidObjectType := True;
            if Copy(ObjKey, 1, 3) = 'OT:' then
              ValidObjectType := ThreadSnapshotValid;
            NeedObjectNotify := ValidObjectType and (OwnerList.Count > 1) and
              ((not ObjectState.MultiOwnerActive) or
               (OwnerList.Count > ObjectState.LastOwnerCount));
            if (Copy(ObjKey, 1, 3) = 'OT:') and
               (ThreadBaselineRemaining > 0) then
              NeedObjectNotify := False;
            if (Copy(ObjKey, 1, 3) <> 'OT:') and
               (ProcessBaselineRemaining > 0) then
              NeedObjectNotify := False;

            ObjectState.LastOwnerCount := OwnerList.Count;
            ObjectState.MultiOwnerActive := OwnerList.Count > 1;
            ObjectState.LastSeenTick := TickStart;
            ObjectStates.AddOrSetValue(ObjKey, ObjectState);
            if NeedObjectNotify then
            begin
              Include(Detected, dkOwnership);
              for Pair in Holders do
              begin
                H := Pair.Value;
                if (H.Level<3) or (ObjectKey(H)<>ObjKey) then Continue;
                if OwnerCache.TryGetValue(H.PID,Cached) then H.CreateTime:=Cached.CreateTime;
                if H.IsThread then
                  NHWNoteAccessContext(dkOwnership,H.PID,H.CreateTime,LivePID,
                    'THREAD_ACCESS',H.RightsUnion,False)
                else
                  NHWNoteAccessContext(dkOwnership,H.PID,H.CreateTime,LivePID,
                    'PROCESS_ACCESS',H.RightsUnion,False);
              end;
            end;
          end;

          // Reset missing-object ownership state only when the corresponding
          // snapshot is valid. Otherwise a transient NT failure looks like a
          // genuine ownership disappearance and triggers false reappearance.
          Keys.Clear;
          for ObjKey in ObjectStates.Keys do Keys.Add(ObjKey);
          for I := 0 to Keys.Count - 1 do
          begin
            ObjKey := Keys[I];
            if ObjectOwners.ContainsKey(ObjKey) then Continue;
            if (Copy(ObjKey, 1, 3) = 'OT:') and
               not ThreadSnapshotValid then Continue;
            if not ObjectStates.TryGetValue(ObjKey, ObjectState) then Continue;
            if (TickStart >= ObjectState.LastSeenTick) and
               (TickStart - ObjectState.LastSeenTick > TRACK_RETENTION_MS) then
              ObjectStates.Remove(ObjKey)
            else
            begin
              ObjectState.LastOwnerCount := 0;
              ObjectState.MultiOwnerActive := False;
              ObjectStates.AddOrSetValue(ObjKey, ObjectState);
            end;
          end;

          Unified.Add(orHandleSnapshot, Detected);
          RapidAccess := AccessMicroburst.Correlated(TickStart);
          ReadGuard.EndSnapshot;
          // Stabilization boundary: Behavior.EndSnapshot (slot 6).
          if BeginProbe(6, ProbeStarted, ProbeReset) then
          begin
            ProbeKinds := Detected;
            try
              if ProbeReset then
              begin
                Behavior.Reset;
              end;
              Behavior.EndSnapshot(Detected);
              CompleteProbe(6, ProbeStarted, orHandleSnapshot,
                ProbeKinds, Detected);
            except
              on E: Exception do
              begin
                Detected := ProbeKinds;
                RejectProbe(6, ProbeStarted, E);
                if NHWFatalSensorException(E) then raise;
              end;
            end;
          end;
        end;
        // Do not treat a new thread as a hostile action unless there is a
        // recently newly OBSERVED external handle activity signal.
        ExternalEvent := (Detected * [dkProcess, dkThread, dkOwnership,
          dkEscalation, dkReappearance, dkThreadBurst, dkHandleChurn,
          dkCrossAccess, dkAccessBurst]) <> [];
        if NativeThreadValid then
          // Stabilization boundary: Lifecycle.ExamineThreads (slot 9).
          if BeginProbe(9, ProbeStarted, ProbeReset) then
          begin
            ProbeKinds := Detected;
            try
              if ProbeReset then
              begin
                Lifecycle.Reset;
              end;
              Lifecycle.ExamineThreads(NativeThreads, TickStart,
                ProcessBaselineRemaining > 0, ExternalEvent, Detected);
              CompleteProbe(9, ProbeStarted, orThreadSnapshot,
                ProbeKinds, Detected);
            except
              on E: Exception do
              begin
                Detected := ProbeKinds;
                RejectProbe(9, ProbeStarted, E);
                if NHWFatalSensorException(E) then raise;
              end;
            end;
          end;
        if NativeThreadValid and HandleSnapshotValid then
          // Stabilization boundary: Lifecycle.ExamineInheritance (slot 9).
          if BeginProbe(9, ProbeStarted, ProbeReset) then
          begin
            ProbeKinds := Detected;
            try
              if ProbeReset then
              begin
                Lifecycle.Reset;
              end;
              Lifecycle.ExamineInheritance(ObservedHandles, ParentMap,
                OwnerCreated, ProcessBaselineRemaining > 0,
                ThreadBaselineRemaining > 0, Detected);
              CompleteProbe(9, ProbeStarted, orThreadSnapshot,
                ProbeKinds, Detected);
            except
              on E: Exception do
              begin
                Detected := ProbeKinds;
                RejectProbe(9, ProbeStarted, E);
                if NHWFatalSensorException(E) then raise;
              end;
            end;
          end;
        InspectSecurityAndConfiguration;
        CollectAndFuseKernelEvents;
        InspectThreadAndMemoryState;
        InspectSystemAndSelfState;
        InspectCodeAndInitialCorrelations;
        InspectImageAndForensicState;
        InspectTemporalReconstruction;
        EvaluateRiskAndConsensus;
        RecordCycleEvidence;
        if StopRequested then Break;
        if HandleSnapshotValid then
        begin
          Keys.Clear;
          for TrackPair in Tracks do Keys.Add(TrackPair.Key);
          for I := 0 to Keys.Count - 1 do
          begin
            Key := Keys[I];
            if not Tracks.TryGetValue(Key, T) then Continue;
            if T.IsThread and not ThreadSnapshotValid then Continue;
            if not Seen.ContainsKey(Key) and T.Active then
            begin
              Inc(T.MissingScans);
              if T.MissingScans >= Opt.MissThreshold then T.Active := False;
              Tracks.AddOrSetValue(Key, T);
            end
            else if (not T.Active) and (T.LastSeenTick <> 0) and
                    (TickStart - T.LastSeenTick > TRACK_RETENTION_MS) then
              Tracks.Remove(Key);
          end;

          if ProcessBaselineRemaining > 0 then Dec(ProcessBaselineRemaining);
        end;
        if LocalBaselineRemaining > 0 then Dec(LocalBaselineRemaining);
        if ThreadSnapshotValid and (ThreadBaselineRemaining > 0) then
          Dec(ThreadBaselineRemaining);

        FinalizeSamplingAndReport;
        if not Opt.Watch then Break;
        Elapsed := WinTick64 - TickStart;
        if Elapsed < Opt.IntervalMS then
          SleepUntilDueOrEvent(Opt.IntervalMS - Cardinal(Elapsed),
            KernelTrace.WakeHandle, TickStart, RealtimeWake, nil, Cancelled);
    until False;
  finally
    ReleaseSessionComponents;
  end;
end;

end.
