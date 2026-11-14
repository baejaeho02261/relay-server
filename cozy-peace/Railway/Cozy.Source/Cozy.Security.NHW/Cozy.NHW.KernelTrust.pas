unit Cozy.NHW.KernelTrust;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  Cozy.NHW.Logging,
  Cozy.NHW.BootTrust,
  Cozy.NHW.VBSHVCI,
  Cozy.NHW.VulnerableDriver,
  Cozy.NHW.DriverIdentity,
  Cozy.NHW.DriverCrossView,
  Cozy.NHW.KernelTrustDowngrade,
  Cozy.NHW.CodeIntegrityPolicy,
  Cozy.NHW.DriverTimeline,
  Cozy.NHW.SystemViewDisagreement,
  Cozy.NHW.KernelMappingEvidence,
  Cozy.NHW.BootAttestationContinuity,
  Cozy.NHW.CodeIntegrityEventCorrelation,
  Cozy.NHW.KernelTelemetryGap,
  Cozy.NHW.SessionTrustLadder,
  Cozy.NHW.ResponsePathMesh,
  Cozy.NHW.KernelTrust.PlatformNative,
  Cozy.NHW.DriverLoadProvenance,
  Cozy.NHW.DriverSignerAttestation,
  Cozy.NHW.DriverServiceTimeline,
  Cozy.NHW.HypervisorVBSCrossView,
  Cozy.NHW.KernelDMAIOMMUTrust,
  Cozy.NHW.ServerNonceAttestation,
  Cozy.NHW.SessionEpochGuard,
  Cozy.NHW.SessionInvalidation,
  Cozy.NHW.ResponsePath.Dispatch,
  Cozy.NHW.ResponseSink.Local,
  Cozy.NHW.KernelTrust.CorrelationPolicy,
  Cozy.NHW.Attestation.Transport,
  Cozy.NHW.KernelTrust.Native;

type
  TKernelTrustMonitor = class
  private
    FBoot: TBootTrustMonitor;
    FVBS: TVBSHVCIMonitor;
    FVulnerable: TVulnerableDriverMonitor;
    FIdentity: TDriverIdentityMonitor;
    FCrossView: TDriverCrossViewMonitor;
    FTrustDowngrade: TKernelTrustDowngradeMonitor;
    FPolicy: TCodeIntegrityPolicyMonitor;
    FTimeline: TDriverLoadTimelineMonitor;
    FDisagreement: TSystemViewDisagreementMonitor;
    FMapping: TKernelMappingEvidenceMonitor;
    FBootAttestation: TBootAttestationContinuityMonitor;
    FCIEvent: TCodeIntegrityEventCorrelationMonitor;
    FTelemetry: TKernelTelemetryGapMonitor;
    FSession: TSessionTrustLadderMonitor;
    FResponse: TResponsePathMesh;
    FLocalResponse: TLocalResponseSinkSet;
    FLastCorrelation: TKernelCorrelationSummary;
    FLastObservationKinds: TDetectionKinds;
    FProvenance: TDriverLoadProvenanceMonitor;
    FSigner: TDriverSignerAttestationMonitor;
    FServiceTimeline: TDriverServiceTimelineMonitor;
    FHyperVBS: THypervisorVBSCrossViewMonitor;
    FDMAIOMMU: TKernelDMAIOMMUTrustMonitor;
    FAttestation: TServerNonceAttestation;
    FInvalidation: TSessionInvalidationLatch;
    FLastTrustScan: UInt64;
    FLastDriverScan: UInt64;
    FLastPolicyScan: UInt64;
    FLastPlatformScan: UInt64;
    FLastTrustDowngradeEvidence: UInt64;
    FLastKernelMappingEvidence: UInt64;
    FLastBoot: TSecureBootSnapshot;
    FLastCI: TCodeIntegritySnapshot;
    FHaveBoot: Boolean;
    FHaveCI: Boolean;
    FLastBootCaptureValid: Boolean;
    FLastCICaptureValid: Boolean;
    FLastNativeModulesValid: Boolean;
    FLastPSAPIValid: Boolean;
    FLastPlatform: TPlatformSecuritySnapshot;
    FHavePlatform: Boolean;
    FLastBootIdentity: TBootIdentity;
    FHaveBootIdentity, FLastBootIdentityValid: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Tick: UInt64; var Detected: TDetectionKinds);
    function ResponseVoteMask(Tick: UInt64): Byte;
    function ResponseQuorum(Tick: UInt64): Boolean;
    function TrustResponseDigest: UInt64;
    function DriverResponseDigest: UInt64;
    function IntegrityResponseDigest: UInt64;
    function SessionTrust: TKernelSessionTrust;
    function BeginServerChallenge(Epoch: UInt64; const Nonce: TAttestationNonce;
      Tick: UInt64): Boolean;
    function BeginServerChallengeFrame(const Frame: TBytes;
      Tick: UInt64): Boolean;
    function BuildServerAttestation(Tick: UInt64;
      out Evidence: TServerAttestationEvidence; out MeasuredBootLog: TBytes): Boolean;
    function BuildServerAttestationFrame(Tick: UInt64;
      out Frame: TBytes): Boolean;
    procedure ApplyServerAttestationVerdict(Epoch: UInt64; Accepted: Boolean;
      Tick: UInt64);
    function ApplyServerVerdictFrame(const Frame: TBytes;
      Tick: UInt64): Boolean;
    procedure ConfigureResponseSinks(TrustSink, DriverSink,
      IntegritySink: TResponsePathSink);
    function SessionInvalidated: Boolean;
    property ObservationKinds: TDetectionKinds read FLastObservationKinds;
    function AttestationEpoch: UInt64;
    function CorrelationScore: Word;
    function CorrelationFamilyCount: Byte;
    function LocalResponseQuorum(Tick: UInt64): Boolean;
    function ReadBootIdentity(out Identity: TBootIdentity): Boolean;
    procedure ReadLocalReceipts(out Trust, Driver, Integrity: TResponsePathEvent);
  end;

implementation

const
  TRUST_SCAN_MS = 5000;
  DRIVER_SCAN_MS = 10000;
  POLICY_SCAN_MS = 30000;
  PLATFORM_SCAN_MS = 30000;
  TRUST_EVIDENCE_MS = 60000;

constructor TKernelTrustMonitor.Create;
begin
  inherited Create;
  FBoot := TBootTrustMonitor.Create;
  FVBS := TVBSHVCIMonitor.Create;
  FVulnerable := TVulnerableDriverMonitor.Create;
  FIdentity := TDriverIdentityMonitor.Create;
  FCrossView := TDriverCrossViewMonitor.Create;
  FTrustDowngrade := TKernelTrustDowngradeMonitor.Create;
  FPolicy := TCodeIntegrityPolicyMonitor.Create;
  FTimeline := TDriverLoadTimelineMonitor.Create;
  FDisagreement := TSystemViewDisagreementMonitor.Create;
  FMapping := TKernelMappingEvidenceMonitor.Create;
  FBootAttestation := TBootAttestationContinuityMonitor.Create;
  FCIEvent := TCodeIntegrityEventCorrelationMonitor.Create;
  FTelemetry := TKernelTelemetryGapMonitor.Create;
  FSession := TSessionTrustLadderMonitor.Create;
  FResponse := TResponsePathMesh.Create;
  FLocalResponse := TLocalResponseSinkSet.Create;
  FResponse.SetLocalSinks(FLocalResponse.TrustReceive,
    FLocalResponse.DriverReceive, FLocalResponse.IntegrityReceive);
  FProvenance := TDriverLoadProvenanceMonitor.Create;
  FSigner := TDriverSignerAttestationMonitor.Create;
  FServiceTimeline := TDriverServiceTimelineMonitor.Create;
  FHyperVBS := THypervisorVBSCrossViewMonitor.Create;
  FDMAIOMMU := TKernelDMAIOMMUTrustMonitor.Create;
  FAttestation := TServerNonceAttestation.Create;
  FInvalidation := TSessionInvalidationLatch.Create;
  Reset;
end;

destructor TKernelTrustMonitor.Destroy;
begin
  FInvalidation.Free;
  FAttestation.Free;
  FDMAIOMMU.Free;
  FHyperVBS.Free;
  FServiceTimeline.Free;
  FSigner.Free;
  FProvenance.Free;
  FResponse.Free;
  FLocalResponse.Free;
  FSession.Free;
  FTelemetry.Free;
  FCIEvent.Free;
  FBootAttestation.Free;
  FMapping.Free;
  FDisagreement.Free;
  FTimeline.Free;
  FPolicy.Free;
  FTrustDowngrade.Free;
  FCrossView.Free;
  FIdentity.Free;
  FVulnerable.Free;
  FVBS.Free;
  FBoot.Free;
  inherited Destroy;
end;

procedure TKernelTrustMonitor.Reset;
begin
  FLastTrustScan := 0;
  FLastDriverScan := 0;
  FLastPolicyScan := 0;
  FLastPlatformScan := 0;
  FLastTrustDowngradeEvidence := 0;
  FLastKernelMappingEvidence := 0;
  FLastBoot := Default(TSecureBootSnapshot);
  FLastCI := Default(TCodeIntegritySnapshot);
  FHaveBoot := False;
  FHaveCI := False;
  FLastBootCaptureValid := False;
  FLastCICaptureValid := False;
  FLastNativeModulesValid := False;
  FLastPSAPIValid := False;
  FLastPlatform := Default(TPlatformSecuritySnapshot);
  FHavePlatform := False;
  FLastBootIdentity := Default(TBootIdentity);
  FHaveBootIdentity := False;
  FLastBootIdentityValid := False;
  FBoot.Reset;
  FVBS.Reset;
  FIdentity.Reset;
  FCrossView.Reset;
  FVulnerable.Reset;
  FTrustDowngrade.Reset;
  FPolicy.Reset;
  FTimeline.Reset;
  FDisagreement.Reset;
  FMapping.Reset;
  FBootAttestation.Reset;
  FCIEvent.Reset;
  FTelemetry.Reset;
  FSession.Reset;
  FResponse.Reset;
  FLocalResponse.Reset;
  FLastCorrelation := Default(TKernelCorrelationSummary);
  FLastObservationKinds := [];
  FProvenance.Reset;
  FSigner.Reset;
  FServiceTimeline.Reset;
  FHyperVBS.Reset;
  FDMAIOMMU.Reset;
  FAttestation.Reset;
  FInvalidation.Reset;
end;

function SameResponseReceipt(const Producer, Local: TResponsePathEvent): Boolean;
begin
  Result := (Producer.Channel = Local.Channel) and
    (Producer.Sequence = Local.Sequence) and (Producer.Tick = Local.Tick) and
    (Producer.Digest = Local.Digest);
end;

function TKernelTrustMonitor.ResponseVoteMask(Tick: UInt64): Byte;
var
  Trust, Driver, Integrity: TResponsePathEvent;
  LocalTrust, LocalDriver, LocalIntegrity: TResponsePathEvent;
begin
  Result := FResponse.VoteMask(Tick) and FLocalResponse.VoteMask(Tick);
  FResponse.ReadProducerReceipts(Trust, Driver, Integrity);
  FLocalResponse.ReadReceipts(LocalTrust, LocalDriver, LocalIntegrity);
  if not SameResponseReceipt(Trust, LocalTrust) then
    Result := Result and not RESPONSE_VOTE_TRUST;
  if not SameResponseReceipt(Driver, LocalDriver) then
    Result := Result and not RESPONSE_VOTE_DRIVER;
  if not SameResponseReceipt(Integrity, LocalIntegrity) then
    Result := Result and not RESPONSE_VOTE_INTEGRITY;
end;

function TKernelTrustMonitor.ResponseQuorum(Tick: UInt64): Boolean;
begin
  Result := ResponsePathQuorum(ResponseVoteMask(Tick));
end;

function TKernelTrustMonitor.TrustResponseDigest: UInt64;
begin
  Result := FResponse.TrustDigest;
end;

function TKernelTrustMonitor.DriverResponseDigest: UInt64;
begin
  Result := FResponse.DriverDigest;
end;

function TKernelTrustMonitor.IntegrityResponseDigest: UInt64;
begin
  Result := FResponse.IntegrityDigest;
end;

function TKernelTrustMonitor.SessionTrust: TKernelSessionTrust;
begin
  Result := FSession.State;
end;

function TKernelTrustMonitor.BeginServerChallenge(Epoch: UInt64;
  const Nonce: TAttestationNonce; Tick: UInt64): Boolean;
begin
  Result := FAttestation.BeginChallenge(Epoch, Nonce, Tick);
  if Result then FInvalidation.BeginEpoch(FAttestation.CurrentEpoch);
end;

function TKernelTrustMonitor.BeginServerChallengeFrame(const Frame: TBytes;
  Tick: UInt64): Boolean;
var
  Challenge: TAttestationChallengeFrame;
begin
  Result := False;
  if not ParseAttestationChallengeFrame(Frame, Challenge) then Exit;
  Result := FAttestation.BeginChallengeEx(Challenge.Epoch,
    Challenge.ServerSequence, Challenge.Nonce, Tick);
  if Result then FInvalidation.BeginEpoch(FAttestation.CurrentEpoch);
end;

function TKernelTrustMonitor.BuildServerAttestation(Tick: UInt64;
  out Evidence: TServerAttestationEvidence;
  out MeasuredBootLog: TBytes): Boolean;
begin
  Result := FAttestation.BuildEvidence(FLastBootIdentity, FHaveBootIdentity,
    FSession.State, ResponseVoteMask(Tick), FResponse.TrustDigest,
    FResponse.DriverDigest, FResponse.IntegrityDigest, Tick, Evidence,
    MeasuredBootLog);
end;

function TKernelTrustMonitor.BuildServerAttestationFrame(Tick: UInt64;
  out Frame: TBytes): Boolean;
var
  Evidence: TServerAttestationEvidence;
  MeasuredBootLog: TBytes;
begin
  Frame := nil;
  Result := BuildServerAttestation(Tick, Evidence, MeasuredBootLog);
  if Result then
    Result := BuildAttestationEvidenceFrame(Evidence, MeasuredBootLog, Frame);
end;

procedure TKernelTrustMonitor.ApplyServerAttestationVerdict(Epoch: UInt64;
  Accepted: Boolean; Tick: UInt64);
begin
  // A legacy verdict has no server sequence, nonce or binding digest and is
  // therefore not accepted as a security decision. Use ApplyServerVerdictFrame.
end;

function TKernelTrustMonitor.ApplyServerVerdictFrame(const Frame: TBytes;
  Tick: UInt64): Boolean;
var
  Verdict: TAttestationVerdictFrame;
begin
  Result := False;
  if not ParseAttestationVerdictFrame(Frame, Verdict) then Exit;
  if not FAttestation.ApplyVerdictEx(Verdict.Epoch, Verdict.ServerSequence,
      Verdict.Nonce, Verdict.BindingDigest, Verdict.Accepted, Tick) then Exit;
  FInvalidation.ApplyServerVerdict(Verdict.Epoch, Verdict.Accepted, Tick);
  Result := True;
end;

procedure TKernelTrustMonitor.ConfigureResponseSinks(TrustSink, DriverSink,
  IntegritySink: TResponsePathSink);
begin
  FResponse.SetSinks(TrustSink, DriverSink, IntegritySink);
end;

function TKernelTrustMonitor.SessionInvalidated: Boolean;
begin
  Result := FInvalidation.Invalidated;
end;

function TKernelTrustMonitor.AttestationEpoch: UInt64;
begin
  Result := FAttestation.CurrentEpoch;
end;

function TKernelTrustMonitor.CorrelationScore: Word;
begin
  Result := FLastCorrelation.Score;
end;

function TKernelTrustMonitor.CorrelationFamilyCount: Byte;
begin
  Result := FLastCorrelation.IndependentFamilies;
end;

function TKernelTrustMonitor.LocalResponseQuorum(Tick: UInt64): Boolean;
begin
  Result := FLocalResponse.Quorum(Tick);
end;

function TKernelTrustMonitor.ReadBootIdentity(out Identity: TBootIdentity): Boolean;
begin
  Result := FHaveBootIdentity and FLastBootIdentityValid;
  Identity := Default(TBootIdentity);
  if Result then Identity := FLastBootIdentity;
end;

procedure TKernelTrustMonitor.ReadLocalReceipts(out Trust, Driver,
  Integrity: TResponsePathEvent);
begin
  FLocalResponse.ReadReceipts(Trust, Driver, Integrity);
end;

procedure TKernelTrustMonitor.Examine(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Boot: TSecureBootSnapshot;
  CI: TCodeIntegritySnapshot;
  Policy: TCodeIntegrityPolicySnapshot;
  Modules, PSAPIModules: TKernelModuleInfos;
  Services: TDriverServiceInfos;
  PSAPI: TKernelBaseList;
  NativeValid, PSAPIValid, ServicesValid: Boolean;
  RuntimeDowngradeRecent, MappingRecent, KernelCorroborated: Boolean;
  PlatformFresh: Boolean;
  BootIdentity: TBootIdentity;
  BootIdentityValid: Boolean;
  CurrentKinds: TDetectionKinds;
begin
  PlatformFresh := False;
  if ((FLastTrustScan <> 0) and (Tick < FLastTrustScan)) or
     ((FLastDriverScan <> 0) and (Tick < FLastDriverScan)) or
     ((FLastPolicyScan <> 0) and (Tick < FLastPolicyScan)) or
     ((FLastPlatformScan <> 0) and (Tick < FLastPlatformScan)) then
    Reset;

  if (FLastTrustScan = 0) or (Tick - FLastTrustScan >= TRUST_SCAN_MS) then
  begin
    FLastTrustScan := Tick;
    FLastBootCaptureValid := CaptureSecureBootSnapshot(Boot);
    if FLastBootCaptureValid then
    begin
      FLastBoot := Boot;
      FHaveBoot := True;
      FBoot.Examine(Boot, Tick, Detected);
    end;
    FLastCICaptureValid := CaptureCodeIntegritySnapshot(CI);
    if FLastCICaptureValid then
    begin
      FLastCI := CI;
      FHaveCI := True;
      FVBS.Examine(CI, Tick, Detected);
      FTrustDowngrade.Examine(CI, Tick, Detected);
      if dkKernelTrustDowngrade in Detected then
        FLastTrustDowngradeEvidence := Tick;
    end;
    BootIdentityValid := CaptureBootIdentity(BootIdentity);
    FLastBootIdentityValid := BootIdentityValid;
    if BootIdentityValid then
    begin
      FLastBootIdentity := BootIdentity;
      FHaveBootIdentity := True;
    end;
    FBootAttestation.Examine(BootIdentityValid, BootIdentity, Tick, Detected);
  end;

  if (FLastPolicyScan = 0) or (Tick - FLastPolicyScan >= POLICY_SCAN_MS) then
  begin
    FLastPolicyScan := Tick;
    RuntimeDowngradeRecent := (FLastTrustDowngradeEvidence <> 0) and
      (Tick >= FLastTrustDowngradeEvidence) and
      (Tick - FLastTrustDowngradeEvidence <= TRUST_EVIDENCE_MS);
    if CaptureCodeIntegrityPolicySnapshot(Policy) then
      FPolicy.Examine(Policy, RuntimeDowngradeRecent, Tick, Detected);
  end;

  if (FLastPlatformScan = 0) or (Tick - FLastPlatformScan >= PLATFORM_SCAN_MS) then
  begin
    FLastPlatformScan := Tick;
    if CapturePlatformSecuritySnapshot(FLastPlatform) then
    begin
      FHavePlatform := True;
      PlatformFresh := True;
    end;
  end;

  if (FLastDriverScan = 0) or (Tick - FLastDriverScan >= DRIVER_SCAN_MS) then
  begin
    FLastDriverScan := Tick;
    NativeValid := CaptureNativeKernelModules(Modules);
    PSAPIValid := CapturePSAPIKernelModules(PSAPIModules);
    ServicesValid := CaptureDriverServices(Services);
    FLastNativeModulesValid := NativeValid;
    FLastPSAPIValid := PSAPIValid;
    if PSAPIValid then KernelModulesToBases(PSAPIModules, PSAPI)
    else PSAPI := nil;

    FVulnerable.Examine(Modules, NativeValid, Tick, Detected);
    FIdentity.Examine(Modules, PSAPIModules, NativeValid, PSAPIValid,
      Tick, Detected);
    FCrossView.Examine(Modules, NativeValid, PSAPI, PSAPIValid, Tick, Detected);
    FTimeline.Examine(Modules, NativeValid,
      FVulnerable.LastConfirmedModuleKey,
      FVulnerable.LastConfirmedTick, Tick, Detected);

    if FHaveBoot and FHaveCI then
      FDisagreement.Examine(FLastBoot, FLastCI, Modules, PSAPIModules,
        NativeValid, PSAPIValid, Tick, Detected);

    MappingRecent := (FLastKernelMappingEvidence <> 0) and
      (Tick >= FLastKernelMappingEvidence) and
      (Tick - FLastKernelMappingEvidence <= TRUST_EVIDENCE_MS);
    RuntimeDowngradeRecent := (FLastTrustDowngradeEvidence <> 0) and
      (Tick >= FLastTrustDowngradeEvidence) and
      (Tick - FLastTrustDowngradeEvidence <= TRUST_EVIDENCE_MS);
    KernelCorroborated := MappingRecent or RuntimeDowngradeRecent or
      (dkVulnerableDriver in Detected) or
      (dkDriverCrossView in Detected) or
      (dkSystemViewDisagreement in Detected);
    FProvenance.Examine(Modules, NativeValid, Services, ServicesValid,
      KernelCorroborated, Tick, Detected);
    FSigner.Examine(Modules, NativeValid, KernelCorroborated, Tick, Detected);
    // A transient driver service is only high-risk when tied to the two
    // strongest mapper-related signals: an exact vulnerable-driver finding or
    // an already-confirmed kernel-mapping correlation. Generic cross-view
    // disagreement is intentionally insufficient to avoid normal driver churn.
    FServiceTimeline.Examine(Services, ServicesValid, Modules, NativeValid,
      MappingRecent or
      ((FVulnerable.LastConfirmedTick <> 0) and
       (Tick >= FVulnerable.LastConfirmedTick) and
       (Tick - FVulnerable.LastConfirmedTick <= TRUST_EVIDENCE_MS)),
      Tick, Detected);
  end;

  CurrentKinds := Detected;
  FCIEvent.Examine(CurrentKinds, Tick, Detected);

  FTelemetry.Examine(FLastNativeModulesValid, FLastPSAPIValid,
    FLastBootCaptureValid, FLastCICaptureValid, FCIEvent.LastCaptureValid,
    Tick, Detected);

  // Correlation only. A normal kernel driver load by itself is not evidence.
  FMapping.Observe(Detected, Tick, Detected);
  if dkKernelMappingEvidence in Detected then
    FLastKernelMappingEvidence := Tick;

  if PlatformFresh and FHavePlatform and FHaveCI then
  begin
    FHyperVBS.Examine(FLastPlatform, FLastCI, Tick, Detected);
    RuntimeDowngradeRecent := (FLastTrustDowngradeEvidence <> 0) and
      (Tick >= FLastTrustDowngradeEvidence) and
      (Tick - FLastTrustDowngradeEvidence <= TRUST_EVIDENCE_MS);
    MappingRecent := (FLastKernelMappingEvidence <> 0) and
      (Tick >= FLastKernelMappingEvidence) and
      (Tick - FLastKernelMappingEvidence <= TRUST_EVIDENCE_MS);
    KernelCorroborated := RuntimeDowngradeRecent or MappingRecent or
      (dkKernelTrustDowngrade in Detected) or
      (dkKernelMappingEvidence in Detected) or
      (dkSystemViewDisagreement in Detected) or
      (dkCodeIntegrityEventCorrelation in Detected);
    FDMAIOMMU.Examine(FLastPlatform, KernelCorroborated, Tick, Detected);
  end;

  FSession.Observe(Detected, Tick, Detected);
  FLastObservationKinds := Detected;
  FResponse.Observe(Detected, Tick);
  FLastCorrelation := EvaluateKernelCorrelation(Detected, FSession.State,
    ResponseQuorum(Tick));
  FInvalidation.ObserveLocalCorrelated(FSession.State, ResponseQuorum(Tick),
    FLastCorrelation.CanInvalidate, Tick);
  FLastObservationKinds := Detected;
end;

end.
