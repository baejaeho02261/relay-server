unit Cozy.NHW.Logging;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

type
  TDetectionKind = (dkProcess, dkThread, dkOwnership, dkEscalation,
    dkReappearance, dkThreadBurst, dkHandleChurn, dkCrossAccess, dkAccessBurst,
    dkThreadCreation, dkThreadExit, dkThreadState, dkHandleInherit, dkLifecycle,
    dkTokenObject, dkTokenRights, dkTokenChange, dkDacl, dkThreadToken,
    dkEvent, dkMutex, dkSemaphore, dkSection, dkIPC, dkJob,
    dkFileSwap, dkFileRename, dkReparse, dkStream, dkFileSecurity, dkFileLink,
    dkRegistryValue, dkRegistryKey, dkRegistrySecurity, dkPolicy, dkRegistryBurst,
    dkThreadPriority, dkProcessPriority, dkAffinity, dkCPUGroup,
    dkScheduling, dkMitigation,
    dkNamespace, dkObjectType, dkSymbolicLink, dkDeviceMap,
    dkObjectSecurity, dkNamespaceBurst,
    dkTransientThread, dkProcessLifetime, dkKernelFileIO,
    dkKernelRegistry, dkEventFusion, dkTraceGap,
    dkThreadStart, dkPrivateThread, dkRemoteThread, dkThreadRegion, dkThreadSpawn,
    dkStackBounds, dkStackGuard, dkStackExecute, dkStackAllocation,
    dkStackGrowth, dkStackCorrelation,
    dkAllocation, dkCommit, dkExecuteProtect, dkRWX, dkMemoryRelease,
    dkAllocationBurst,
    dkMappedView, dkCOW, dkPageSharing, dkMappingBacking,
    dkExecutableMapping, dkMappingBurst,
    dkProtectTransition, dkProtectionCycle, dkImageProtection,
    dkGuardTransition, dkNoAccess, dkProtectBurst,
    dkReadAccess, dkCanaryAccess, dkReadCorrelation, dkReadPattern, dkReadGap,
    dkWriteWatch, dkWriteBurst, dkRepeatedWrite, dkWriteCorrelation,
    dkWriteIntegrity,
    dkDeadlock, dkThreadWait, dkExternalWait, dkCriticalSection,
    dkContention, dkWaitBurst,
    dkCaptureClient, dkCaptureLibrary, dkCaptureDriver,
    dkCaptureProxy, dkCaptureCorrelation,
    dkNetworkFilter, dkWFPCallout, dkWFPProvider, dkRouteChange,
    dkProxyChange, dkNetworkCorrelation,
    dkDNSServer, dkDNSPolicy, dkWinsockProvider, dkInterfaceChange,
    dkPathCorrelation, dkNetworkIntegrity,
    dkIAT, dkFunctionPointer, dkCallback, dkProcessParameter,
    dkThreadProvenance, dkBoundary,
    dkTLSPointer, dkFLSCallback, dkHeapState, dkHeapIntegrity,
    dkHeapCorrelation,
    dkUnwind, dkFunctionTable, dkExceptionRange,
    dkExceptionCallback, dkExceptionCorrelation,
    dkCompletionPort, dkCompletionKey, dkAsyncCallback,
    dkThreadpool, dkAsyncBurst, dkAsyncCorrelation,
    dkPEHeader, dkSectionMapping, dkRelocation, dkTLSDirectory,
    dkLoadConfig, dkDirectoryBounds,
    dkExportTable, dkExportForwarder, dkAPISet, dkDelayImport,
    dkExportTarget, dkResolution,
    dkMultiSignal, dkPECodeIntegrity, dkPrivateExecRegion,
    dkETWImageFusion, dkInjectionEvidence,
    dkExecutionProvenance, dkImageCOWIntegrity, dkTemporalHandleGraph,
    dkModuleOrigin, dkETWLoss,
    dkImportRedirect, dkTLSCallbackIntegrity, dkUnwindStructural,
    dkExecutableLifecycle, dkSectionBacking, dkThreadStackOrigin,
    dkCoverageGap,
    dkProcessSnapshot, dkLoaderCrossView, dkFileAttestation,
    dkControlFlow, dkSnapshotETW, dkObserverMismatch,
    dkEvidenceIntegrity, dkRiskConfidence,
    dkCausalSequence, dkCodeProvenance, dkSectionCorrelation,
    dkIndirectTarget, dkThreadTimeline, dkObservationUncertain,
    dkSensorPressure, dkIncidentReconstruction,
    dkHandleSharingEvidence, dkAPCStyleEvidence,
    dkBootTrust, dkVBSHVCI, dkVulnerableDriver, dkDriverIdentity,
    dkDriverCrossView, dkKernelTrustDowngrade, dkCodeIntegrityPolicy,
    dkDriverTimelineKernel, dkSystemViewDisagreement,
    dkKernelMappingEvidence, dkBootAttestationContinuity,
    dkCodeIntegrityEventCorrelation, dkKernelTelemetryGap,
    dkSessionTrustUntrusted,
    dkDriverLoadProvenance, dkDriverSignerAttestation,
    dkDriverServiceTimeline, dkHypervisorVBSCrossView,
    dkKernelDMAIOMMUTrust);
  TDetectionKinds = set of TDetectionKind;

procedure ReportDetections(const Kinds: TDetectionKinds);
procedure ReportSamplingWarning;

implementation

procedure ReportDetections(const Kinds: TDetectionKinds);
begin
  // Compatibility for diagnostics. Production uses typed engine observations.
end;

procedure ReportSamplingWarning;
begin
  // The sampling monitor keeps its health state without emitting output.
end;

end.
