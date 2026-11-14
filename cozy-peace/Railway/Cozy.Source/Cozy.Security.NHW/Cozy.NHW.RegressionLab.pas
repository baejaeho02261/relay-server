unit Cozy.NHW.RegressionLab;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// v60: deterministic rules + read-only local smoke. It never creates a
// remote thread, mutates a process, or induces an artificial intrusion.
function ValidateSectionIdentityRegression(out Failure: string;
  out Checks: Integer): Boolean;

function ValidateV60Regression(out Failure: string;
  out OptionalLiveChecks: Integer): Boolean;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestRegressionLab10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.Logging, Cozy.NHW.WinPointers, Cozy.NHW.ReplayValidation,
  Cozy.NHW.PEView, Cozy.NHW.ImportRedirection, Cozy.NHW.TLSCallbackIntegrity,
  Cozy.NHW.UnwindConsistency, Cozy.NHW.ExecutableLifecycle,
  Cozy.NHW.SectionBackingIdentity, Cozy.NHW.ThreadStackProvenance,
  Cozy.NHW.CoverageWindow, Cozy.NHW.FalsePositiveControl,
  Cozy.NHW.ExplainableEvidence, Cozy.NHW.EvidenceChain;

function ValidateSectionIdentityRegression(out Failure: string;
  out Checks: Integer): Boolean;
var Base, Current: TSectionIdentity; I: Integer;
  procedure Check(Value: Boolean; const Description: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Description);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  try
    Base := Default(TSectionIdentity);
    Base.Valid := True; Base.Base := $180000000;
    Base.MappedNameHash := 1234; Base.PathFileID := 88;
    Base.FileIDKind := sfkFileID128; Base.VolumeSerial := 100;
    for I := 0 to 15 do Base.FileID128[I] := Byte(I + 1);
    Current := Base;
    Check(not SectionBackingCandidate(Base, Current, 2, True), '128-bit identity unchanged');
    // Test every ID byte independently; the compatibility digest stays equal.
    for I := 0 to 15 do
    begin
      Current := Base;
      Current.FileID128[I] := Current.FileID128[I] xor $80;
      Check(SectionBackingCandidate(Base, Current, 2, True), 'full 128-bit ID byte change');
      Check(not SectionBackingCandidate(Base, Current, 1, True), 'single observation rejected');
      Check(not SectionBackingCandidate(Base, Current, 2, False), 'independent evidence required');
    end;
    Current := Base; Current.VolumeSerial := 101;
    Check(SectionBackingCandidate(Base, Current, 2, True), 'same ID on different volume');
    Current := Base; Current.PathFileID := 89;
    Check(not SectionBackingCandidate(Base, Current, 2, True), 'compatibility digest not full-ID identity');
    Current := Base; Current.FileIDKind := sfkLegacy64;
    Check(not SectionBackingCandidate(Base, Current, 2, True), '128 to legacy is re-prime, not comparison');
    Base.FileIDKind := sfkLegacy64; Base.LegacyFileIndex := 88;
    Current := Base; Current.LegacyFileIndex := 89;
    Check(SectionBackingCandidate(Base, Current, 2, True), 'documented legacy comparison');
    Current := Base; Current.FileIDKind := sfkFileID128;
    Check(not SectionBackingCandidate(Base, Current, 2, True), 'legacy to full ID is representation boundary');
    Current := Base; Current.Valid := False;
    Check(not SectionBackingCandidate(Base, Current, 2, True), 'failed capture not identity replacement');
    Current := Base; Current.Base := Base.Base + $10000;
    Check(not SectionBackingCandidate(Base, Current, 2, True), 'different mapped image not same candidate');
    // Keep the old compatibility contract under test as well.
    Base.FileIDKind := sfkUnspecified; Current := Base; Inc(Current.PathFileID);
    Check(SectionBackingCandidate(Base, Current, 2, True), 'pre-G synthetic compatibility');
    Result := True;
  except
    on E: Exception do Failure := E.Message;
  end;
end;

function ValidateV60Regression(out Failure: string;
  out OptionalLiveChecks: Integer): Boolean;
var
  ReplayFailure: string;
  IdentityChecks: Integer;
  Kinds: TDetectionKinds;
  Suppressor: TNewSignalSuppressor;
  Coverage: TCoverageWindowMonitor;
  Explained: TExplainableEvidence;
  Frame: TExplanationFrame;
  PE: TPEView;
  ImportInfo: TImportRiskSnapshot;
  TLSInfo: TTLSCallbackSnapshot;
  procedure Check(Value: Boolean; const Description: string);
  begin
    if not Value then raise Exception.Create(Description);
  end;

  procedure TestPriorReplay;
  begin
    Check(ValidateReplayRules(ReplayFailure),
      'v50 baseline: ' + ReplayFailure);
  end;

  procedure TestImageAndExecutionRules;
  begin
    Check(IsImportRedirectionCandidate(0, 1, 2, True),
      'v51 import candidate');
    Check(not IsImportRedirectionCandidate(0, 1, 1, True),
      'v51 single-scan rejection');
    Check(not IsImportRedirectionCandidate(2, 2, 2, True),
      'v51 baseline private allowed');
    Check(TLSCallbackAnomaly(10, 11, 1, 2, True),
      'v52 TLS candidate');
    Check(not TLSCallbackAnomaly(10, 11, 0, 2, True),
      'v52 no private callback');
    Check(UnwindStructuralCandidate(100, 101, 2, True),
      'v53 confirmed table change');
    Check(not UnwindStructuralCandidate(100, 101, 2, False),
      'v53 no corroboration');
    Check(IsExecutableTransition(epWritable, epExecutable),
      'v54 RW to RX');
    Check(IsExecutableTransition(epWritable, epRWX),
      'v54 RW to RWX');
    Check(not IsExecutableTransition(epExecutable, epExecutable),
      'v54 no change');
    Check(ClassifyPrivateProtection($04) = epWritable,
      'v54 RW classification');
    Check(ClassifyPrivateProtection($20) = epExecutable,
      'v54 RX classification');
    Check(ValidateSectionIdentityRegression(ReplayFailure, IdentityChecks),
      'v55 identity regression: ' + ReplayFailure);
    Check(IdentityChecks > 0, 'v55 full identity fixtures executed');
    Check(StackOriginCandidate($50000, 2, True),
      'v56 call stack provenance');
    Check(not StackOriginCandidate(0, 2, True),
      'v56 absent private call frame');
    Check(CoverageIntervalSlow(5000, 5000, 1000),
      'v57 slow interval');
    Check(not CoverageIntervalSlow(300, 1000, 1000),
      'v57 normal interval');
  end;

  procedure TestCoverageState;
  begin
    Coverage := TCoverageWindowMonitor.Create;
    Kinds := [];
    Coverage.Examine(5000, 6000, 1000, False, 1000, Kinds);
    Coverage.Examine(5000, 6000, 1000, False, 2000, Kinds);
    Check(not (dkCoverageGap in Kinds), 'v57 sustained requirement');
    Coverage.Examine(5000, 6000, 1000, False, 3000, Kinds);
    Check(dkCoverageGap in Kinds, 'v57 coverage gap');
  end;

  procedure TestOutputSuppression;
  begin
    Suppressor := TNewSignalSuppressor.Create;
    Kinds := [dkProcess, dkImportRedirect];
    Suppressor.Apply(False, 1000, Kinds);
    Check((dkProcess in Kinds) and (dkImportRedirect in Kinds),
      'v58 first occurrence preserved');
    Kinds := [dkProcess, dkImportRedirect];
    Suppressor.Apply(False, 1100, Kinds);
    Check((dkProcess in Kinds) and not (dkImportRedirect in Kinds),
      'v58 new-signal cooldown only');
    Kinds := [dkImportRedirect];
    Suppressor.Apply(False, 70000, Kinds);
    Check(dkImportRedirect in Kinds, 'v58 rearm');
  end;

  procedure TestExplanationRing;
  var
    I: Integer;
  begin
    Explained := TExplainableEvidence.Create;
    for I := 1 to 300 do
      Explained.RecordFrame(I, 1234, [dkTLSCallbackIntegrity],
        [efExternalCapability, efMemoryChange]);
    Check(Explained.Count = 256, 'v59 bounded ring');
    Check(Explained.Recent(0, Frame) and (Frame.Sequence = 300),
      'v59 newest sequence');
    Check((xfExternalCapability in Frame.Reasons) and
      (xfTLSCallback in Frame.Reasons) and (Frame.ActorPID = 0),
      'v59 faithful explanations');
    Check(not Explained.Recent(256, Frame), 'v59 bounded access');
  end;

  procedure TestLiveImageQueries;
  begin
    // Live smoke is optional; unavailable Win32 APIs are UNKNOWN, not FAIL.
    ResolveWinPointers;
    if LoadPEView(NativeUInt(HInstance), PE) then
      Inc(OptionalLiveChecks)
    else
      raise Exception.Create('v60 own executable PE image is unreadable');
    if CaptureImportRisk(ImportInfo) and ImportInfo.Valid then
      Inc(OptionalLiveChecks);
    if CaptureTLSCallbacks(TLSInfo) and TLSInfo.Valid then
      Inc(OptionalLiveChecks);
  end;

begin
  Result := False;
  Failure := '';
  OptionalLiveChecks := 0;
  Suppressor := nil;
  Coverage := nil;
  Explained := nil;
  try
    TestPriorReplay;
    TestImageAndExecutionRules;
    TestCoverageState;
    TestOutputSuppression;
    TestExplanationRing;
    TestLiveImageQueries;
    Result := True;
  except
    on E: Exception do Failure := E.Message;
  end;
  Explained.Free;
  Suppressor.Free;
  Coverage.Free;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.RegressionLab.inc}
{$ENDIF}

end.
