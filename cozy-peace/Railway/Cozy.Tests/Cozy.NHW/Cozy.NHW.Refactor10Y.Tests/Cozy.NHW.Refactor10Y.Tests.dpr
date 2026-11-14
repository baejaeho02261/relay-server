program CozyNHW_Refactor10Y_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE10Q_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Refactor10Y.Tests.dproj with its fixture defines.'}
{$ENDIF}

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.Types, Cozy.NHW.Logging, Cozy.NHW.WinPointers,
  Cozy.NHW.Namespace, Cozy.NHW.NamespaceNative,
  Cozy.NHW.ReadAccess, Cozy.NHW.MemoryDelta, Cozy.NHW.SectionCorrelation,
  Cozy.NHW.ExceptionGuard, Cozy.NHW.ExceptionRules, Cozy.NHW.SelfRules,
  Cozy.NHW.FileGuard, Cozy.NHW.FileNative, Cozy.NHW.CodeProvenanceGraph,
  Cozy.NHW.FileAttestation, Cozy.NHW.ExportRules, Cozy.NHW.PERules,
  Cozy.NHW.ForensicHashChain;

type
  TFixture = function(out Failure: string; out Checks: Integer): Boolean;
var
  ContractChecks, FixtureChecks, Groups: Integer;

procedure Check(Condition: Boolean; const Name: string);
begin
  Inc(ContractChecks);
  if not Condition then raise Exception.Create(Name);
end;

procedure Existing(const Name: string; Test: TFixture);
var Failure: string; Count: Integer;
begin
  Failure := ''; Count := 0;
  if not Test(Failure, Count) then
    raise Exception.Create(Name + ': ' + Failure);
  Inc(FixtureChecks, Count);
end;

procedure Done(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure TestNamespace;
var A, B: TNamespaceEntries; E: TNamespaceEntry;
  Changes: Integer; D: TDetectionKinds;
begin
  Existing('namespace publication and allocation failures', TestNamespace10M);
  A := nil; B := nil;
  try
    A := TNamespaceEntries.Create;
    B := TNamespaceEntries.Create;
    D := CompareNamespaceEntries(A, B, False, Changes);
    Check((D = []) and (Changes = 0), 'namespace: empty equality');
    E := Default(TNamespaceEntry); E.TypeName := 'SymbolicLink';
    E.TargetKnown := True; E.Target := '\\old';
    A.Add('NHW.TEST', E); B.Add('NHW.TEST', E);
    D := CompareNamespaceEntries(A, B, True, Changes);
    Check((D = []) and (Changes = 0), 'namespace: known unchanged link');
    E.Target := '\\new'; B['NHW.TEST'] := E;
    D := CompareNamespaceEntries(A, B, True, Changes);
    Check((dkSymbolicLink in D) and (dkDeviceMap in D), 'namespace: link change classification');
    Check(Changes = 1, 'namespace: exactly one target change');
    E.TargetKnown := False; B['NHW.TEST'] := E;
    D := CompareNamespaceEntries(A, B, True, Changes);
    Check(D = [], 'namespace: unknown target is not a confirmed change');
    B.Clear;
    D := CompareNamespaceEntries(A, B, True, Changes);
    Check((dkNamespace in D) and (Changes = 1), 'namespace: confirmed removal');
  finally B.Free; A.Free; end;
  Done('Namespace: filter, preserve links, commit');
end;

procedure TestReadAccess;
var M: TReadAccessMonitor; H: TTargetHolder; D: TDetectionKinds;
begin
  Existing('canary failures, rearm and gap behavior', TestReadAccess5I);
  M := TReadAccessMonitor.Create;
  try
    Check(M.CanaryAddress = 0, 'read: no target means no canary allocation');
    D := [dkCrossAccess];
    M.ExamineCanary(0, 1000, D);
    Check(D = [dkCrossAccess], 'read: inactive canary preserves signals');
    H := Default(TTargetHolder); H.RightsUnion := ACCESS_VM_READ;
    M.BeginSnapshot;
    M.ObserveHolder(H, True, False, True, 0, 1100, D);
    Check(D = [dkCrossAccess], 'read: baseline access remains quiet');
    M.EndSnapshot; M.BeginSnapshot;
    M.ObserveHolder(H, True, False, False, 0, 1200, D);
    Check(dkReadAccess in D, 'read: fresh read-capable access retained');
    M.Reset(0);
    Check(M.CanaryAddress = 0, 'read: reset preserves inactive allocation state');
  finally M.Free; end;
  Done('ReadAccess: establish, observe loss, apply guard state');
end;

procedure TestMemoryDelta;
var M: TIncrementalMemoryDelta;
begin
  Existing('rotating delta, failures and baseline recovery', TestMemoryDeltaHardening);
  M := TIncrementalMemoryDelta.Create;
  try
    Check(M.ObservedTransitions = 0, 'delta: initial transition count');
    Check(M.LastChangeTick = 0, 'delta: initial change tick');
    M.Examine(False, False, True, 1000);
    Check(M.ObservedTransitions = 0, 'delta: non-self target adds no transitions');
    M.Examine(True, True, False, 2000);
    Check(M.LastChangeTick = 0, 'delta: skipped heavy scan publishes no change');
    M.Reset;
    Check((M.ObservedTransitions = 0) and (M.LastChangeTick = 0), 'delta: reset');
  finally M.Free; end;
  Done('MemoryDelta: recheck, seed, publish');
end;

procedure TestSections;
var M: TSectionCorrelation; D: TDetectionKinds;
begin
  Existing('mapped thread remap and query failures', TestSectionCorrelationHardening);
  Check(SectionCorrelationCandidate(True, True, 2, True, True, True, True), 'section: complete corroboration');
  Check(not SectionCorrelationCandidate(True, True, 1, True, True, True, True), 'section: two confirmations required');
  Check(not SectionCorrelationCandidate(True, True, 2, False, True, True, True), 'section: external section context required');
  Check(not SectionCorrelationCandidate(True, True, 2, True, True, True, False), 'section: epoch stability required');
  M := TSectionCorrelation.Create;
  try
    D := [dkCrossAccess];
    M.Examine(False, False, False, False, False, 0, nil, nil, [], 1000, D);
    Check(D = [dkCrossAccess], 'section: non-self reset keeps caller signals');
  finally M.Free; end;
  Done('SectionCorrelation: context, retirement, thread inspection');
end;

procedure TestExceptions;
var F: TStableFingerprint;
begin
  Existing('exception capture gaps and callback failures', TestExceptionGuard5K);
  F := Default(TStableFingerprint);
  Check(not ObserveFingerprint(F, 100, True), 'exception: baseline accepted quietly');
  Check(not ObserveFingerprint(F, 100, True), 'exception: unchanged fingerprint');
  Check(not ObserveFingerprint(F, 200, True), 'exception: one changed observation is insufficient');
  Check(not ObserveFingerprint(F, 200, False), 'exception: invalid observation does not confirm');
  Check(not ObserveFingerprint(F, 200, True), 'exception: invalid read breaks pending sequence');
  Check(ObserveFingerprint(F, 200, True), 'exception: two new valid changed observations');
  Done('ExceptionGuard: baseline, image, structure, callback');
end;

procedure TestFiles;
var S: TFileGuardState; E: TFileEvidence; D: TDetectionKinds; I: Integer;
begin
  Existing('file baseline and unknown-read continuity', TestFileGuard5K);
  S := Default(TFileGuardState); S.Reset;
  E := Default(TFileEvidence);
  E.ReferenceIdKnown := True; E.ReferenceId := 'I:original';
  E.PathKnown := True; E.PathPresent := True; E.PathId := E.ReferenceId;
  for I := 1 to 3 do
  begin
    D := []; S.Observe(E, D);
    Check(D = [], 'file: three valid baseline samples are quiet');
  end;
  E.PathId := 'I:replacement'; D := [];
  S.Observe(E, D);
  Check(dkFileSwap in D, 'file: new same-format identity is reported');
  D := []; S.Observe(E, D);
  Check(not (dkFileSwap in D), 'file: unchanged replacement is not repeatedly reported');
  E := Default(TFileEvidence); D := [dkCrossAccess]; S.Observe(E, D);
  Check(D = [dkCrossAccess], 'file: unknown sample preserves caller signals');
  Done('FileGuard: path identity and optional metadata');
end;

procedure TestProvenance;
var M: TCodeProvenanceGraph; D: TDetectionKinds;
begin
  Existing('provenance read failures and remapped candidates', TestCodeProvenanceHardening);
  Check(CodeProvenanceCandidate(True, 2, True, True), 'code: corroborated current candidate');
  Check(not CodeProvenanceCandidate(False, 2, True, True), 'code: baseline threads excluded');
  Check(not CodeProvenanceCandidate(True, 1, True, True), 'code: single observation excluded');
  Check(not CodeProvenanceCandidate(True, 2, False, True), 'code: independent evidence required');
  M := TCodeProvenanceGraph.Create;
  try
    D := [dkCrossAccess];
    M.Examine(False, False, False, False, False, nil, 1000, D);
    Check(D = [dkCrossAccess], 'code: non-self path publishes nothing');
    M.Examine(True, False, False, False, False, nil, 2000, D);
    Check(D = [dkCrossAccess], 'code: unavailable snapshot publishes nothing');
  finally M.Free; end;
  Done('CodeProvenanceGraph: retire, inspect current region, report');
end;

procedure TestAttestation;
var A, B: TAttestedFileIdentity;
begin
  Existing('identity failure, expiration and remap fixtures', TestFileAttestationHardening);
  A := Default(TAttestedFileIdentity); B := A;
  Check(not CaptureAttestedFile(0, B), 'attest: null module is not the main executable');
  Check(not B.Valid, 'attest: rejected module has no valid output');
  A.Valid := True; A.Base := $10000; A.PathFileID := 1; A.PEImageSize := $2000;
  B := A;
  Check(not AttestationCandidate(A, B, 2, True), 'attest: unchanged identity');
  B.PathFileID := 2;
  Check(not AttestationCandidate(A, B, 1, True), 'attest: single changed sample');
  Check(AttestationCandidate(A, B, 2, True), 'attest: repeated identity change');
  Check(not AttestationCandidate(A, B, 2, False), 'attest: independent evidence required');
  Done('FileAttestation: candidate advancement and reporting');
end;

procedure TestDelayImports;
var W: TExportWatch; S: TDelaySlotSnapshot;
begin
  Existing('delay import resolve/unload and partial snapshot fixtures', TestExportRules10Q);
  Check(IsValidForwarder(AnsiString('kernel32.Sleep')), 'exports: named forwarder');
  Check(IsValidForwarder(AnsiString('ntdll.#123')), 'exports: ordinal forwarder');
  Check(not IsValidForwarder(AnsiString('ntdll.#')), 'exports: missing ordinal');
  Check(IsApiSetContract(AnsiString('API-test')), 'exports: ASCII contract case');
  W := Default(TExportWatch); S := Default(TDelaySlotSnapshot);
  Check(not ObserveDelayImportSlots(W, S, False), 'exports: incomplete snapshot is not a change');
  Check(Length(W.DelaySlots) = 0, 'exports: incomplete input does not publish slots');
  Done('ExportRules: layout, slot candidates, commit');
end;

procedure TestHashChain;
var C: TForensicHashChain; F, Previous: TForensicHashFrame; I: Integer;
begin
  // Local CNG integration only. Failure is not silently reported as a pass.
  Check(HashingAvailable, 'chain: Windows SHA-256 provider is required');
  C := TForensicHashChain.Create;
  try
    Check(C.Count = 0, 'chain: empty ring');
    Check(not C.Latest(F), 'chain: no latest frame initially');
    Check(not C.Append(1000, 7, [], 0, False), 'chain: empty non-gap input ignored');
    Check(C.Append(1000, 7, [dkCrossAccess], 3, False), 'chain: append first evidence');
    Check(C.Latest(F), 'chain: latest first frame available');
    Check((F.Payload.Sequence = 1) and (F.Payload.TargetPID = 7), 'chain: payload identity');
    Check(C.Verify, 'chain: first hash verifies');
    Previous := F;
    Check(C.Append(1001, 7, [], 0, True), 'chain: gap-only evidence is retained');
    Check(C.Latest(F), 'chain: latest gap frame available');
    Check(F.Payload.VisibilityGap = 1, 'chain: gap flag');
    Check(CompareMem(@F.Payload.PreviousHash[0], @Previous.Digest[0], SizeOf(THash256)), 'chain: digest link');
    for I := 1 to 260 do
      Check(C.Append(UInt64(1001 + I), 7, [dkCrossAccess], 1, False), 'chain: bounded-ring append');
    Check(C.Count = 256, 'chain: fixed capacity retained');
    Check(C.Verify, 'chain: wrapped ring verifies');
    Check(C.Latest(F) and (F.Payload.Sequence = 262), 'chain: sequence across ring wrap');
    C.Prune(100000);
    Check(C.Count = 0, 'chain: expired verified entries pruned');
    C.Reset;
    Check(C.Count = 0, 'chain: reset');
  finally C.Free; end;
  Done('ForensicHashChain: payload construction, hash, ring commit');
end;

begin
  try
    ContractChecks := 0; FixtureChecks := 0; Groups := 0;
    ResolveWinPointers;
    TestNamespace; TestReadAccess; TestMemoryDelta; TestSections;
    TestExceptions; TestFiles; TestProvenance; TestAttestation;
    TestDelayImports; TestHashChain;
    if Groups <> 10 then raise Exception.Create('Incomplete group execution');
    Writeln('PASS Refactor10Y: ', Groups, ' groups; ', ContractChecks,
      ' contract checks; ', FixtureChecks, ' inherited fixture checks.');
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln('FAIL Refactor10Y: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
