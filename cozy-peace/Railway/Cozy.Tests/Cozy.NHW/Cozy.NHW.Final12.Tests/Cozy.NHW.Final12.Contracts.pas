unit Cozy.NHW.Final12.Contracts;
interface
function TestCausalFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestRiskFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestAsyncRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestReadRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestWriteRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestTypesFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestETWTypesFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestOptionsFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestLoggingFinal12(out Failure: string; out Checks: Integer): Boolean;
function TestAdvancedRegressionFinal12(out Failure: string; out Checks: Integer): Boolean;
implementation
uses Winapi.Windows, System.SysUtils, Cozy.NHW.CausalGraph, Cozy.NHW.RiskConfidence,
  Cozy.NHW.AsyncRules, Cozy.NHW.ReadRules, Cozy.NHW.WriteRules, Cozy.NHW.Types, Cozy.NHW.ETWTypes,
  Cozy.NHW.Options, Cozy.NHW.Logging, Cozy.NHW.WinPointers, Cozy.NHW.AdvancedRegression;
function TestCausalFinal12(out Failure: string; out Checks: Integer): Boolean;
var C: TCausalAttackGraph; D: TDetectionKinds; Last: TCorrelatedSequence;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  C := nil;
  try
  try

    C := TCausalAttackGraph.Create; D := [];
    Check(CausalSequenceCandidate(1, 2, 20001, True, True), '20 second window inclusive');
    Check(not CausalSequenceCandidate(1, 2, 20002, True, True), 'window exceeded');
    Check(not CausalSequenceCandidate(High(UInt64), 2, 3, True, True), 'ordered subtraction guarded');
    Check(not CausalSequenceCandidate(1, 2, 3, False, True), 'identity required');
    C.Examine(True, False, True, True, 1, 1, True, [], 1000, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPECodeIntegrity], 2000, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPrivateThread], 3000, D);
    Check(dkCausalSequence in D, 'normal ordered sequence retained');
    Last := C.LastSequence;
    Check(Last.ActorPID = 0, 'no actor attribution from temporal evidence');
    Check(Last.ConfirmedTemporalOrder and (Last.AccessTick = 1000), 'sequence detail retained');
    C.Reset; D := [];
    C.Examine(True, False, True, True, 1, 1, True, [], 1000, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPECodeIntegrity], 2000, D);
    C.Examine(True, False, True, True, 1, 1, False, [], 1500, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPrivateThread], 3000, D);
    Check(D = [], 'rollback after memory breaks sequence even when after access');
    C.Reset; D := [];
    C.Examine(True, False, True, True, 1, 1, True, [], 1000, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPECodeIntegrity], 2000, D, False);
    C.Examine(True, False, True, True, 1, 1, False, [dkPrivateThread], 3000, D);
    Check(D = [], 'known producer gap breaks phases');
    C.Reset; D := [];
    C.Examine(True, False, True, True, 1, 1, True, [], 1000, D);
    C.ObservationGap;
    C.Examine(True, False, True, True, 1, 1, False, [dkPECodeIntegrity], 2000, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPrivateThread], 3000, D);
    Check(D = [], 'asynchronous failure notification invalidates sequence');
    C.Reset; D := [];
    C.Examine(True, False, True, True, 0, 1, True, [], 1000, D);
    C.Examine(True, False, True, True, 0, 1, False, [dkPECodeIntegrity], 2000, D);
    C.Examine(True, False, True, True, 0, 1, False, [dkPrivateThread], 3000, D);
    Check(D = [], 'PID zero cannot be a causal target');
    C.Reset; D := [];
    C.Examine(True, False, True, True, 1, 1, True, [], 1000, D);
    C.Examine(True, False, True, True, 1, 2, False, [dkPECodeIntegrity], 2000, D);
    C.Examine(True, False, True, True, 1, 2, False, [dkPrivateThread], 3000, D);
    Check(D = [], 'epoch transition breaks phases');
    C.Reset; D := [];
    C.Examine(True, False, True, True, 1, 1, True, [], 1000, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPECodeIntegrity], 1000, D);
    C.Examine(True, False, True, True, 1, 1, False, [dkPrivateThread], 1001, D);
    Check(D = [], 'duplicate timestamp cannot add a phase');
    Check(IsMemoryEvidence([dkWriteIntegrity]), 'legacy memory family retained');
    Check(IsThreadEvidence([dkPrivateThread]), 'legacy thread family retained');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
  finally C.Free; end;
end;

function TestRiskFinal12(out Failure: string; out Checks: Integer): Boolean;
var M: TRiskConfidenceMonitor; D: TDetectionKinds; F: TRiskFamilies; Score: Integer;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil;
  try
  try

    M := TRiskConfidenceMonitor.Create;
    Check(IndependentFamilyCount([rfExternal, rfThread, rfTelemetryGap]) = 2, 'gap is not independent family');
    Check(ComputeEvidenceConfidence([rfExternal, rfThread, rfMemory]) = 76, 'unchanged score');
    Check(ComputeEvidenceConfidence([rfTelemetryGap]) = 0, 'score floor');
    Check(ComputeEvidenceConfidence([rfExternal, rfThread, rfMemory, rfModule, rfIndependentObserver]) = 100, 'score cap');
    D := [dkProcess];
    F := M.Evaluate([dkPrivateThread, dkPECodeIntegrity], True, False, False, True, 1, Score, D);
    Check(dkProcess in D, 'input detection bits preserved');
    Check(dkRiskConfidence in D, 'valid positive report');
    Check(IndependentFamilyCount(F) = 3, 'families classified');
    D := []; M.Evaluate([dkPrivateThread, dkPECodeIntegrity], True, False, False, True, 1, Score, D);
    Check(D = [], 'duplicate no output');
    D := []; M.Evaluate([dkPrivateThread, dkPECodeIntegrity], True, False, False, True, 60000, Score, D);
    Check(D = [], 'cooldown below boundary');
    D := []; M.Evaluate([dkPrivateThread, dkPECodeIntegrity], True, False, False, True, 60001, Score, D);
    Check(dkRiskConfidence in D, 'cooldown inclusive boundary');
    M.Reset; D := [];
    M.Evaluate([dkPrivateThread, dkPECodeIntegrity], True, True, False, True, 1000, Score, D);
    Check(D = [], 'trace loss not strong confirmation');
    M.Reset; D := [];
    M.Evaluate([dkPrivateThread, dkPECodeIntegrity], True, False, False, False, 1000, Score, D);
    Check(D = [], 'identity missing not strong confirmation');
    M.Reset; D := [];
    M.Evaluate([dkPrivateThread, dkPECodeIntegrity], True, False, False, True, 0, Score, D);
    Check(D = [], 'zero timestamp not evidence');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
  finally M.Free; end;
end;

function TestAsyncRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
var I: Integer;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try

    Check(ExpectedCompletion(1, 1, 4, 4, nil), 'matching self completion');
    Check(not ExpectedCompletion(1, 2, 4, 4, nil), 'key mismatch');
    Check(not ExpectedCompletion(1, 1, 4, 5, nil), 'length mismatch');
    Check(not ExpectedCompletion(1, 1, 4, 4, Pointer(1)), 'unexpected overlapped');
    Check(WorkCountersConsistent(0, 0), 'zero counters');
    Check(not WorkCountersConsistent(-1, 0), 'negative submitted');
    Check(not WorkCountersConsistent(1, -1), 'negative completed');
    Check(not WorkCountersConsistent(1, 2), 'completed beyond submitted');
    Check(WorkCountersConsistent(High(LongInt), High(LongInt)), 'max signed counters');
    for I := 0 to 20 do
      Check(InRecentWindow(100+UInt64(I), 100, 10) = (I <= 10), 'time window');
    Check(not InRecentWindow(99, 100, 10), 'future stamp');
    Check(not InRecentWindow(100, 0, 10), 'zero event');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
end;

function TestReadRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
var I: Integer;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try

    Check(ReadCapable(False, ACCESS_VM_READ), 'process read');
    Check(not ReadCapable(True, ACCESS_VM_READ), 'thread mask has different semantics');
    Check(not ReadCapable(False, ACCESS_QUERY_LIMITED), 'query is not read');
    Check(NewlyReadCapable(False, True, False, 0, ACCESS_VM_READ), 'new read');
    Check(not NewlyReadCapable(False, False, False, ACCESS_VM_READ, ACCESS_VM_READ), 'unchanged read');
    Check(NewlyReadCapable(False, False, True, ACCESS_VM_READ, ACCESS_VM_READ), 'inactive return');
    Check(not CanaryGuardLost(True, True, False, False), 'failed guard query unknown');
    Check(CanaryGuardLost(True, True, True, False), 'observed guard transition');
    Check(not SamplingGapRelevant(500, 1000, 500), 'exact sampling boundary');
    Check(SamplingGapRelevant(501, 1000, 500), 'scan over budget');
    Check(not SamplingGapRelevant(0, UInt64(High(Cardinal))*2, High(Cardinal)), 'wide arithmetic interval');
    for I := 0 to 20 do Check(RecentObservation(100+UInt64(I), 100, 10) = (I <= 10), 'read time window');
    Check(not RecentObservation(99, 100, 10), 'reverse read observation');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
end;

function TestWriteRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
var I: Integer;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try

    Check(WriteCapable(False, ACCESS_VM_WRITE), 'process write');
    Check(not WriteCapable(True, ACCESS_VM_WRITE), 'not a process right on a thread');
    Check(not WriteCapable(False, ACCESS_VM_READ), 'read is not write');
    Check(NewlyWriteCapable(False, True, False, 0, ACCESS_VM_WRITE), 'new write');
    Check(not NewlyWriteCapable(False, False, False, ACCESS_VM_WRITE, ACCESS_VM_WRITE), 'unchanged write');
    Check(CountSetBits(0) = 0, 'empty mask');
    Check(CountSetBits(High(Cardinal)) = 32, 'all bits');
    for I := 0 to 31 do Check(CountSetBits(Cardinal(1) shl I) = 1, 'each single bit');
    Check(CountSetBits($AAAAAAAA) = 16, 'alternating mask');
    Check(RecentWriteObservation(110, 100, 10), 'inclusive write window');
    Check(not RecentWriteObservation(99, 100, 10), 'reverse write observation');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
end;

function TestTypesFinal12(out Failure: string; out Checks: Integer): Boolean;
var H, Other: TTargetHolder;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try

    H := Default(TTargetHolder); H.PID := 42; H.CreateTime := 100; H.ObjectIdentity := $1234;
    Other := H;
    Check(IdentityKey(H) = IdentityKey(Other), 'same process identity');
    Other.CreateTime := 101;
    Check(IdentityKey(H) <> IdentityKey(Other), 'creation time separates reused PID');
    Other := H; Other.IsThread := True;
    Check(IdentityKey(H) <> IdentityKey(Other), 'process and thread domains separate');
    H := Other; Other.ObjectIdentity := $1235;
    Check(IdentityKey(H) <> IdentityKey(Other), 'thread object identity separates');
    Check(LevelForProcessRights(ACCESS_VM_READ) = 1, 'read level unchanged');
    Check(LevelForProcessRights(ACCESS_VM_WRITE) = 3, 'write level unchanged');
    Check(LevelForThreadRights(THREAD_GET_CONTEXT_RIGHT) = 1, 'get context level');
    Check(LevelForThreadRights(THREAD_SET_CONTEXT_RIGHT) = 3, 'set context level');
    Check(SignificantRights(H) = THREAD_SIGNIFICANT_RIGHTS, 'thread rights domain');
    Check(QueryRights(H) = THREAD_QUERY_RIGHTS, 'thread query domain');
    H.IsThread := False;
    Check(SignificantRights(H) = PROCESS_SIGNIFICANT_RIGHTS, 'process rights domain');
    Check(QueryRights(H) = PROCESS_QUERY_RIGHTS, 'process query domain');
    H.CreateTime := High(UInt64); Other := H; Other.CreateTime := High(UInt64)-1;
    Check(IdentityKey(H) <> IdentityKey(Other), 'high-bit creation IDs remain distinct');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
end;

function TestETWTypesFinal12(out Failure: string; out Checks: Integer): Boolean;
var L: TKernelEventList; E: TKernelEvent;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  L := nil;
  try
  try

    L := TKernelEventList.Create;
    E := Default(TKernelEvent); E.Kind := keThreadStart; E.PID := 42; E.ThreadID := 43; E.Tick := 100;
    L.Add(E); E.Kind := keImageLoad; E.Tick := 101; L.Add(E);
    Check(L.Count = 2, 'event records retained');
    Check(L[0].Kind = keThreadStart, 'value copy not alias');
    Check(L[0].Tick = 100, 'old timestamp not overwritten');
    Check(L[1].Kind = keImageLoad, 'second event type');
    Check(L[1].PID = 42, 'process identity field');
    Check(L[1].ThreadID = 43, 'thread identity field');
    Check(L[1].ParentPID = 0, 'default parent is unknown');
    L.Clear; Check(L.Count = 0, 'RAM container clear');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
  finally L.Free; end;
end;

function TestOptionsFinal12(out Failure: string; out Checks: Integer): Boolean;
var O: TOptions;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try

    ResolveWinPointers;
    O.TargetName := 'stale'; O.IgnorePathPrefix := 'stale'; O.IgnorePID := 123;
    ConfigureDefaultMonitoring(O);
    Check(O.TargetPID = WinCurrentProcessId, 'own PID default');
    Check(O.TargetName = '', 'old managed target cleared');
    Check(O.IgnorePathPrefix = '', 'old managed path cleared');
    Check(O.IgnorePID = 0, 'old ignore PID cleared');
    Check(O.IntervalMS = 500, 'interval preserved');
    Check(O.BaselineScans = 3, 'baseline preserved');
    Check(O.MissThreshold = 2, 'missing threshold preserved');
    Check((O.MinLevel = 3) and (O.ThreadMinLevel = 3),
      'only high-impact holders produce direct process/thread alerts');
    Check(O.Watch and O.ThreadWatch, 'watch settings preserved');
    Check(not O.ReportHandleCount, 'count-only output off');
    Check(not O.Help and not O.PauseOnExit, 'no help or pause defaults');

    Result := True;
  except on E: Exception do Failure := E.Message; end;
end;

function TestLoggingFinal12(out Failure: string; out Checks: Integer): Boolean;
var D: TDetectionKinds; K: TDetectionKind; N: Integer;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try

    D := []; N := 0;
    for K := Low(TDetectionKind) to High(TDetectionKind) do begin Include(D, K); Inc(N); end;
    Check(N <= 256, 'enum fits Delphi set');
    Check(SizeOf(TDetectionKinds) <= 32, 'bitset fits chain event payload');
    Check(dkProcess in D, 'legacy category retained');
    Check(dkAPCStyleEvidence in D, 'last category retained');
    D := []; ReportDetections(D);
    Check(D = [], 'empty output request leaves data unchanged');
    // Console literals/order and disabled categories are byte-compared in the static audit.

    Result := True;
  except on E: Exception do Failure := E.Message; end;
end;

function TestAdvancedRegressionFinal12(out Failure: string; out Checks: Integer): Boolean;
begin
  Result := ValidateV70RiskStateCases(Failure, Checks);
end;

end.
