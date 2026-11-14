unit Cozy.NHW.StabilityRegression;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Explicit offline test entry point. Never called by the production engine.
function ValidateStabilization(out Failure: string;
  out PassedChecks, OptionalChecks: Integer): Boolean;

implementation

uses
  Winapi.Windows, System.SysUtils, System.Classes,
  Cozy.NHW.NativeSafety, Cozy.NHW.SensorFaultIsolation, Cozy.NHW.UnifiedEvidence,
  Cozy.NHW.PerformanceBudget, Cozy.NHW.RAMLifecycle, Cozy.NHW.Logging,
  Cozy.NHW.EvidenceChain, Cozy.NHW.ExplainableEvidence, Cozy.NHW.ForensicHashChain,
  Cozy.NHW.MemoryEvidenceCapsule, Cozy.NHW.PrivacyForensics, Cozy.NHW.SensorConsensus,
  Cozy.NHW.IncidentReconstruction, Cozy.NHW.FastEventRing, Cozy.NHW.ETWTypes,
  Cozy.NHW.PEView, Cozy.NHW.WinPointers,
  Cozy.NHW.AdvancedRegressionV80, Cozy.NHW.AdvancedRealtimeRegression,
  Cozy.NHW.AdvancedPrivacyRegressionV100, Cozy.NHW.SelectedRegressionV109;

type
  TPruneProbe = class
    Calls: Integer;
    LastTick: UInt64;
    ShouldFail: Boolean;
    procedure Maintain(Tick: UInt64);
  end;

  TRingProducer = class(TThread)
  private
    FRing: TFastEventRing;
  protected
    procedure Execute; override;
  public
    constructor Create(Ring: TFastEventRing);
  end;

procedure TPruneProbe.Maintain(Tick: UInt64);
begin
  Inc(Calls); LastTick := Tick;
  if ShouldFail then raise Exception.Create('synthetic cleanup fault');
end;

constructor TRingProducer.Create(Ring: TFastEventRing);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FRing := Ring;
end;

procedure TRingProducer.Execute;
var I: Cardinal; E: TKernelEvent;
begin
  E := Default(TKernelEvent);
  E.Kind := keProcessStart;
  for I := 1 to 10000 do
  begin
    E.PID := I;
    while not Terminated do
    begin
      if FRing.Push(E, Int64(I)) then Break;
      TThread.Sleep(0);
    end;
    if Terminated then Exit;
  end;
end;

function ValidateStabilization(out Failure: string;
  out PassedChecks, OptionalChecks: Integer): Boolean;
var
  Faults: TSensorFaultIsolation;
  U: TUnifiedEvidence;
  B: TPerformanceBudget;
  R: TRAMLifecycle;
  P1, P2: TPruneProbe;
  E: TEvidenceChain;
  X: TExplainableEvidence;
  H: TForensicHashChain;
  C: TMemoryEvidenceCapsule;
  P: TPrivacyForensics;
  S: TSensorConsensus;
  Incidents: TIncidentReconstruction;
  Ring: TFastEventRing;
  Producer: TRingProducer;
  Address, Size: NativeUInt;
  Next: Cardinal;
  NeedReset, ProducerStarted: Boolean;
  N, Live: Integer;
  Tick, Sequence, FailDeadline: UInt64;
  State: TSensorFaultState;
  Frame: TUnifiedFrame;
  EvidenceFrame: TEvidenceFrame;
  PrivateFrame: TMemoryEvidenceFrame;
  Sample: TFastKernelSample;
  Kinds: TDetectionKinds;
  PE: TPEView;
  Problem: string;
  procedure Check(Value: Boolean; const Name: string);
  begin
    if not Value then raise Exception.Create(Name);
    Inc(PassedChecks);
  end;
  procedure TestNativeBounds;
  begin
    Check(NHWTryAddAddress($10000, 16, Address) and
      (Address = $10010), 'safe addition');
    Check(not NHWTryAddAddress(High(NativeUInt), 1, Address) and
      (Address = 0), 'addition overflow cleared');
    Check(NHWTryMultiplySize(100, 8, Size) and (Size = 800), 'safe product');
    Check(not NHWTryMultiplySize(High(NativeUInt), 2, Size) and
      (Size = 0), 'multiplication overflow cleared');
    Check(NHWBufferSpan(16, 8, 8), 'exact buffer end');
    Check(not NHWBufferSpan(16, 17, 0), 'offset beyond buffer');
    Check(not NHWBufferSpan(16, 8, 9), 'size beyond buffer');
    Check(not NHWAddressSpan(0, 8), 'null range');
    Check(not NHWAddressSpan(High(NativeUInt) - 3, 8), 'range wraps');
    Check(NHWContainedSpan($10000, 4096, $10FFF, 1), 'last byte');
    Check(not NHWContainedSpan($10000, 4096, $10FFF, 2), 'cross boundary');
    Check(NHWNextBufferSize(1024, 2048, 4096, Next) and
      (Next = 4096), 'bounded growth');
    Check(not NHWNextBufferSize(4096, 4097, 4096, Next), 'cap enforced');
    Check(not NHWNextBufferSize(0, 1, 4096, Next), 'zero allocation rejected');
    Check(NHWSaturatingAdd(High(UInt64), 1) = High(UInt64), 'counter saturation');
    Check(not NHWExpired(1000, 61000, 60000), 'TTL inclusive boundary');
    Check(NHWExpired(1000, 61001, 60000), 'TTL expiration');
    Check(NHWExpired(1000, 999, 60000), 'backwards clock');
    Check(not LoadPEView(High(NativeUInt) - 16, PE) and
      (PE.Base = 0), 'failed PE read publishes no partial header');
  end;

  procedure TestFaultIsolation;
  begin
    Faults.BeginCycle;
    Check(Faults.TryBegin(1, 1000, NeedReset) and not NeedReset, 'first admission');
    Check(not Faults.TryBegin(1, 1001, NeedReset), 'reentry rejected');
    Faults.Failed(1, 1001, sfcRecoverable);
    Check(not Faults.TryBegin(1, 1100, NeedReset), 'fault retry cooldown');
    Check(Faults.TryBegin(2, 1100, NeedReset), 'unrelated sensor admitted');
    Faults.Succeeded(2, 1101);
    Check(Faults.TryBegin(1, 1251, NeedReset) and NeedReset, 'retry resets failed sensor');
    Faults.Succeeded(1, 1252);
    State := Faults.Snapshot(1);
    Check((State.Successes = 1) and not State.NeedsReset and
      not State.Running, 'success clears failure state');
    Check(Faults.TakeCoverageWarning(1253), 'coverage warning once');
    Check(not Faults.TakeCoverageWarning(1254), 'warning dedupe');
    Faults.BeginCycle;
    Check(not Faults.CycleIncomplete, 'new cycle visibility');
    Check(Faults.TryBegin(1, 2000, NeedReset), 'retry setup');
    Faults.Failed(1, 2000, sfcRecoverable);
    Check(Faults.TryBegin(1, 100, NeedReset), 'clock rollback does not trap sensor');
    Faults.Succeeded(1, 101);
  end;

  procedure TestEvidenceRoots;
  var
    I: Integer;
  begin
    U.BeginFrame(1000, 101, 123456);
    U.Add(orHandleSnapshot, [dkProcess]);
    U.Add(orHandleSnapshot, [dkProcess]);
    U.Add(orDerived, [dkMultiSignal, dkInjectionEvidence]);
    Check(U.PrimaryRootCount = 1, 'derived/duplicate signals not independent');
    U.Add(orSelfMemory, [dkPECodeIntegrity]);
    Check(U.PrimaryRootCount = 2, 'second acquisition root');
    U.MarkIncomplete;
    Check(not U.CurrentComplete, 'gap is unknown not healthy');
    U.Commit;
    Check(U.Recent(0, Frame) and (Frame.DuplicateKinds = 1), 'duplicate accounting');
    U.BeginFrame(1001, 101, 999999);
    U.Add(orSelfMemory, [dkPECodeIntegrity]); U.Commit;
    Check(U.Recent(0, Frame) and (Frame.TargetCreation = 999999), 'PID reuse epoch');
    for I := 1 to 10000 do
    begin
      U.BeginFrame(UInt64(I + 2000), 101, 999999);
      U.Add(orSelfMemory, [dkPECodeIntegrity]); U.Commit;
    end;
    Check(U.Count = 256, 'unified ring bounded under 10000 frames');
    U.Prune(1000000);
    Check(U.Count = 0, 'unified history expiration');
    S.Evaluate([dkProcess, dkPrivateThread, dkPECodeIntegrity], True,
      False, True, True, False, 1000);
    S.ConstrainToObservedRoots(1, False);
    Check((S.Last.IndependentCount <= 1) and not S.Last.Corroborated,
      'consensus metadata source cap');
  end;

  procedure TestPerformanceBudget;
  begin
    B.BeginCycle(1000, 500);
    B.RecordCost(1, 200000);
    Check(not B.AllowOptional(owImageVerification, 1000, False, False), 'heavy budget deferred');
    Check(B.AllowOptional(owV80Analysis, 1000, True, False), 'baseline never budget-skipped');
    Check(B.AllowOptional(owMemoryDelta, 1000, False, True), 'trigger never budget-skipped');
    Check(not B.AllowOptional(owImageVerification, 5999, False, False), 'defer before limit');
    Check(B.AllowOptional(owImageVerification, 6000, False, False), 'starvation bound');
    Check(B.Cost(1).MaximumUS = 200000, 'wall-duration measurement');
    B.RecordCost(1, High(UInt64));
    Check(B.SpentUS = High(UInt64), 'cost overflow saturation');
  end;

  procedure TestRAMMaintenance;
  begin
    Check(R.RegisterStore(0, 64, P1.Maintain), 'register fixed store');
    Check(R.RegisterStore(1, 64, P2.Maintain), 'exact RAM budget');
    Check(not R.RegisterStore(2, 1, P2.Maintain), 'RAM registration cap');
    Check(not R.RegisterStore(0, 1, P1.Maintain), 'duplicate registration rejected');
    P1.ShouldFail := True;
    R.Maintain(1000, True);
    Check(R.CycleFailure and (P2.Calls = 1), 'failed store does not block another');
    P1.ShouldFail := False;
    R.Maintain(1001, True);
    Check(not R.CycleFailure and (P1.LastTick = 1001), 'cleanup recovery');
    R.Maintain(1002);
    Check(P2.Calls = 2, 'maintenance cadence');
    R.Clear;
    R.Maintain(3000, True);
    Check((R.ReservedBytes = 0) and (P2.Calls = 2), 'unregister before destruction');
  end;

  procedure TestEvidenceRetention;
  var
    I: Integer;
  begin
    for I := 1 to 10000 do
    begin
      E.RecordFrame(UInt64(I), 101, [dkProcess], []);
      X.RecordFrame(UInt64(I), 101, [dkProcess], []);
      C.Append(UInt64(I), 1, 30, False, [dkProcess]);
      P.Observe(1, UInt64(I), 1, False, False);
    end;
    Check((E.Count = 256) and (X.Count = 256) and
      (C.Count = 128) and (P.Count = 64), 'legacy rings bounded');
    Check(E.Recent(0, EvidenceFrame) and
      (EvidenceFrame.Sequence = 10000), 'legacy order preserved');
    E.Prune(1000000); X.Prune(1000000);
    C.Prune(1000000); P.Prune(1000000);
    Check((E.Count = 0) and (X.Count = 0) and
      (C.Count = 0) and (P.Count = 0), 'legacy evidence expiration');
    C.Append(2000, 1, 30, False, [dkProcess]);
    C.Prune(1000);
    Check(not C.Recent(0, PrivateFrame), 'backwards privacy clock clears stale frame');
    Kinds := [];
    Incidents.RecordFrame(101, 1, 1000, [dkProcess], True, True, 10, Kinds);
    Incidents.Prune(1000000);
    Check(Incidents.Count = 0, 'expired incident closes open slot');
    Incidents.RecordFrame(101, 1, 1000001, [dkProcess], True, True, 10, Kinds);
    Check(Incidents.Count = 1, 'append after incident expiry');
  end;

  procedure TestOptionalHashChain;
  var
    I: Integer;
  begin
    if HashingAvailable then
    begin
      for I := 1 to 300 do
        Check(H.Append(UInt64(I), 101, [dkProcess], 30, False), 'hash append');
      Check(H.Verify and (H.Count = 256), 'wrapped hash chain');
      H.Prune(60300);
      Check(H.Verify and (H.Count = 1), 'hash prefix prune preserves linkage');
      H.Prune(60301);
      Check(H.Count = 0, 'hash full expiration');
      Check(H.Append(70000, 101, [dkProcess], 10, False) and H.Verify,
        'hash chain continues after expiration');
      Inc(OptionalChecks);
    end;
  end;

  procedure TestConcurrentRing;
  begin
    // Real one-producer/one-consumer stress; no ETW or process injection.
    Producer := TRingProducer.Create(Ring);
    Producer.Start;
    ProducerStarted := True;
    N := 0; Sequence := 0; Tick := WinTick64;
    FailDeadline := NHWSaturatingAdd(Tick, 10000);
    while N < 10000 do
    begin
      if Ring.Pop(Sample) then
      begin
        Inc(N);
        Check(Sample.Event.PID = Cardinal(N), 'SPSC ordered payload');
        Check(UInt64(Sample.Serial) > Sequence, 'SPSC ordered serial');
        Sequence := Sample.Serial;
      end
      else TThread.Sleep(0);
      if WinTick64 > FailDeadline then
        raise Exception.Create('SPSC stress deadline exceeded');
    end;
    Producer.WaitFor;
    FreeAndNil(Producer);
    Check(Ring.Pending = 0, 'SPSC drained');
  end;

  procedure TestLegacyRegressions;
  begin
    // V80 runner includes earlier V70/V60/V50 regression entry points.
    Check(ValidateV80Regression(Problem, Live), 'legacy V80 chain: ' + Problem);
    Inc(OptionalChecks, Live);
    Check(ValidateRealtimeV90(Problem), 'legacy V90: ' + Problem);
    Check(ValidatePrivacyV100(Problem), 'legacy V100: ' + Problem);
    Check(ValidateSelectedV109(Problem), 'legacy selected V109: ' + Problem);
  end;

begin
  Result := False;
  Failure := '';
  PassedChecks := 0;
  OptionalChecks := 0;
  ProducerStarted := False;
  Faults := nil; U := nil; B := nil; R := nil; P1 := nil; P2 := nil;
  E := nil; X := nil; H := nil; C := nil; P := nil; S := nil;
  Incidents := nil; Ring := nil; Producer := nil;
  try
    try
      Faults := TSensorFaultIsolation.Create;
      U := TUnifiedEvidence.Create;
      B := TPerformanceBudget.Create;
      R := TRAMLifecycle.Create(128);
      P1 := TPruneProbe.Create; P2 := TPruneProbe.Create;
      E := TEvidenceChain.Create; X := TExplainableEvidence.Create;
      H := TForensicHashChain.Create;
      C := TMemoryEvidenceCapsule.Create; P := TPrivacyForensics.Create;
      S := TSensorConsensus.Create;
      Incidents := TIncidentReconstruction.Create;
      Ring := TFastEventRing.Create;
      ResolveWinPointers;

      TestNativeBounds;

      TestFaultIsolation;

      TestEvidenceRoots;

      TestPerformanceBudget;

      TestRAMMaintenance;

      TestEvidenceRetention;

      TestOptionalHashChain;

      TestConcurrentRing;

      TestLegacyRegressions;
      Result := True;
    except
      on Ex: Exception do Failure := Ex.ClassName + ': ' + Ex.Message;
    end;
  finally
    if Producer <> nil then
    begin
      Producer.Terminate;
      if ProducerStarted then Producer.WaitFor;
      Producer.Free;
    end;
    if R <> nil then R.Clear;
    Ring.Free; Incidents.Free; S.Free; P.Free; C.Free; H.Free;
    X.Free; E.Free; P2.Free; P1.Free; R.Free; B.Free; U.Free; Faults.Free;
  end;
end;

end.
