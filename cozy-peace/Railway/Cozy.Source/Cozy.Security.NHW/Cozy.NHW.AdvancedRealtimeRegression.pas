unit Cozy.NHW.AdvancedRealtimeRegression;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

function ValidateRealtimeV90(out Failure: string): Boolean;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestAdvancedRealtimeRegression10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils,
  Cozy.NHW.ETWTypes,
  Cozy.NHW.Logging,
  Cozy.NHW.FastEventRing,
  Cozy.NHW.EventDrivenWake,
  Cozy.NHW.RealtimeFusion,
  Cozy.NHW.FastPipeline,
  Cozy.NHW.MicroburstAccess,
  Cozy.NHW.TriggeredSnapshot,
  Cozy.NHW.MemoryDelta,
  Cozy.NHW.SensorRecovery,
  Cozy.NHW.RealtimeBenchmark,
  Cozy.NHW.HighResolutionClock;

{$IFDEF NHW_NATIVE10P_TESTS}
var RealtimeFailStage10P: Integer = 0;
procedure RealtimeStage10P(Stage: Integer);
begin
  if Stage = RealtimeFailStage10P then
    raise Exception.Create('synthetic realtime construction failure');
end;
{$ENDIF}

procedure Ensure(Condition: Boolean; const MessageText: string);
begin
  if not Condition then raise Exception.Create(MessageText);
end;

function ValidateRealtimeV90(out Failure: string): Boolean;
var
  Ring: TFastEventRing;
  Queue: TFastKernelSampleList;
  Fusion: TRealtimeFusion;
  Wake: TEventDrivenWake;
  Pipeline: TFastDeferredPipeline;
  Burst: TMicroburstAccess;
  Snap: TTriggeredSnapshot;
  Delta: TIncrementalMemoryDelta;
  Recovery: TSensorCoverageRecovery;
  Bench: TRealtimeBenchmark;
  Metrics: TRealtimeMetrics;
  E: TKernelEvent;
  S: TFastKernelSample;
  Kinds: TDetectionKinds;
  Relevant: Boolean;
  procedure TestEventRing;
  var
    I: Integer;
  begin
    E := Default(TKernelEvent);
    E.Kind := keThreadStart;
    E.PID := 42;
    E.Tick := 1200;
    // Exactly CAPACITY - 1 slots are usable in this SPSC scheme.
    for I := 1 to NHW_FAST_RING_CAPACITY - 1 do
    begin
      E.ThreadID := Cardinal(I);
      Ensure(Ring.Push(E, I), 'ring should accept ' + IntToStr(I));
    end;
    Ensure(not Ring.Push(E, 2000), 'ring capacity limit');
    Ensure(Ring.DroppedTotal = 1, 'ring loss counter');
    Ensure(Ring.Pending = NHW_FAST_RING_CAPACITY - 1, 'ring pending');
    for I := 1 to NHW_FAST_RING_CAPACITY - 1 do
    begin
      Ensure(Ring.Pop(S), 'ring pop');
      Ensure(S.Event.ThreadID = Cardinal(I), 'ring FIFO order');
    end;
    Ensure(not Ring.Pop(S), 'ring empty');
    E.ThreadID := 3;
    Ensure(Ring.Push(E, 100), 'ring reuse after full');
    Ensure(Ring.Pop(S), 'ring pop after reuse');
  end;

  procedure TestEventCorrelation;
  begin
    Queue.Add(S);
    Fusion.Observe(Queue, 42, Relevant);
    Ensure(Relevant, 'thread is relevant');
    Ensure(not Fusion.CorrelatedWithExternal(False, 1300),
      'no external evidence');
    Ensure(Fusion.CorrelatedWithExternal(True, 1300),
      'recent thread and independent access');
    Ensure(not Fusion.CorrelatedWithExternal(True, 5000),
      'expired correlation');
  end;

  procedure TestWakeAndDeferredWork;
  begin
    Wake.Reset;
    Ensure(not Wake.MayWake(1000, 1100), 'minimum wake separation');
    Ensure(Wake.MayWake(1000, 1300), 'eligible early wake');
    Ensure(not Wake.MayWake(1300, 1400), 'wake rate limit');
    Pipeline.NotifyRelevant(3000);
    Ensure(Pipeline.Pending(3500), 'deferred work pending');
    Ensure(Pipeline.AllowDeferred(3500, False, False),
      'first heavy pass');
    Ensure(not Pipeline.AllowDeferred(3650, False, False),
      'heavy work bounded');
    Pipeline.CompleteDeferred(True);
    Ensure(not Pipeline.Pending(3600), 'completed work acknowledged');
  end;

  procedure TestActorMicrobursts;
  begin
    Burst.ObserveNewEdge(41, $20, 2000, 4100);
    Burst.ObserveNewEdge(41, $20, 2010, 4100);
    Ensure(not Burst.Correlated(2100), 'same actor not multi-actor');
    Burst.ObserveNewEdge(43, $20, 2200, 4300);
    Ensure(Burst.Correlated(2300), 'distinct actors correlated');
  end;

  procedure TestTriggeredCapture;
  begin
    Snap.SignalRelevant(4000);
    Ensure(not Snap.CorroboratedTrigger(False, 4200),
      'no snapshot for uncorroborated event');
    Ensure(Snap.CorroboratedTrigger(True, 4300),
      'snapshot independent evidence');
    Snap.CompleteAttempt(4300, False);
    Ensure(not Snap.CorroboratedTrigger(True, 4400), 'bounded skipped retry');
    Ensure(Snap.CorroboratedTrigger(True, 5300), 'skipped work retries before 6s');
    Snap.CompleteAttempt(5300, True);
    Ensure(not Snap.CorroboratedTrigger(True, 5400), 'real capture throttle');
  end;

  procedure TestDeltaAndCoverage;
  begin
    Delta.Reset;
    Delta.Examine(False, False, True, 10000);
    Ensure(Delta.ObservedTransitions = 0, 'no remote delta');
    Kinds := [];
    Recovery.Observe(False, False, 0, 0, 2000, 1000, Kinds);
    Ensure(Kinds = [], 'unavailable ETW is not an attack');
    Recovery.Observe(True, True, 0, 0, 2000, 2000, Kinds);
    Ensure(dkObservationUncertain in Kinds, 'real loss warning');
    Kinds := [];
    Recovery.Observe(True, True, 0, 0, 2000, 2100, Kinds);
    Ensure(Kinds = [], 'warning dedupe');
  end;

  procedure TestBenchmarkAndClock;
  begin
    Bench.ObserveDispatch(150, 1);
    Bench.ObserveDispatch(1500, 2);
    Bench.ObserveScan(30, 1, 5000);
    Metrics := Bench.Metrics;
    Ensure(Metrics.Samples = 1, 'benchmark scan count');
    Ensure(Metrics.EventSamples = 2, 'benchmark event count');
    Ensure((Metrics.P50DispatchUS = 200) and
           (Metrics.P95DispatchUS = 2000), 'benchmark histogram');
    Ensure(NHWQpcElapsedUS(1000, 1000) = 0, 'zero QPC latency');
  end;

begin
  Result := False;
  Failure := '';
  Ring := nil;
  Queue := nil;
  Fusion := nil;
  Wake := nil;
  Pipeline := nil;
  Burst := nil;
  Snap := nil;
  Delta := nil;
  Recovery := nil;
  Bench := nil;
  try
    try
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(1);
{$ENDIF}
    Ring := TFastEventRing.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(2);
{$ENDIF}
    Queue := TFastKernelSampleList.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(3);
{$ENDIF}
    Fusion := TRealtimeFusion.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(4);
{$ENDIF}
    Wake := TEventDrivenWake.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(5);
{$ENDIF}
    Pipeline := TFastDeferredPipeline.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(6);
{$ENDIF}
    Burst := TMicroburstAccess.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(7);
{$ENDIF}
    Snap := TTriggeredSnapshot.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(8);
{$ENDIF}
    Delta := TIncrementalMemoryDelta.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(9);
{$ENDIF}
    Recovery := TSensorCoverageRecovery.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
      RealtimeStage10P(10);
{$ENDIF}
    Bench := TRealtimeBenchmark.Create;
      TestEventRing;
      TestEventCorrelation;
      TestWakeAndDeferredWork;
      TestActorMicrobursts;
      TestTriggeredCapture;
      TestDeltaAndCoverage;
      TestBenchmarkAndClock;
      Result := True;
    except
      on X: Exception do Failure := X.Message;
    end;
  finally
    Bench.Free;
    Recovery.Free;
    Delta.Free;
    Snap.Free;
    Burst.Free;
    Pipeline.Free;
    Wake.Free;
    Fusion.Free;
    Queue.Free;
    Ring.Free;
  end;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.AdvancedRealtimeRegression.inc}
{$ENDIF}

end.
