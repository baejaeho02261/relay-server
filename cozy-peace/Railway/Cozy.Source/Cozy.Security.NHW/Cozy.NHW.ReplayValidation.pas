unit Cozy.NHW.ReplayValidation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Logging;

type
  // v50: offline deterministic input. NO synthetic events are injected into
  // a live process, ETW session, handle table or protection policy.
  TReplayStep = record
    Tick: UInt64;
    ExternalCapability: Boolean;
    Observed: TDetectionKinds;
  end;

function ReplayDetections(const Steps: array of TReplayStep;
  out Emitted: TDetectionKinds; out Recorded: Integer): Boolean;
function ValidateReplayRules(out ErrorText: string): Boolean;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestReplayValidation10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils, Cozy.NHW.SignalCorrelation, Cozy.NHW.InjectionEvidence,
  Cozy.NHW.AdaptiveInspector, Cozy.NHW.EvidenceChain, Cozy.NHW.TemporalHandleGraph,
  Cozy.NHW.ThreadExecutionProvenance, Cozy.NHW.ImageCOWIntegrity,
  Cozy.NHW.ModuleOriginVerification, Cozy.NHW.ETWLossHealth, Cozy.NHW.Types;

{$IFDEF NHW_NATIVE10P_TESTS}
var ReplayFailStage10P: Integer = 0;
procedure ReplayStage10P(Stage: Integer);
begin
  if Stage = ReplayFailStage10P then
    raise Exception.Create('synthetic replay allocation/processing failure');
end;
{$ENDIF}

function ReplayDetections(const Steps: array of TReplayStep;
  out Emitted: TDetectionKinds; out Recorded: Integer): Boolean;
var
  Correlator: TSignalCorrelationMonitor;
  Injector: TInjectionEvidenceMonitor;
  Evidence: TEvidenceChain;
  Kinds, PendingKinds: TDetectionKinds;
  Flags: TEvidenceFlags;
  I: Integer;
  LastTick: UInt64;
begin
  Result := False;
  Emitted := [];
  Recorded := 0;
  // Reject malformed order before allocation or event processing.
  for I := Low(Steps) to High(Steps) do
    if I > Low(Steps) then
      if Steps[I].Tick < Steps[I - 1].Tick then Exit;
  Correlator := nil;
  Injector := nil;
  Evidence := nil;
  PendingKinds := [];
  try
{$IFDEF NHW_NATIVE10P_TESTS}
    ReplayStage10P(1);
{$ENDIF}
    Correlator := TSignalCorrelationMonitor.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
    ReplayStage10P(2);
{$ENDIF}
    Injector := TInjectionEvidenceMonitor.Create;
{$IFDEF NHW_NATIVE10P_TESTS}
    ReplayStage10P(3);
{$ENDIF}
    Evidence := TEvidenceChain.Create;
    for I := Low(Steps) to High(Steps) do
    begin
      LastTick := Steps[I].Tick;
      Kinds := Steps[I].Observed;
      Correlator.Examine(False, Steps[I].ExternalCapability, LastTick, Kinds);
      Injector.Examine(True, False, Steps[I].ExternalCapability, LastTick, Kinds);
      Flags := [efReplaySynthetic];
      if Steps[I].ExternalCapability then Include(Flags, efExternalCapability);
      if (Kinds * [dkPrivateThread, dkRemoteThread]) <> [] then
        Include(Flags, efThreadOrigin);
      if (Kinds * [dkPECodeIntegrity, dkPrivateExecRegion]) <> [] then
        Include(Flags, efMemoryChange);
      Evidence.RecordFrame(LastTick, 1234, Kinds, Flags);
      PendingKinds := PendingKinds + Kinds;
{$IFDEF NHW_NATIVE10P_TESTS}
      ReplayStage10P(4);
{$ENDIF}
    end;
    Emitted := PendingKinds;
    Recorded := Evidence.Count;
    Result := True;
  finally
    Evidence.Free;
    Injector.Free;
    Correlator.Free;
  end;
end;

function ValidateReplayRules(out ErrorText: string): Boolean;
var
  Steps: array[0..2] of TReplayStep;
  Kinds: TDetectionKinds;
  Count: Integer;
  Schedule: TAdaptiveInspector;
  Graph: TTemporalHandleGraph;
  Holder: TTargetHolder;
  Evidence: TEvidenceChain;
  Frame: TEvidenceFrame;
  Before, After: TETWLossSnapshot;
  procedure Check(Condition: Boolean; const Reason: string);
  begin
    if not Condition then raise Exception.Create(Reason);
  end;
  procedure TestPureDetectionRules;
  begin
    Check(ProvenanceConfirmed(True, 2, 100, 200), 'v43 true sequence');
    Check(not ProvenanceConfirmed(False, 2, 100, 200), 'v43 startup excluded');
    Check(IsConfirmedCOW(True, False, 2, True), 'v44 confirmed transition');
    Check(not IsConfirmedCOW(True, False, 1, True), 'v44 no single scan');
    Check(HandleSequenceRisk(100, 200, 2, 300), 'v45 ordered evidence');
    Check(not HandleSequenceRisk(200, 100, 3, 300), 'v45 reversed order');
    Check(ModuleOriginCandidate('C:\Users\A\AppData\Local\Temp\q.dll',
      '\Device\HarddiskVolume1\Users\A\AppData\Local\Temp\q.dll',
      True, False, True), 'v46 unsigned staging candidate');
    Check(not ModuleOriginCandidate('C:\Tools\q.dll',
      '\Device\HarddiskVolume1\Tools\q.dll',
      True, False, True), 'v46 unsigned ordinary is not detection');
    Before := Default(TETWLossSnapshot);
    Before.Available := True;
    Before.EventsLost := 2;
    After := Before;
    After.RealTimeBuffersLost := 1;
    Check(TraceCountersAdvanced(Before, After), 'v47 loss counter');
    Check(not TraceCountersAdvanced(After, After), 'v47 no new loss');
    Check(AdaptiveInterval(True) < AdaptiveInterval(False), 'v48 hot faster');
    Check(DueAfter(100, 9000, 8000), 'v48 cold due');
    Check(not DueAfter(100, 500, 8000), 'v48 cold not due');
  end;

  procedure TestInspectionCadence;
  begin
    Schedule := TAdaptiveInspector.Create;
    Check(Schedule.ShouldInspect(False, False, 100), 'v48 initial');
    Schedule.CompleteInspection(0, 100, True);
    Check(not Schedule.ShouldInspect(False, False, 200), 'v48 no duplicate');
    Check(Schedule.ShouldInspect(False, True, 2200), 'v48 hot triggered');
    Schedule.CompleteInspection(0, 2200, True);
  end;

  procedure TestAccessSequence;
  begin
    Graph := TTemporalHandleGraph.Create;
    Holder := Default(TTargetHolder);
    Holder.PID := 2233;
    Holder.CreateTime := 4567;
    Holder.RightsUnion := ACCESS_QUERY_INFORMATION;
    Kinds := [];
    Graph.Observe(Holder, False, 100, Kinds);
    Holder.RightsUnion := ACCESS_VM_WRITE;
    Graph.Observe(Holder, False, 200, Kinds);
    Check(not (dkTemporalHandleGraph in Kinds), 'v45 requires repeat');
    Graph.Observe(Holder, False, 300, Kinds);
    Check(dkTemporalHandleGraph in Kinds, 'v45 repeated escalation');
  end;

  procedure TestEvidenceHistory;
  var
    I: Integer;
  begin
    Evidence := TEvidenceChain.Create;
    for I := 0 to 300 do
      Evidence.RecordFrame(I + 1, 1234, [dkProcess], []);
    Check(Evidence.Count = 256, 'v49 bounded history');
    Check(Evidence.Recent(0, Frame) and (Frame.Sequence = 301),
      'v49 newest');
    Check(Evidence.Recent(255, Frame) and (Frame.Sequence = 46),
      'v49 oldest');
    Check(not Evidence.Recent(256, Frame), 'v49 bounds');
  end;

  procedure TestReplayOrdering;
  begin
    Steps[0] := Default(TReplayStep);
    Steps[0].Tick := 1000;
    Steps[0].ExternalCapability := True;
    Steps[1] := Default(TReplayStep);
    Steps[1].Tick := 1100;
    Steps[1].Observed := [dkPrivateThread];
    Steps[2] := Default(TReplayStep);
    Steps[2].Tick := 1200;
    Steps[2].Observed := [dkPECodeIntegrity];
    Check(ReplayDetections(Steps, Kinds, Count), 'v50 replay');
    Check((dkMultiSignal in Kinds) and (dkInjectionEvidence in Kinds),
      'v50 correlation and injection evidence');
    Check(Count = 3, 'v50 event count');
    Steps[2].Tick := 900;
    Check(not ReplayDetections(Steps, Kinds, Count), 'v50 unordered refused');
    Check((Kinds = []) and (Count = 0), 'v50 failure outputs empty');
  end;

begin
  Result := False;
  ErrorText := '';
  Schedule := nil;
  Graph := nil;
  Evidence := nil;
  try
    TestPureDetectionRules;
    TestInspectionCadence;
    TestAccessSequence;
    TestEvidenceHistory;
    TestReplayOrdering;
    Result := True;
  except
    on E: Exception do ErrorText := E.Message;
  end;
  Evidence.Free;
  Graph.Free;
  Schedule.Free;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.ReplayValidation.inc}
{$ENDIF}

end.
