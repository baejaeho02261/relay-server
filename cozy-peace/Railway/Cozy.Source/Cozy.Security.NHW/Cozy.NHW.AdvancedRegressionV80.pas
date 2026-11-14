unit Cozy.NHW.AdvancedRegressionV80;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

function ValidateV80StateSequences(out Failure: string; out Checks: Integer): Boolean;

function ValidateV80Regression(out Failure: string;
  out OptionalLiveChecks: Integer): Boolean;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestAdvancedRegressionV8010Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.Logging, Cozy.NHW.AdvancedRegression,
  Cozy.NHW.MultiEpochBaseline, Cozy.NHW.CodeProvenanceGraph,
  Cozy.NHW.SectionCorrelation, Cozy.NHW.IndirectTargets,
  Cozy.NHW.ThreadTimeline, Cozy.NHW.CausalGraph,
  Cozy.NHW.ObservationTrust, Cozy.NHW.ResourceController,
  Cozy.NHW.IncidentReconstruction;

function ValidateV80StateSequences(out Failure: string; out Checks: Integer): Boolean;
var
  B: TMultiEpochBaseline;
  C: TCausalAttackGraph;
  O: TObservationTrust;
  M, Failed: TModuleEpochView;
  D: TDetectionKinds;
  procedure Check(Value: Boolean; const Description: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Description);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  B := nil; C := nil; O := nil;
  try
    try
      B := TMultiEpochBaseline.Create;
      C := TCausalAttackGraph.Create;
      O := TObservationTrust.Create;
      M := Default(TModuleEpochView); M.Valid := True;
      M.Count := 1; M.Bases[0] := $180000000;
      Failed := Default(TModuleEpochView);
      B.FeedSample(M, 1000); B.FeedSample(M, 5000);
      Check(B.Stable and (B.Epoch = 1), 'state baseline accepted');
      M.Bases[0] := $180100000;
      B.FeedSample(M, 6000); B.FeedSample(M, 6000);
      Check((B.Epoch = 1) and not B.Stable, 'duplicate cannot approve epoch');
      B.FeedSample(Failed, 7000);
      Check((B.Epoch = 1) and not B.Stable, 'gap preserves approved epoch only');
      B.FeedSample(M, 8000); B.FeedSample(M, 8000);
      Check(B.Epoch = 1, 'post-gap duplicate does not use old candidate');
      B.FeedSample(M, 9000);
      Check((B.Epoch = 2) and not B.Stable, 'two new samples approve candidate');
      B.FeedSample(M, 12000); Check(B.Stable, 'new epoch settles');
      M.Bases[0] := $180200000;
      B.FeedSample(M, 13000); B.FeedSample(M, 12500);
      Check(B.Epoch = 2, 'reverse time interrupts candidate');
      B.FeedSample(M, 12500); Check(B.Epoch = 2, 'reverse-time duplicate not confirmation');
      B.FeedSample(M, 14000); Check(B.Epoch = 3, 'fresh sample after boundary');

      D := [];
      C.Examine(True, False, True, True, 456, 1, True, [], 1000, D);
      C.Examine(True, False, True, True, 456, 2, False, [dkPECodeIntegrity], 2000, D);
      C.Examine(True, False, True, True, 456, 2, False, [dkPrivateThread], 3000, D);
      Check(not (dkCausalSequence in D), 'epoch transition cannot bridge causal phases');
      C.Examine(True, False, True, True, 456, 2, True, [], 4000, D);
      C.Examine(True, False, True, True, 456, 2, False, [dkPECodeIntegrity], 5000, D);
      C.Examine(True, False, True, True, 456, 2, False, [dkPrivateThread], 6000, D);
      Check(dkCausalSequence in D, 'complete new-epoch sequence remains detected');
      C.Reset; D := [];
      C.Examine(True, False, True, True, 456, 1, True, [], 1000, D);
      C.Examine(True, False, True, True, 456, 1, False, [dkPECodeIntegrity], 2000, D);
      C.Examine(True, False, True, False, 456, 1, False, [], 2500, D);
      C.Examine(True, False, True, True, 456, 1, False, [dkPrivateThread], 3000, D);
      Check(not (dkCausalSequence in D), 'failed trust observation breaks causal sequence');
      C.Reset; D := [];
      C.Examine(True, False, True, True, 456, 1, True, [], 1000, D);
      C.Examine(True, False, True, True, 456, 1, False, [dkPECodeIntegrity], 1000, D);
      C.Examine(True, False, True, True, 456, 1, False, [dkPrivateThread], 1001, D);
      Check(not (dkCausalSequence in D), 'same-time phases cannot establish order');
      C.Examine(True, False, True, True, 456, 1, False, [dkPECodeIntegrity], 2000, D);
      C.Examine(True, False, True, True, 456, 1, False, [dkPrivateThread], 500, D);
      C.Examine(True, False, True, True, 456, 1, False, [dkPrivateThread], 3000, D);
      Check(not (dkCausalSequence in D), 'reverse-time phase discarded');

      D := [];
      O.Examine(True, True, True, True, False, 1000, 1000, 1000, D);
      O.Examine(True, True, True, True, True, 1000, 1000, 2000, D);
      O.Examine(True, True, True, True, True, 1000, 1000, 2000, D);
      O.Examine(True, True, True, True, True, 1000, 1000, 2000, D);
      Check(D = [], 'duplicate degraded samples do not reach threshold');
      O.Examine(True, True, True, True, True, 1000, 1000, 1500, D);
      Check((D = []) and (O.Current = ogUnknown), 'backwards timestamp resets trust run');
      O.Examine(True, True, True, True, False, 1000, 1000, 3000, D);
      O.Examine(True, True, True, True, True, 1000, 1000, 4000, D);
      O.Examine(True, True, True, True, True, 1000, 1000, 5000, D);
      Check(D = [], 'no premature warning after recovery');
      O.Examine(True, True, True, True, True, 1000, 1000, 6000, D);
      Check(dkObservationUncertain in D, 'three fresh degraded observations still warn');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    O.Free; C.Free; B.Free;
  end;
end;

function ValidateV80Regression(out Failure: string;
  out OptionalLiveChecks: Integer): Boolean;
var
  Live, SequenceChecks: Integer;
  SequenceFailure: string;
  B: TMultiEpochBaseline;
  M: TModuleEpochView;
  C: TCausalAttackGraph;
  O: TObservationTrust;
  R: TResourceAwareController;
  I: TIncidentReconstruction;
  K: TDetectionKinds;
  Incident: TInMemoryIncident;
  S: TCorrelatedSequence;
  procedure Check(Pass: Boolean; const MessageText: string);
  begin
    if not Pass then raise Exception.Create(MessageText);
  end;
  procedure TestEarlierVersionChains;
  begin
    Check(ValidateV70Regression(Failure, Live),
      'v70 regression: ' + Failure);
    Inc(OptionalLiveChecks, Live);
    Check(ValidateV80StateSequences(SequenceFailure, SequenceChecks),
      'v80 continuous-state regression: ' + SequenceFailure);
    Check(SequenceChecks > 0, 'v80 actual state objects exercised');
  end;

  procedure TestModuleEpochs;
  begin
    B := TMultiEpochBaseline.Create;
    M := Default(TModuleEpochView);
    M.Valid := True;
    M.Count := 1;
    M.Bases[0] := $180000000;
    B.FeedSample(M, 1000);
    Check((B.Epoch = 1) and not B.Stable, 'v72 priming');
    B.FeedSample(M, 5000);
    Check(B.Stable and (B.Epoch = 1), 'v72 stable baseline');
    M.Bases[0] := $180100000;
    B.FeedSample(M, 6000);
    Check((B.Epoch = 1) and not B.Stable, 'v72 transient module');
    B.FeedSample(M, 7000);
    Check((B.Epoch = 2) and not B.Stable, 'v72 new epoch');
    B.FeedSample(M, 11000);
    Check(B.Stable, 'v72 second epoch stable');
    M.Valid := False;
    B.FeedSample(M, 12000);
    Check(not B.Stable and (B.Epoch = 2),
      'v72 incomplete snapshot cannot advance epoch');
  end;

  procedure TestExecutionCandidates;
  begin
    Check(CodeProvenanceCandidate(True, 2, True, True),
      'v73 corroborated private start');
    Check(not CodeProvenanceCandidate(True, 1, True, True),
      'v73 single observation rejected');
    Check(SectionCorrelationCandidate(True, True, 2, True,
      True, True, True), 'v74 corroborated section context');
    Check(not SectionCorrelationCandidate(True, True, 2,
      True, False, True, True), 'v74 absent mapping context');
    Check(IndirectTargetCandidate(True, True, 2, True, True),
      'v75 callback provenance');
    Check(not IndirectTargetCandidate(False, True, 2, True,
      True), 'v75 baseline private callback ignored');
    Check(ThreadTimelineCandidate(True, True, 2, True, True,
      True), 'v76 thread timeline');
    Check(not ThreadTimelineCandidate(False, True, 2, True,
      True, True), 'v76 preexisting thread');
  end;

  procedure TestCausalOrdering;
  begin
    C := TCausalAttackGraph.Create;
    K := [];
    C.Examine(True, False, True, True, 456, 2, True, [], 1000, K);
    C.Examine(True, False, True, True, 456, 2, False,
      [dkPECodeIntegrity], 2000, K);
    C.Examine(True, False, True, True, 456, 2, False,
      [dkPrivateThread], 3000, K);
    Check(dkCausalSequence in K, 'v71 ordered causal sequence');
    S := C.LastSequence;
    Check(S.ConfirmedTemporalOrder and (S.ActorPID = 0),
      'v71 unattributed sequence');
    Check(not CausalSequenceCandidate(2000, 1000, 3000,
      True, True), 'v71 reverse order rejected');
    Check(not CausalSequenceCandidate(1000, 2000, 3000,
      True, False), 'v71 weak visibility rejected');
  end;

  procedure TestObservationTrust;
  begin
    Check(GradeObservation(True, True, True, True, False,
      1000, 1000) = ogReliable, 'v77 trusted observation');
    Check(GradeObservation(True, True, True, True, True,
      1000, 1000) = ogDegraded, 'v77 loss downgrades');
    O := TObservationTrust.Create;
    K := [];
    O.Examine(True, True, True, True, False, 1000, 1000, 500, K);
    O.Examine(True, True, True, True, True, 1000, 1000, 1000, K);
    O.Examine(True, True, True, True, True, 1000, 1000, 2000, K);
    Check(K = [], 'v77 no premature warning');
    O.Examine(True, True, True, True, True, 1000, 1000, 3000, K);
    Check(dkObservationUncertain in K, 'v77 sustained uncertainty');
    O.Reset;
    K := [];
    O.Examine(True, True, True, False, False, 0, 1000, 4000, K);
    O.Examine(True, True, True, False, False, 0, 1000, 5000, K);
    O.Examine(True, True, True, False, False, 0, 1000, 6000, K);
    Check(not (dkObservationUncertain in K),
      'v77 optional ETW unavailable is unknown');
  end;

  procedure TestResourceCadence;
  begin
    R := TResourceAwareController.Create;
    Check(OptionalInspectionInterval(slNormal) = 8000,
      'v78 normal cadence');
    Check(OptionalInspectionInterval(slDegraded) = 15000,
      'v78 degraded cadence');
    Check(not IsSensorUnderPressure(100, 900, 1000),
      'v78 normal sampling');
    Check(R.ShouldRunHeavy(False, 1000), 'v78 first scan');
    Check(not R.ShouldRunHeavy(False, 1200), 'v78 bounded scan');
  end;

  procedure TestIncidentHistory;
  var
    J: Integer;
  begin
    I := TIncidentReconstruction.Create;
    K := [];
    I.RecordFrame(456, 2, 1000, [dkProcess], True,
      True, 78, K);
    I.RecordFrame(456, 2, 2000,
      [dkPECodeIntegrity, dkPrivateThread], False,
      True, 78, K);
    Check(dkIncidentReconstruction in K, 'v79 independent incident');
    Check(I.Count = 1, 'v79 merge same epoch');
    Check(I.Recent(0, Incident) and
      (Incident.ActorPID = 0) and (Incident.Observations = 2),
      'v79 bounded RAM incident');
    K := [];
    I.RecordFrame(456, 3, 4000, [dkProcess], False,
      True, 78, K);
    Check(I.Count = 2, 'v79 distinct epochs never merge');
    Check(not IncidentCandidate([ifExternal, ifMemory],
      2, 90, True), 'v79 two-family rejected');
    // The incident ring remains bounded even under hostile event volume.
    for J := 1 to 100 do
    begin
      K := [];
      I.RecordFrame(456, Cardinal(20 + J),
        UInt64(100000 + J * 20000),
        [dkProcess], False, True, 10, K);
    end;
    Check(I.Count = 64, 'v79 bounded ring under sustained events');
    Check(I.Recent(0, Incident) and
      (Incident.Epoch = 120), 'v79 newest incident retained');
    Check(not I.Recent(64, Incident), 'v79 out-of-range rejected');
    Check(IncidentCandidate([ifExternal, ifMemory, ifThread],
      2, 70, True), 'v79 three-family candidate');
  end;

begin
  Result := False;
  Failure := '';
  OptionalLiveChecks := 0;
  B := nil;
  C := nil;
  O := nil;
  R := nil;
  I := nil;
  try
    TestEarlierVersionChains;
    TestModuleEpochs;
    TestExecutionCandidates;
    TestCausalOrdering;
    TestObservationTrust;
    TestResourceCadence;
    TestIncidentHistory;
    Result := True;
  except
    on E: Exception do Failure := E.Message;
  end;
  I.Free;
  R.Free;
  O.Free;
  C.Free;
  B.Free;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.AdvancedRegressionV80.inc}
{$ENDIF}

end.
