unit Cozy.NHW.AdaptiveAnomaly;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TAnomalyState = record
    Tick: UInt64;
    ValidSamples: Cardinal;
    MeanX8: Cardinal;        // edges per second, scaled by 8 (not per scan)
    LastCount: Cardinal;     // original observed edge count, kept for callers
    AnomalyCount: Cardinal;
    Anomalous: Boolean;
    IntervalMS: UInt64;
    RateX8: Cardinal;
    SampleValid: Boolean;
  end;

  // Bounded, elapsed-time-normalized learning; single monitor-thread owner.
  TAdaptiveAnomaly = class
  private
    FState: TAnomalyState;
    FAnchorTick: UInt64;
    FHaveAnchor: Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(NewEdges: Cardinal;
      Baseline, Valid: Boolean; Tick: UInt64);
    property State: TAnomalyState read FState;
  end;

// Observed is a rate in whole edges/second; MeanX8 is the scaled rate.
function NHWAnomalyCandidate(Samples: Cardinal; MeanX8,
  Observed: Cardinal): Boolean;
{$IFDEF NHW_NATIVE5J_TESTS}
function TestAnomaly5J(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation
{$IFDEF NHW_NATIVE5J_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  ANOMALY_MIN_INTERVAL_MS = 50;
  ANOMALY_MAX_INTERVAL_MS = 30000;
  ANOMALY_TIME_CONSTANT_MS = 8000;
  ANOMALY_MAX_LEARNING_RATE_X8 = 4096 * 8;

function RateCandidate(Samples, MeanX8: Cardinal; RateX8: UInt64): Boolean;
var ThresholdX8: UInt64;
begin
  ThresholdX8 := UInt64(MeanX8) * 4 + 48;
  if ThresholdX8 < 64 then ThresholdX8 := 64;
  Result := (Samples >= 8) and (RateX8 >= ThresholdX8) and
    (RateX8 > UInt64(MeanX8) + 32);
end;

function NHWAnomalyCandidate(Samples, MeanX8, Observed: Cardinal): Boolean;
begin Result := RateCandidate(Samples, MeanX8, UInt64(Observed) * 8); end;

constructor TAdaptiveAnomaly.Create;
begin inherited Create; Reset; end;

procedure TAdaptiveAnomaly.Reset;
begin
  FState := Default(TAnomalyState);
  FAnchorTick := 0;
  FHaveAnchor := False;
end;

procedure TAdaptiveAnomaly.Observe(NewEdges: Cardinal;
  Baseline, Valid: Boolean; Tick: UInt64);
var
  Elapsed, Rate: UInt64;

  function TryBuildRateSample: Boolean;
  begin
    if Baseline or not Valid then
    begin FHaveAnchor := False; Exit(False); end;
    if not FHaveAnchor then
    begin
      FAnchorTick := Tick;
      FHaveAnchor := True;
      Exit(False); // no duration for the first count: do not train or classify it
    end;
    if Tick <= FAnchorTick then
    begin FHaveAnchor := False; Exit(False); end;
    Elapsed := Tick - FAnchorTick;
    FAnchorTick := Tick;
    if (Elapsed < ANOMALY_MIN_INTERVAL_MS) or
       (Elapsed > ANOMALY_MAX_INTERVAL_MS) then
    begin FHaveAnchor := False; Exit(False); end;
    // Cardinal * 8000 fits UInt64; divide BEFORE narrowing.
    Rate := (UInt64(NewEdges) * 8000) div Elapsed;
    if Rate > UInt64(High(Cardinal)) then Rate := High(Cardinal);
    FState.RateX8 := Cardinal(Rate);
    FState.IntervalMS := Elapsed;
    FState.SampleValid := True;
    Result := True;
  end;

  function ClassifySampleForLearning: Boolean;
  begin
    FState.Anomalous := RateCandidate(FState.ValidSamples, FState.MeanX8, Rate);
    if FState.Anomalous then
    begin
      if FState.AnomalyCount < High(Cardinal) then Inc(FState.AnomalyCount);
      Exit(False); // exclude anomalous frames from training
    end;
    Result := True;
  end;

  procedure LearnNormalRate;
  var
    Weight, SampleX8: UInt64;
  begin
    SampleX8 := Rate;
    if SampleX8 > ANOMALY_MAX_LEARNING_RATE_X8 then
      SampleX8 := ANOMALY_MAX_LEARNING_RATE_X8;
    Weight := Elapsed;
    if Weight > ANOMALY_TIME_CONSTANT_MS then Weight := ANOMALY_TIME_CONSTANT_MS;
    if FState.ValidSamples = 0 then
      FState.MeanX8 := Cardinal(SampleX8)
    else
      FState.MeanX8 := Cardinal((UInt64(FState.MeanX8) *
        (UInt64(ANOMALY_TIME_CONSTANT_MS) - Weight) + SampleX8 * Weight) div
        ANOMALY_TIME_CONSTANT_MS);
    if FState.ValidSamples < High(Cardinal) then Inc(FState.ValidSamples);
  end;

begin
  FState.Tick := Tick;
  FState.LastCount := NewEdges;
  FState.Anomalous := False;
  FState.SampleValid := False;
  FState.IntervalMS := 0;
  FState.RateX8 := 0;
  if not TryBuildRateSample then Exit;
  if not ClassifySampleForLearning then Exit;
  LearnNormalRate;
end;

{$IFDEF NHW_NATIVE5J_TESTS}
{$I Cozy.NHW.Native5J.Anomaly.inc}
{$ENDIF}
end.
