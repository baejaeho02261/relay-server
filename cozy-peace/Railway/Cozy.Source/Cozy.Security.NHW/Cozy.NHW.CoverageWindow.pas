unit Cozy.NHW.CoverageWindow;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TCoverageStats = record
    Samples: Cardinal;
    SlowIntervals: Cardinal;
    EstimatedMissed: UInt64;
    LastSlowTick: UInt64;
  end;

  // v57: measures polling uncertainty, NOT evidence of an attacker.
  TCoverageWindowMonitor = class
  private
    FStats: TCoverageStats;
    FWindowStart: UInt64;
    FLastReport: UInt64;
    FLastSample: UInt64;
    FHaveWindow, FHaveSample, FHaveReport: Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(ScanMS, GapMS: UInt64; IntervalMS: Cardinal;
      ETWLoss: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
    property Stats: TCoverageStats read FStats;
  end;

function CoverageIntervalSlow(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal): Boolean;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestCoverageWindow10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10P_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  COVERAGE_WINDOW_MS = 60000;
  COVERAGE_COOLDOWN_MS = 30000;

function CoverageIntervalSlow(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal): Boolean;
var Interval: UInt64;
begin
  Interval := IntervalMS;
  if Interval < 250 then Interval := 250;
  Result := (ScanMS > Interval * 3) or (GapMS > Interval * 5);
end;

constructor TCoverageWindowMonitor.Create;
begin inherited Create; Reset; end;

procedure TCoverageWindowMonitor.Reset;
begin
  FStats := Default(TCoverageStats);
  FWindowStart := 0;
  FLastReport := 0;
  FLastSample := 0;
  FHaveWindow := False;
  FHaveSample := False;
  FHaveReport := False;
end;

procedure TCoverageWindowMonitor.Examine(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal; ETWLoss: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Interval: UInt64;

  function AcceptSampleTick: Boolean;
  begin
    Result := False;
    if FHaveSample and (Tick <= FLastSample) then
    begin
      if Tick < FLastSample then
      begin
        Reset;
        // Establish the new clock anchor, but do not count the reversed frame.
        FHaveSample := True;
        FLastSample := Tick;
      end;
      Exit;
    end;
    FHaveSample := True;
    FLastSample := Tick;
    Result := True;
  end;

  procedure StartWindowIfNeeded;
  begin
    if not FHaveWindow or (Tick < FWindowStart) or
       (Tick - FWindowStart >= COVERAGE_WINDOW_MS) then
    begin
      FHaveWindow := True;
      FWindowStart := Tick;
      FStats := Default(TCoverageStats);
    end;
  end;

  procedure RecordCoverageInterval;
  var
    Missed: UInt64;
  begin
    if FStats.Samples < High(Cardinal) then Inc(FStats.Samples);
    Interval := IntervalMS;
    if Interval < 250 then Interval := 250;
    if not CoverageIntervalSlow(ScanMS, GapMS, IntervalMS) then Exit;
    if FStats.SlowIntervals < High(Cardinal) then Inc(FStats.SlowIntervals);
    FStats.LastSlowTick := Tick;
    if GapMS <= Interval then Exit;
    Missed := (GapMS div Interval) - 1;
    if Missed > High(UInt64) - FStats.EstimatedMissed then
      FStats.EstimatedMissed := High(UInt64)
    else
      Inc(FStats.EstimatedMissed, Missed);
  end;

  procedure ReportCoverageIfDue;
  begin
    if (FStats.SlowIntervals < 3) and
       (not ETWLoss or (FStats.SlowIntervals < 1)) then Exit;
    if FHaveReport and (Tick >= FLastReport) and
       (Tick - FLastReport < COVERAGE_COOLDOWN_MS) then Exit;
    Include(Detected, dkCoverageGap);
    FLastReport := Tick;
    FHaveReport := True;
  end;
begin
  if not AcceptSampleTick then Exit;
  if IntervalMS = 0 then Exit;
  StartWindowIfNeeded;
  RecordCoverageInterval;
  ReportCoverageIfDue;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.CoverageWindow.inc}
{$ENDIF}

end.
