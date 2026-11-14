unit Cozy.NHW.SensorTamperHealth;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TSensorHealthConcern = (shNone, shTraceStopped,
    shThreadSnapshotMissing, shProlongedScanGap, shEventLoss);

  // Detects persistent sensor COVERAGE degradation, not a proved attacker.
  // The ETW provider may never be available: that is not tampering.
  TSensorTamperHealth = class
  private
    FTraceEverReady: Boolean;
    FTraceMissingScans: Cardinal;
    FThreadMissingScans: Cardinal;
    FLastDropTotal: Cardinal;
    FLastWarning: UInt64;
    FLastReason: TSensorHealthConcern;
    FLastTick: UInt64;
    FHaveTick: Boolean;
    procedure ResetObservationBoundary(TraceReady: Boolean;
      DropTotal: Cardinal; Tick: UInt64);
    function UpdateTraceHealth(TraceReady: Boolean): TSensorHealthConcern;
    function UpdateThreadHealth(ThreadWatchEnabled,
      ThreadSnapshotValid: Boolean): TSensorHealthConcern;
    function CoverageConcern(TraceReady, TraceGap: Boolean;
      DropTotal: Cardinal; ScanGapMS: UInt64;
      IntervalMS: Cardinal): TSensorHealthConcern;
    function WarningDue(Tick: UInt64): Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(TraceReady, TraceGap, ThreadWatchEnabled,
      ThreadSnapshotValid, Baseline: Boolean; DropTotal: Cardinal;
      ScanGapMS: UInt64; IntervalMS: Cardinal; Tick: UInt64;
      var Detected: TDetectionKinds);
    property LastReason: TSensorHealthConcern read FLastReason;
  end;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestSensorTamperHealth10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10Q_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  SENSOR_WARNING_COOLDOWN_MS = 30000;

constructor TSensorTamperHealth.Create;
begin
  inherited Create;
  Reset;
end;

procedure TSensorTamperHealth.Reset;
begin
  FTraceEverReady := False;
  FTraceMissingScans := 0;
  FThreadMissingScans := 0;
  FLastDropTotal := 0;
  FLastWarning := 0;
  FLastReason := shNone;
  FLastTick := 0;
  FHaveTick := False;
end;

procedure TSensorTamperHealth.ResetObservationBoundary(
  TraceReady: Boolean; DropTotal: Cardinal; Tick: UInt64);
begin
  FTraceEverReady := TraceReady;
  FTraceMissingScans := 0;
  FThreadMissingScans := 0;
  FLastDropTotal := DropTotal;
  FLastReason := shNone;
  FLastTick := Tick;
  FHaveTick := Tick <> 0;
end;

function TSensorTamperHealth.UpdateTraceHealth(
  TraceReady: Boolean): TSensorHealthConcern;
begin
  Result := shNone;
  if TraceReady then
  begin
    FTraceEverReady := True;
    FTraceMissingScans := 0;
  end
  else if FTraceEverReady then
  begin
    if FTraceMissingScans < High(Cardinal) then Inc(FTraceMissingScans);
    if FTraceMissingScans >= 3 then Result := shTraceStopped;
  end;
end;

function TSensorTamperHealth.UpdateThreadHealth(ThreadWatchEnabled,
  ThreadSnapshotValid: Boolean): TSensorHealthConcern;
begin
  Result := shNone;
  if ThreadWatchEnabled and not ThreadSnapshotValid then
  begin
    if FThreadMissingScans < High(Cardinal) then Inc(FThreadMissingScans);
    if FThreadMissingScans >= 3 then Result := shThreadSnapshotMissing;
  end
  else
    FThreadMissingScans := 0;
end;

function TSensorTamperHealth.CoverageConcern(TraceReady,
  TraceGap: Boolean; DropTotal: Cardinal; ScanGapMS: UInt64;
  IntervalMS: Cardinal): TSensorHealthConcern;
begin
  Result := shNone;
  if (IntervalMS > 0) and (ScanGapMS > UInt64(IntervalMS) * 6) then
    Exit(shProlongedScanGap);
  if (TraceReady and TraceGap) or (DropTotal > FLastDropTotal) then
    Result := shEventLoss;
end;

function TSensorTamperHealth.WarningDue(Tick: UInt64): Boolean;
begin
  Result := (FLastWarning = 0) or (Tick < FLastWarning) or
    (Tick - FLastWarning >= SENSOR_WARNING_COOLDOWN_MS);
end;

procedure TSensorTamperHealth.Observe(TraceReady, TraceGap,
  ThreadWatchEnabled, ThreadSnapshotValid, Baseline: Boolean;
  DropTotal: Cardinal; ScanGapMS: UInt64; IntervalMS: Cardinal;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Concern, Candidate: TSensorHealthConcern;
  GapLimit: UInt64;
begin
  if Baseline or (Tick = 0) or (FHaveTick and (Tick < FLastTick)) then
  begin
    ResetObservationBoundary(TraceReady, DropTotal, Tick);
    Exit; // preserve warning cooldown, but do not bridge baseline/clock gaps
  end;
  if FHaveTick and (Tick = FLastTick) then Exit;
  GapLimit := UInt64(IntervalMS) * 6;
  if GapLimit < 30000 then GapLimit := 30000;
  if FHaveTick and (Tick - FLastTick > GapLimit) then
  begin
    FTraceMissingScans := 0;
    FThreadMissingScans := 0;
  end;
  FLastTick := Tick;
  FHaveTick := True;

  Concern := UpdateTraceHealth(TraceReady);
  Candidate := UpdateThreadHealth(ThreadWatchEnabled, ThreadSnapshotValid);
  if (Concern = shNone) and (Candidate <> shNone) then Concern := Candidate;
  Candidate := CoverageConcern(TraceReady, TraceGap, DropTotal,
    ScanGapMS, IntervalMS);
  if (Concern = shNone) and (Candidate <> shNone) then Concern := Candidate;
  FLastDropTotal := DropTotal;

  if Concern = shNone then
  begin
    FLastReason := shNone;
    Exit;
  end;
  FLastReason := Concern;
  if WarningDue(Tick) then
  begin
    // Preserve legacy output policy: this is ONLY "Waring Detect".
    Include(Detected, dkObservationUncertain);
    FLastWarning := Tick;
  end;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.SensorTamperHealth.inc}
{$ENDIF}

end.
