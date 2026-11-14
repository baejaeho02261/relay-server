unit Cozy.NHW.ResourceController;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TSensorLoad = (slNormal, slHot, slDegraded);

  // v78: ONLY optional v71-v79 inspections use this scheduler. Original
  // v1-v70 inspection intervals, detection kinds and state are untouched.
  TResourceAwareController = class
  private
    FLastHeavy: UInt64;
    FHotUntil: UInt64;
    FDegradedUntil: UInt64;
    FPressureStreak: Byte;
    FLastWarning: UInt64;
    FLoad: TSensorLoad;
    FLastTick: UInt64;
    FHasTick: Boolean;
    FHasHeavy: Boolean;
    procedure ObserveClock(Tick: UInt64);
    procedure RefreshLoad(Tick: UInt64);
  public
    constructor Create;
    procedure Reset;
    procedure ObserveScan(ScanMS, GapMS: UInt64; IntervalMS: Cardinal;
      Tick: UInt64; var Detected: TDetectionKinds);
    function ShouldRunHeavy(Triggered: Boolean; Tick: UInt64): Boolean;
    property Load: TSensorLoad read FLoad;
  end;

function OptionalInspectionInterval(Load: TSensorLoad): Cardinal;
function IsSensorUnderPressure(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal): Boolean;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestResourceController10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10O_TESTS}
uses System.SysUtils;
{$ENDIF}

function OptionalInspectionInterval(Load: TSensorLoad): Cardinal;
begin
  case Load of
    slHot: Result := 2000;
    slDegraded: Result := 15000;
  else
    Result := 8000;
  end;
end;

function IsSensorUnderPressure(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal): Boolean;
var Expected: UInt64;
begin
  Expected := IntervalMS;
  if Expected < 250 then Expected := 250;
  Result := (ScanMS > Expected * 3) or
    ((GapMS <> 0) and (GapMS > Expected * 5));
end;

constructor TResourceAwareController.Create;
begin inherited Create; Reset; end;

procedure TResourceAwareController.Reset;
begin
  FLastHeavy := 0;
  FHotUntil := 0;
  FDegradedUntil := 0;
  FPressureStreak := 0;
  FLastWarning := 0;
  FLoad := slNormal;
  FLastTick := 0;
  FHasTick := False;
  FHasHeavy := False;
end;

function ResourceDeadline(Tick, Duration: UInt64): UInt64;
begin
  if Tick > High(UInt64) - Duration then Result := High(UInt64)
  else Result := Tick + Duration;
end;

procedure TResourceAwareController.ObserveClock(Tick: UInt64);
begin
  if FHasTick and (Tick < FLastTick) then Reset;
  FLastTick := Tick;
  FHasTick := True;
end;

procedure TResourceAwareController.RefreshLoad(Tick: UInt64);
begin
  if (FDegradedUntil <> 0) and (Tick <= FDegradedUntil) then
    FLoad := slDegraded
  else if (FHotUntil <> 0) and (Tick <= FHotUntil) then
    FLoad := slHot
  else
    FLoad := slNormal;
end;

procedure UpdatePressureStreak(Controller: TResourceAwareController;
  UnderPressure: Boolean);
begin
  if UnderPressure then
  begin
    if Controller.FPressureStreak < 255 then Inc(Controller.FPressureStreak);
  end
  else
    Controller.FPressureStreak := 0;
end;

procedure ApplyPressureState(Controller: TResourceAwareController;
  Tick: UInt64; var Detected: TDetectionKinds);
begin
  if Controller.FPressureStreak < 3 then Exit;
  Controller.FDegradedUntil := ResourceDeadline(Tick, 30000);
  if (Controller.FLastWarning = 0) or (Tick < Controller.FLastWarning) or
     (Tick - Controller.FLastWarning >= 30000) then
  begin
    Include(Detected, dkSensorPressure);
    Controller.FLastWarning := Tick;
  end;
end;

function HeavyInspectionDue(Controller: TResourceAwareController;
  Tick: UInt64; Interval: Cardinal): Boolean;
begin
  Result := (not Controller.FHasHeavy) or (Tick < Controller.FLastHeavy) or
    (Tick - Controller.FLastHeavy >= Interval);
end;

procedure ReserveHeavyInspection(Controller: TResourceAwareController;
  Tick: UInt64);
begin
  Controller.FLastHeavy := Tick;
  Controller.FHasHeavy := True;
end;

procedure TResourceAwareController.ObserveScan(ScanMS, GapMS: UInt64;
  IntervalMS: Cardinal; Tick: UInt64; var Detected: TDetectionKinds);
begin
  ObserveClock(Tick);
  UpdatePressureStreak(Self,
    IsSensorUnderPressure(ScanMS, GapMS, IntervalMS));
  ApplyPressureState(Self, Tick, Detected);
  RefreshLoad(Tick);
end;

function TResourceAwareController.ShouldRunHeavy(Triggered: Boolean;
  Tick: UInt64): Boolean;
var Interval: Cardinal;
begin
  ObserveClock(Tick);
  if Triggered then FHotUntil := ResourceDeadline(Tick, 20000);
  // Recompute ALL live states; expiring degraded mode must not discard
  // a hot interval that remains valid. Pressure always has priority.
  RefreshLoad(Tick);
  Interval := OptionalInspectionInterval(FLoad);
  Result := HeavyInspectionDue(Self, Tick, Interval);
  if Result then ReserveHeavyInspection(Self, Tick);
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.ResourceController.inc}
{$ENDIF}

end.
