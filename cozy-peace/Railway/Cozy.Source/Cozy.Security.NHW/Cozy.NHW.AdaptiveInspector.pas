unit Cozy.NHW.AdaptiveInspector;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TAdaptiveInspectionState = record
    LastSample, LastAttempt, ReservationTick: UInt64;
    HasSample, HasAttempt, Reserved: Boolean;
  end;

  // The two existing optional image sensors are scheduled independently.
  // Engine thread owned. Core v1-v42 cadence is not changed.
  TAdaptiveInspector = class
  private
    FStates: array[0..1] of TAdaptiveInspectionState;
    FHotUntil, FLastTick: UInt64;
    FHaveTick, FHot: Boolean;
  public
    constructor Create;
    procedure Reset;
    function ShouldInspect(Baseline, Triggered: Boolean;
      Tick: UInt64; SensorIndex: Integer = 0): Boolean;
    procedure CompleteInspection(SensorIndex: Integer;
      ReservationTick: UInt64; Performed: Boolean);
  end;

function AdaptiveInterval(Hot: Boolean): Cardinal;
function DueAfter(LastTick, Tick: UInt64; Interval: Cardinal): Boolean;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestAdaptiveInspector10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10P_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  QUIET_INTERVAL_MS = 8000;
  HOT_INTERVAL_MS = 2000;
  HOT_WINDOW_MS = 20000;
  INSPECTION_RETRY_MS = 1000;

function AdaptiveInterval(Hot: Boolean): Cardinal;
begin
  if Hot then Result := HOT_INTERVAL_MS else Result := QUIET_INTERVAL_MS;
end;

function DueAfter(LastTick, Tick: UInt64; Interval: Cardinal): Boolean;
begin
  Result := (LastTick = 0) or (Tick < LastTick) or
    (Tick - LastTick >= Interval);
end;

constructor TAdaptiveInspector.Create;
begin inherited Create; Reset; end;

procedure TAdaptiveInspector.Reset;
begin
  FillChar(FStates, SizeOf(FStates), 0);
  FHotUntil := 0;
  FLastTick := 0;
  FHaveTick := False;
  FHot := False;
end;

function UpdateAdaptiveWindow(Inspector: TAdaptiveInspector;
  Baseline, Triggered: Boolean; Tick: UInt64): Boolean;
begin
  if Inspector.FHaveTick and (Tick < Inspector.FLastTick) then
    Inspector.Reset;
  Inspector.FHaveTick := True;
  Inspector.FLastTick := Tick;
  if Baseline or Triggered then
  begin
    Inspector.FHot := True;
    if Tick > High(UInt64) - UInt64(HOT_WINDOW_MS) then
      Inspector.FHotUntil := High(UInt64)
    else
      Inspector.FHotUntil := Tick + UInt64(HOT_WINDOW_MS);
  end;
  Result := Inspector.FHot and (Tick <= Inspector.FHotUntil);
  if not Result then Inspector.FHot := False;
end;

function AdaptiveStateDue(const State: TAdaptiveInspectionState;
  Tick: UInt64; Hot: Boolean): Boolean;
begin
  Result := False;
  if State.HasAttempt and (Tick >= State.LastAttempt) and
     (Tick - State.LastAttempt < INSPECTION_RETRY_MS) then Exit;
  if State.HasSample and (Tick >= State.LastSample) and
     (Tick - State.LastSample < AdaptiveInterval(Hot)) then Exit;
  Result := True;
end;

procedure ReserveAdaptiveInspection(var State: TAdaptiveInspectionState;
  Tick: UInt64);
begin
  // Reclaim an abandoned reservation after the retry interval. A token
  // from that old reservation cannot complete the new one.
  State.LastAttempt := Tick;
  State.HasAttempt := True;
  State.Reserved := True;
  State.ReservationTick := Tick;
end;

function CompleteAdaptiveReservation(var State: TAdaptiveInspectionState;
  ReservationTick: UInt64; Performed: Boolean): Boolean;
begin
  Result := State.Reserved and (State.ReservationTick = ReservationTick);
  if not Result then Exit;
  State.Reserved := False;
  if Performed then
  begin
    State.LastSample := ReservationTick;
    State.HasSample := True;
  end;
end;

function TAdaptiveInspector.ShouldInspect(Baseline, Triggered: Boolean;
  Tick: UInt64; SensorIndex: Integer): Boolean;
var S: TAdaptiveInspectionState; Hot: Boolean;
begin
  Result := False;
  if (SensorIndex < Low(FStates)) or (SensorIndex > High(FStates)) then Exit;
  Hot := UpdateAdaptiveWindow(Self, Baseline, Triggered, Tick);
  S := FStates[SensorIndex];
  if not AdaptiveStateDue(S, Tick, Hot) then Exit;
  ReserveAdaptiveInspection(S, Tick);
  FStates[SensorIndex] := S;
  Result := True;
end;

procedure TAdaptiveInspector.CompleteInspection(SensorIndex: Integer;
  ReservationTick: UInt64; Performed: Boolean);
var S: TAdaptiveInspectionState;
begin
  if (SensorIndex < Low(FStates)) or (SensorIndex > High(FStates)) then Exit;
  S := FStates[SensorIndex];
  if not CompleteAdaptiveReservation(S, ReservationTick, Performed) then Exit;
  FStates[SensorIndex] := S;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.AdaptiveInspector.inc}
{$ENDIF}

end.
