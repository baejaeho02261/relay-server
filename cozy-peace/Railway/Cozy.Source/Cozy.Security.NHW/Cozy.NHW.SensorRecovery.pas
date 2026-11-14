unit Cozy.NHW.SensorRecovery;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TDropCounterStatus = (dcsUnavailable, dcsBaseline, dcsStable,
    dcsAdvanced, dcsDecreaseUnknown);

  // Coverage accounting only: no session restart/control, no new sensor.
  TSensorCoverageRecovery = class
  private
    FLastLostTotal: Cardinal;
    FLastWarning, FDegradedUntil, FLastTick: UInt64;
    FReportedLoss: Cardinal;
    FHasDropSample, FHaveTick, FWarned: Boolean;
    FLastCounterStatus: TDropCounterStatus;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(TraceEnabled, TraceGap: Boolean; DropTotal: Cardinal;
      GapMS: UInt64; IntervalMS: Cardinal; Tick: UInt64;
      var Detected: TDetectionKinds);
    function Degraded(Tick: UInt64): Boolean;
    property ReportedLoss: Cardinal read FReportedLoss;
    property LastCounterStatus: TDropCounterStatus read FLastCounterStatus;
  end;

{$IFDEF NHW_NATIVE5J_TESTS}
function TestRecovery5J(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation
{$IFDEF NHW_NATIVE5J_TESTS}
uses System.SysUtils;
{$ENDIF}

constructor TSensorCoverageRecovery.Create;
begin inherited Create; Reset; end;

procedure TSensorCoverageRecovery.Reset;
begin
  FLastLostTotal := 0; FLastWarning := 0; FDegradedUntil := 0; FLastTick := 0;
  FReportedLoss := 0;
  FHasDropSample := False; FHaveTick := False; FWarned := False;
  FLastCounterStatus := dcsUnavailable;
end;

function TSensorCoverageRecovery.Degraded(Tick: UInt64): Boolean;
begin
  Result := (FDegradedUntil <> 0) and
    ((Tick < FDegradedUntil) or
     ((FDegradedUntil = High(UInt64)) and (Tick = High(UInt64))));
end;

procedure TSensorCoverageRecovery.Observe(TraceEnabled,
  TraceGap: Boolean; DropTotal: Cardinal; GapMS: UInt64;
  IntervalMS: Cardinal; Tick: UInt64; var Detected: TDetectionKinds);
var
  Loss: Boolean;

  procedure BeginCoverageObservation;
  var
    Rollback: Boolean;
  begin
    Rollback := FHaveTick and (Tick < FLastTick);
    Loss := Rollback;
    if Rollback then
    begin
      FHasDropSample := False;
      FDegradedUntil := 0;
    end;
    FLastTick := Tick;
    FHaveTick := True;
  end;

  procedure AccumulateDropCounter;
  var
    Delta: Cardinal;
  begin
    if not TraceEnabled then
    begin
      FHasDropSample := False;
      FLastCounterStatus := dcsUnavailable;
    end
    else if not FHasDropSample then
    begin
      FHasDropSample := True;
      FLastLostTotal := DropTotal;
      FLastCounterStatus := dcsBaseline;
      // An already-positive first counter is not a new interval's loss.
    end
    else
    begin
      if DropTotal > FLastLostTotal then
      begin
        Delta := DropTotal - FLastLostTotal;
        if Delta > High(Cardinal) - FReportedLoss then
          FReportedLoss := High(Cardinal)
        else
          Inc(FReportedLoss, Delta);
        FLastCounterStatus := dcsAdvanced;
        Loss := True;
      end
      else if DropTotal < FLastLostTotal then
      begin
        // No generation marker is supplied by the legacy call. Reset and
        // wrap cannot be distinguished: warn about coverage, count NEITHER.
        FLastCounterStatus := dcsDecreaseUnknown;
        Loss := True;
      end
      else
        FLastCounterStatus := dcsStable;
      FLastLostTotal := DropTotal;
    end;
  end;

  procedure UpdateCoverageAndWarning;
  begin
    if TraceEnabled and TraceGap then Loss := True;
    if (GapMS > 0) and (IntervalMS > 0) and
       (GapMS > UInt64(IntervalMS) * 6) then Loss := True;
    if Loss then
    begin
      if Tick > High(UInt64) - UInt64(15000) then
        FDegradedUntil := High(UInt64)
      else
        FDegradedUntil := Tick + UInt64(15000);
      if (not FWarned) or (Tick < FLastWarning) or
         (Tick - FLastWarning >= 30000) then
      begin
        Include(Detected, dkObservationUncertain);
        FLastWarning := Tick;
        FWarned := True;
      end;
    end;
  end;

begin
  BeginCoverageObservation;
  AccumulateDropCounter;
  UpdateCoverageAndWarning;
end;

{$IFDEF NHW_NATIVE5J_TESTS}
{$I Cozy.NHW.Native5J.Recovery.inc}
{$ENDIF}
end.
