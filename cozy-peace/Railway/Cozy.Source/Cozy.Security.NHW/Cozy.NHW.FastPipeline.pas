unit Cozy.NHW.FastPipeline;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  // v83: no expensive memory work in the ETW callback. The main scan handles
  // heavyweight optional v81-v90 sensors after a bounded fast classification.
  TFastDeferredPipeline = class
  private
    FPendingUntil: UInt64;
    FLastHeavy: UInt64;
    FHasHeavy: Boolean;
    FWorkPending: Boolean;
    FReserved: Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure NotifyRelevant(Tick: UInt64);
    function AllowDeferred(Tick: UInt64; Baseline,
      UnderPressure: Boolean): Boolean;
    procedure CompleteDeferred(Succeeded: Boolean);
    function Pending(Tick: UInt64): Boolean;
  end;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestFastPipeline10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10O_TESTS}
uses System.SysUtils;
{$ENDIF}

constructor TFastDeferredPipeline.Create;
begin inherited Create; Reset; end;

procedure TFastDeferredPipeline.Reset;
begin
  FPendingUntil := 0;
  FLastHeavy := 0;
  FHasHeavy := False;
  FWorkPending := False;
  FReserved := False;
end;

procedure TFastDeferredPipeline.NotifyRelevant(Tick: UInt64);
var UntilTick: UInt64;
begin
  FWorkPending := True;
  if Tick > High(UInt64) - 10000 then UntilTick := High(UInt64)
  else UntilTick := Tick + 10000;
  if UntilTick > FPendingUntil then FPendingUntil := UntilTick;
end;

function TFastDeferredPipeline.Pending(Tick: UInt64): Boolean;
begin
  // Tick remains in the API for compatibility. A pending work request is
  // NOT a time-limited hot-rate hint: only an acknowledged run consumes it.
  Result := FWorkPending;
end;

function TFastDeferredPipeline.AllowDeferred(Tick: UInt64; Baseline,
  UnderPressure: Boolean): Boolean;
var Interval: UInt64;
begin
  Result := False;
  if Baseline then Exit;
  if UnderPressure then Interval := 12000
  else if (FPendingUntil <> 0) and (Tick <= FPendingUntil) then Interval := 600
  else Interval := 6000;
  Result := (not FHasHeavy) or (Tick < FLastHeavy) or
    (Tick - FLastHeavy >= Interval);
  if Result then
  begin
    FLastHeavy := Tick;
    FHasHeavy := True;
    FReserved := True;
  end;
end;

procedure TFastDeferredPipeline.CompleteDeferred(Succeeded: Boolean);
begin
  // Main-thread serialized scheduler. A grant is not proof of execution.
  // Engine acknowledges only after the sensor call completes normally.
  if Succeeded and FReserved then FWorkPending := False;
  FReserved := False;
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.FastPipeline.inc}
{$ENDIF}

end.
