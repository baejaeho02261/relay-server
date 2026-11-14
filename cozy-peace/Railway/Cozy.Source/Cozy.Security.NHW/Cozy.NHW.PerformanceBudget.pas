unit Cozy.NHW.PerformanceBudget;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.SensorFaultIsolation;

type
  TOptionalWork = (owImageVerification, owV80Analysis, owMemoryDelta);
  TProbeCost = record
    Samples, TotalUS, MaximumUS, SmoothedUS: UInt64;
  end;
  TOptionalWorkState = record
    DeferredSince: UInt64;
    Deferrals, Runs: UInt64;
    Deferred: Boolean;
  end;

  // Measured WALL duration, not process CPU time. Only the three optional
  // heavy paths are gated; legacy sensors, handles and ETW are never skipped.
  TPerformanceBudget = class
  private
    FCosts: array[TSensorSlot] of TProbeCost;
    FWork: array[TOptionalWork] of TOptionalWorkState;
    FSpentUS, FBudgetUS: UInt64;
    FLastTick: UInt64;
  public
    constructor Create;
    procedure Reset;
    procedure BeginCycle(Tick: UInt64; IntervalMS: Cardinal);
    procedure RecordCost(Sensor: TSensorSlot; DurationUS: UInt64);
    function AllowOptional(Work: TOptionalWork; Tick: UInt64;
      Baseline, Triggered: Boolean): Boolean;
    function Cost(Sensor: TSensorSlot): TProbeCost;
    function WorkState(Work: TOptionalWork): TOptionalWorkState;
    property SpentUS: UInt64 read FSpentUS;
    property BudgetUS: UInt64 read FBudgetUS;
  end;

implementation

uses Cozy.NHW.NativeSafety;

constructor TPerformanceBudget.Create;
begin inherited Create; Reset; end;

procedure TPerformanceBudget.Reset;
begin
  FillChar(FCosts, SizeOf(FCosts), 0);
  FillChar(FWork, SizeOf(FWork), 0);
  FSpentUS := 0;
  FBudgetUS := 25000;
  FLastTick := 0;
end;

procedure TPerformanceBudget.BeginCycle(Tick: UInt64; IntervalMS: Cardinal);
begin
  if Tick < FLastTick then FillChar(FWork, SizeOf(FWork), 0);
  FLastTick := Tick;
  FSpentUS := 0;
  FBudgetUS := UInt64(IntervalMS) * UInt64(250); // quarter of nominal period
  if FBudgetUS < 5000 then FBudgetUS := 5000;
  if FBudgetUS > 100000 then FBudgetUS := 100000;
end;

procedure TPerformanceBudget.RecordCost(Sensor: TSensorSlot; DurationUS: UInt64);
var C: TProbeCost;
begin
  C := FCosts[Sensor];
  C.Samples := NHWSaturatingAdd(C.Samples, 1);
  C.TotalUS := NHWSaturatingAdd(C.TotalUS, DurationUS);
  if DurationUS > C.MaximumUS then C.MaximumUS := DurationUS;
  if C.Samples = 1 then C.SmoothedUS := DurationUS
  else if DurationUS >= C.SmoothedUS then
    C.SmoothedUS := C.SmoothedUS + (DurationUS - C.SmoothedUS) div 8
  else
    C.SmoothedUS := C.SmoothedUS - (C.SmoothedUS - DurationUS) div 8;
  FCosts[Sensor] := C;
  FSpentUS := NHWSaturatingAdd(FSpentUS, DurationUS);
end;

function TPerformanceBudget.AllowOptional(Work: TOptionalWork;
  Tick: UInt64; Baseline, Triggered: Boolean): Boolean;
var S: TOptionalWorkState;
begin
  S := FWork[Work];
  Result := Baseline or Triggered or (FSpentUS < FBudgetUS);
  // Force an eligible optional inspection after at most 5s of budget-only
  // deferral. The original sensor's own cadence still applies.
  if S.Deferred and ((Tick < S.DeferredSince) or
    (Tick - S.DeferredSince >= 5000)) then Result := True;
  if Result then
  begin
    S.Deferred := False;
    S.DeferredSince := 0;
    S.Runs := NHWSaturatingAdd(S.Runs, 1);
  end
  else
  begin
    if not S.Deferred then S.DeferredSince := Tick;
    S.Deferred := True;
    S.Deferrals := NHWSaturatingAdd(S.Deferrals, 1);
  end;
  FWork[Work] := S;
end;

function TPerformanceBudget.Cost(Sensor: TSensorSlot): TProbeCost;
begin Result := FCosts[Sensor]; end;

function TPerformanceBudget.WorkState(Work: TOptionalWork): TOptionalWorkState;
begin Result := FWork[Work]; end;

end.
