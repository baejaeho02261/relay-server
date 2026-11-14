unit Cozy.NHW.RealtimeBenchmark;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TRealtimeMetrics = record
    Samples: Cardinal;
    EventSamples: Cardinal;
    LastScanMS: Cardinal;
    AverageScanMS: Cardinal;
    P50DispatchUS: Cardinal;
    P95DispatchUS: Cardinal;
    P99DispatchUS: Cardinal;
    DroppedEvents: Cardinal;
    MaxQueueDepth: Cardinal;
    ProcessCPUPercent: Cardinal;
  end;

  // v90: bounded RAM histogram. Percentiles are approximations using the
  // bucket upper bounds (High(Cardinal) is a CLIPPED final bound) and describe ETW callback-to-dispatch delay, NOT
  // kernel event generation-to-detection delay.
  TRealtimeBenchmark = class
  private
    FBuckets: array[0..15] of Cardinal;
    FMetrics: TRealtimeMetrics;
    FSumScanMS: UInt64;
    FLastCPUTime: UInt64;
    FLastCPUTick: UInt64;
    function Percentile(Percent: Cardinal): Cardinal;
    procedure ObserveCPU(Tick: UInt64);
  public
    constructor Create;
    procedure Reset;
    procedure ObserveDispatch(DelayUS: UInt64; QueueDepth: Cardinal);
    procedure ObserveScan(ScanMS: UInt64; DroppedTotal: Cardinal;
      Tick: UInt64);
    function Metrics: TRealtimeMetrics;
  end;

{$IFDEF NHW_NATIVE5I_TESTS}
function TestBenchmark5I(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE5I_TESTS}
uses System.SysUtils;
type
  TBenchmarkTimesHook = function(Process: THandle;
    var StartTime, ExitTime, KernelTime, UserTime: TFileTime): BOOL; stdcall;
var BenchmarkTimesHook: TBenchmarkTimesHook;
{$ENDIF}

function BenchmarkProcessTimes(var StartTime, ExitTime, KernelTime,
  UserTime: TFileTime): Boolean;
begin
{$IFDEF NHW_NATIVE5I_TESTS}
  if Assigned(BenchmarkTimesHook) then
    Exit(BenchmarkTimesHook(GetCurrentProcess, StartTime, ExitTime, KernelTime, UserTime));
{$ENDIF}
  Result := GetProcessTimes(GetCurrentProcess, StartTime, ExitTime, KernelTime, UserTime);
end;

const
  LIMITS: array[0..15] of Cardinal =
    (50, 100, 200, 500, 1000, 2000, 5000, 10000,
     20000, 50000, 100000, 200000, 500000, 1000000,
     2000000, High(Cardinal));

function FileTimeValue(const F: TFileTime): UInt64;
begin
  Result := (UInt64(F.dwHighDateTime) shl 32) or UInt64(F.dwLowDateTime);
end;

constructor TRealtimeBenchmark.Create;
begin inherited Create; Reset; end;

procedure TRealtimeBenchmark.Reset;
begin
  FillChar(FBuckets, SizeOf(FBuckets), 0);
  FMetrics := Default(TRealtimeMetrics);
  FSumScanMS := 0;
  FLastCPUTime := 0;
  FLastCPUTick := 0;
end;

procedure TRealtimeBenchmark.ObserveDispatch(DelayUS: UInt64;
  QueueDepth: Cardinal);
var I: Integer;
begin
  if QueueDepth > FMetrics.MaxQueueDepth then FMetrics.MaxQueueDepth := QueueDepth;
  // Freeze numerator and denominator together when the representable sample
  // count is exhausted. MaxQueueDepth remains a live diagnostic gauge.
  if FMetrics.EventSamples = High(Cardinal) then Exit;
  I := Low(LIMITS);
  while (I < High(LIMITS)) and (DelayUS > LIMITS[I]) do Inc(I);
  // The final bucket also accepts UInt64 values above High(Cardinal).
  if FBuckets[I] = High(Cardinal) then Exit;
  Inc(FBuckets[I]);
  Inc(FMetrics.EventSamples);
end;

function TRealtimeBenchmark.Percentile(Percent: Cardinal): Cardinal;
var
  Target, Count: UInt64;
  I: Integer;
begin
  Result := 0;
  if FMetrics.EventSamples = 0 then Exit;
  Target := (UInt64(FMetrics.EventSamples) * Percent + 99) div 100;
  Count := 0;
  for I := Low(LIMITS) to High(LIMITS) do
  begin
    Inc(Count, FBuckets[I]);
    if Count >= Target then Exit(LIMITS[I]);
  end;
end;

function ClippedCPUPercent(Difference100ns, WallMS: UInt64): Cardinal;
var P: Double;
begin
  Result := 0;
  if WallMS = 0 then Exit;
  // Division first avoids overflow of both Difference*100 and WallMS*10000.
  // Process CPU may exceed 100 percent on multi-core machines; do not cap at 100.
  P := (Double(Difference100ns) / Double(WallMS)) / 100.0;
  if P >= Double(High(Cardinal)) then Exit(High(Cardinal));
  Result := Cardinal(Trunc(P));
end;

procedure TRealtimeBenchmark.ObserveCPU(Tick: UInt64);
var
  StartTime, ExitTime, KernelTime, UserTime: TFileTime;
  Total, KernelValue, UserValue: UInt64;
begin
  if not BenchmarkProcessTimes(StartTime, ExitTime, KernelTime, UserTime) then
  begin
    FLastCPUTick := 0;
    FLastCPUTime := 0;
    FMetrics.ProcessCPUPercent := 0;
    Exit;
  end;
  KernelValue := FileTimeValue(KernelTime);
  UserValue := FileTimeValue(UserTime);
  if KernelValue > High(UInt64) - UserValue then
  begin
    FLastCPUTick := 0;
    FLastCPUTime := 0;
    FMetrics.ProcessCPUPercent := 0;
    Exit;
  end;
  Total := KernelValue + UserValue;
  if (FLastCPUTick <> 0) and (Tick > FLastCPUTick) and
     (Total >= FLastCPUTime) then
    FMetrics.ProcessCPUPercent := ClippedCPUPercent(Total - FLastCPUTime,
      Tick - FLastCPUTick)
  else FMetrics.ProcessCPUPercent := 0;
  FLastCPUTime := Total;
  FLastCPUTick := Tick;
end;

procedure TRealtimeBenchmark.ObserveScan(ScanMS: UInt64;
  DroppedTotal: Cardinal; Tick: UInt64);
var Sample: Cardinal;
begin
  if ScanMS > High(Cardinal) then Sample := High(Cardinal)
  else Sample := Cardinal(ScanMS);
  FMetrics.LastScanMS := Sample;
  if FMetrics.Samples < High(Cardinal) then
  begin
    // With Cardinal samples/count the maximum sum is (2^32-1)^2 < 2^64.
    // Once count saturates, do not keep adding to the average's numerator.
    Inc(FMetrics.Samples);
    Inc(FSumScanMS, UInt64(Sample));
    FMetrics.AverageScanMS := Cardinal(FSumScanMS div UInt64(FMetrics.Samples));
  end;
  FMetrics.DroppedEvents := DroppedTotal;
  if (FLastCPUTick = 0) or (Tick < FLastCPUTick) then ObserveCPU(Tick)
  else if Tick - FLastCPUTick >= 2000 then ObserveCPU(Tick);
end;

function TRealtimeBenchmark.Metrics: TRealtimeMetrics;
begin
  Result := FMetrics;
  Result.P50DispatchUS := Percentile(50);
  Result.P95DispatchUS := Percentile(95);
  Result.P99DispatchUS := Percentile(99);
end;

{$IFDEF NHW_NATIVE5I_TESTS}
{$I Cozy.NHW.Native5I.Benchmark.inc}
{$ENDIF}

end.
