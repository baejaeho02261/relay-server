var
  BenchTestOK: Boolean;
  BenchTestKernel, BenchTestUser: UInt64;
function BenchTestTimes(Process: THandle; var StartTime, ExitTime,
  KernelTime, UserTime: TFileTime): BOOL; stdcall;
begin
  StartTime := Default(TFileTime); ExitTime := Default(TFileTime);
  KernelTime.dwLowDateTime := Cardinal(BenchTestKernel and UInt64($FFFFFFFF));
  KernelTime.dwHighDateTime := Cardinal(BenchTestKernel shr 32);
  UserTime.dwLowDateTime := Cardinal(BenchTestUser and UInt64($FFFFFFFF));
  UserTime.dwHighDateTime := Cardinal(BenchTestUser shr 32);
  Result := BenchTestOK and (Process <> 0);
end;
function TestBenchmark5I(out Failure: string; out Checks: Integer): Boolean;
var
  M: TRealtimeBenchmark;
  R: TRealtimeMetrics;
  Saved: TBenchmarkTimesHook;
  I: Integer; Sum, PriorSum: UInt64;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  function BucketSum: UInt64;
  var J: Integer;
  begin Result := 0; for J := Low(M.FBuckets) to High(M.FBuckets) do Inc(Result, UInt64(M.FBuckets[J])); end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; Saved := BenchmarkTimesHook;
  try
    try
      BenchmarkTimesHook := BenchTestTimes; BenchTestOK := True; BenchTestKernel := 0; BenchTestUser := 0;
      M := TRealtimeBenchmark.Create;
      R := M.Metrics; Check((R.EventSamples = 0) and (R.P99DispatchUS = 0), 'empty histogram');
      M.ObserveDispatch(150, 1); M.ObserveDispatch(1500, 2); R := M.Metrics;
      Check((R.P50DispatchUS = 200) and (R.P95DispatchUS = 2000), 'existing percentile semantics');
      M.Reset; M.ObserveDispatch(High(UInt64), 7); R := M.Metrics;
      Check((R.EventSamples = 1) and (M.FBuckets[15] = 1), 'UInt64 overflow sample counted in final bucket');
      Check((R.P50DispatchUS = High(Cardinal)) and (R.P99DispatchUS = High(Cardinal)), 'tail percentile clipped not zero');
      Check(BucketSum = UInt64(R.EventSamples), 'histogram numerator denominator match');
      M.Reset;
      for I := Low(LIMITS) to High(LIMITS) do M.ObserveDispatch(UInt64(LIMITS[I]), 0);
      Check(BucketSum = 16, 'every bound assigned exactly once');
      for I := Low(LIMITS) to High(LIMITS) do Check(M.FBuckets[I] = 1, 'inclusive bucket bound');
      M.ObserveDispatch(UInt64(High(Cardinal)) + 1, 8);
      Check(M.FBuckets[15] = 2, 'one past maximum accepted into final bucket');
      M.Reset; M.FMetrics.EventSamples := High(Cardinal) - 1;
      M.FBuckets[0] := High(Cardinal) - 1;
      M.ObserveDispatch(High(UInt64), 1);
      Check((M.FMetrics.EventSamples = High(Cardinal)) and (BucketSum = High(Cardinal)), 'last representable event committed coherently');
      Sum := BucketSum; M.ObserveDispatch(100, 99);
      Check((BucketSum = Sum) and (M.FMetrics.EventSamples = High(Cardinal)), 'saturated count freezes whole histogram');
      Check(M.Metrics.MaxQueueDepth = 99, 'live depth maintained after sample freeze');
      M.Reset; M.ObserveScan(30, 1, 1000); M.ObserveScan(50, 2, 3000); R := M.Metrics;
      Check((R.Samples = 2) and (R.AverageScanMS = 40) and (R.LastScanMS = 50), 'ordinary scan average retained');
      Check(R.DroppedEvents = 2, 'caller loss gauge retained');
      M.Reset; M.ObserveScan(High(UInt64), 0, 1000); R := M.Metrics;
      Check((R.LastScanMS = High(Cardinal)) and (R.AverageScanMS = High(Cardinal)), 'huge scan clipped consistently');
      Check(M.FSumScanMS = High(Cardinal), 'sum uses representable sample not raw overflowing duration');
      M.Reset; M.FMetrics.Samples := High(Cardinal) - 1;
      M.FSumScanMS := UInt64(High(Cardinal) - 1) * UInt64(High(Cardinal));
      M.ObserveScan(High(UInt64), 0, 1000); PriorSum := M.FSumScanMS;
      Check((M.FMetrics.Samples = High(Cardinal)) and
        (M.FMetrics.AverageScanMS = High(Cardinal)), 'max scan population cannot overflow sum');
      M.ObserveScan(1, 9, 3000);
      Check((M.FSumScanMS = PriorSum) and (M.FMetrics.AverageScanMS = High(Cardinal)), 'scan numerator freezes with denominator');
      Check((M.FMetrics.LastScanMS = 1) and (M.FMetrics.DroppedEvents = 9), 'last sample and loss remain live after freeze');
      Check(ClippedCPUPercent(10000000, 1000) = 100, 'CPU units correct');
      Check(ClippedCPUPercent(25000000, 1000) = 250, 'CPU may exceed one core');
      Check(ClippedCPUPercent(High(UInt64), 1) = High(Cardinal), 'CPU ratio saturates without integer multiplication overflow');
      Check(ClippedCPUPercent(1, 0) = 0, 'zero wall duration');
      M.Reset; BenchTestKernel := 10000000; M.ObserveScan(1, 0, 1000);
      BenchTestKernel := 20000000; M.ObserveScan(1, 0, 3000);
      Check(M.Metrics.ProcessCPUPercent = 50, 'CPU delta measured');
      BenchTestOK := False; M.ObserveScan(1, 0, 5000);
      Check((M.FLastCPUTick = 0) and (M.Metrics.ProcessCPUPercent = 0), 'failed CPU query does not retain stale sample');
      BenchTestOK := True; BenchTestKernel := 30000000; M.ObserveScan(1, 0, 7000);
      Check(M.Metrics.ProcessCPUPercent = 0, 'CPU recovery rebaselines rather than bridging failure');
      M.ObserveScan(1, 0, 6000);
      Check(M.Metrics.ProcessCPUPercent = 0, 'CPU clock regression is not unsigned gap');
      BenchTestKernel := High(UInt64); BenchTestUser := 1;
      M.ObserveScan(1, 0, 9000);
      Check(M.FLastCPUTick = 0, 'invalid CPU sum rejected');
      M.Reset; R := M.Metrics;
      Check((BucketSum = 0) and (R.Samples = 0) and (R.MaxQueueDepth = 0), 'reset clears all benchmark data');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally M.Free; BenchmarkTimesHook := Saved; end;
end;
