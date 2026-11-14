function TestCoverageWindow10P(out Failure: string; out Checks: Integer): Boolean;
var
  M: TCoverageWindowMonitor; K: TDetectionKinds;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;
  M := nil;
  try
    try
      M := TCoverageWindowMonitor.Create; K := [];
      M.Examine(0, 2000, 1, False, 0, K);
      Check(M.Stats.Samples = 1, 'first sample at zero');
      Check(M.Stats.EstimatedMissed = 7, '250ms normalization used for count');
      Check(M.Stats.SlowIntervals = 1, 'slow interval counted');
      M.Examine(0, High(UInt64), 1, True, 0, K);
      Check((M.Stats.Samples = 1) and (M.Stats.EstimatedMissed = 7), 'duplicate ignored');
      Check(K = [], 'duplicate loss cannot warn');
      M.Examine(0, 2000, 250, False, 1, K);
      M.Examine(0, 2000, 250, False, 2, K);
      Check(dkCoverageGap in K, 'three distinct slow samples warn');
      K := []; M.Examine(0, 2000, 250, False, 3, K);
      Check(K = [], 'warning cooldown');
      M.FStats.Samples := High(Cardinal);
      M.FStats.SlowIntervals := High(Cardinal);
      M.FStats.EstimatedMissed := High(UInt64) - 1;
      M.Examine(High(UInt64), 2000, 250, False, 4, K);
      Check(M.Stats.Samples = High(Cardinal), 'sample saturation');
      Check(M.Stats.SlowIntervals = High(Cardinal), 'slow count saturation');
      Check(M.Stats.EstimatedMissed = High(UInt64), 'missed sum saturation');
      M.Examine(0, 1, 1000, False, 1, K);
      Check(M.Stats.Samples = 0, 'reverse frame resets and is not counted');
      M.Examine(0, 1, 0, False, 2, K);
      Check(M.Stats.Samples = 0, 'invalid interval not sampled');
      M.Examine(0, 1, 1000, False, 3, K);
      Check(M.Stats.Samples = 1, 'fresh sample after clock boundary');
      M.Examine(0, 1, 1000, False, 60003, K);
      Check(M.Stats.Samples = 1, 'window rolls at boundary');
      Check(not CoverageIntervalSlow(750, 1250, 1), 'normalized threshold inclusive');
      Check(CoverageIntervalSlow(751, 1250, 1), 'scan above normalized threshold');
      Check(CoverageIntervalSlow(0, 1251, 1), 'gap above normalized threshold');
      Check(CoverageIntervalSlow(High(UInt64), High(UInt64), High(Cardinal)), 'large values safe');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
