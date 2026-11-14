function TestCapture5L(out Failure: string; out Checks: Integer): Boolean;
var M: TCaptureMonitor; K: TDetectionKinds; I, Rounds: Integer;
    Item: TCaptureProcessInfo;
  procedure Check(C: Boolean; const Msg: string);
  begin Inc(Checks); if not C then raise Exception.Create(Msg); end;
  procedure Prepare(Count: Integer; FirstPID: Cardinal = 2);
  var J: Integer;
  begin
    M.Reset; Capture5LClock := 1000; Capture5LCost := 0;
    Capture5LCalls := 0; Capture5LMode := 0; Capture5LClockReads := 0;
    Capture5LBackwards := False;
    M.FSnapshotValid := True; M.FNextRefresh := High(UInt64);
    M.FLastStatus := 1000;
    for J := 0 to Count - 1 do
    begin
      Item.PID := FirstPID + Cardinal(J); Item.Name := 'app.exe';
      M.FProcesses.Add(Item);
    end;
    K := [];
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  try
    try
      M := TCaptureMonitor.Create;
      Prepare(100); M.Examine(1000, K);
      Check((Capture5LCalls = 12) and (M.FIndex = 12), 'denied reads consume count budget');
      Check(not M.FPrimed, 'incomplete sweep is not primed');
      Check((K = []) and (M.FSeen.Count = 0), 'denied read is not evidence');
      Rounds := 1;
      while M.FIndex < M.FProcesses.Count do
      begin
        Check(Rounds < 10, 'sweep makes bounded progress');
        M.Examine(Capture5LClock, K); Inc(Rounds);
      end;
      Check((Rounds = 9) and M.FPrimed, 'count-limited sweep eventually completes');
      Check(Capture5LCalls = 100, 'no skipped PID during continuation');
      Prepare(50); Capture5LCost := 20; M.Examine(1000, K);
      Check((Capture5LCalls = 4) and (M.FIndex = 4), 'failed read consumes time budget');
      Check(Capture5LClock = 1080, 'no next call after 80ms boundary');
      Prepare(50); Capture5LCost := 55; M.Examine(1000, K);
      Check(Capture5LCalls = 2, 'one uninterruptible call may cross deadline');
      Prepare(50); Capture5LMode := 2; M.Examine(1000, K);
      Check((Capture5LCalls = 12) and (M.FSeen.Count = 0), 'PID name mismatch is budgeted, not evidence');
      Prepare(50, 1); M.Examine(1000, K);
      Check((M.FIndex = 12) and (Capture5LCalls = 11), 'self PID skip consumes an attempt');
      Prepare(12); Capture5LMode := 1; M.Examine(1000, K);
      Check((M.FIndex = 12) and M.FPrimed, 'valid short sweep completes normally');
      Prepare(0); M.Examine(1000, K);
      Check((Capture5LCalls = 0) and M.FPrimed, 'empty complete snapshot remains valid');
      Prepare(30); Capture5LBackwards := True; M.Examine(1000, K);
      Check((Capture5LCalls = 0) and (M.FIndex = 0), 'clock rollback does not underflow');
      Prepare(24); K := [dkHeapState]; M.Examine(1000, K);
      Check(K = [dkHeapState], 'other sensor detections retained');
      I := M.FIndex; M.Examine(1000, K);
      Check((I = 12) and (M.FIndex = 24), 'second tick resumes from cursor');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally M.Free; end;
end;
