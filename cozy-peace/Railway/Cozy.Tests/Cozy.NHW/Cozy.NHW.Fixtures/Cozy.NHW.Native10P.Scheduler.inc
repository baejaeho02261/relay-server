var
  Schedule10PMode: Integer;
  Schedule10PState: TThreadScheduleState;
function Schedule10PRead(PID, ThreadID: Cardinal;
  out State: TThreadScheduleState): Boolean;
begin
  State := Default(TThreadScheduleState);
  if Schedule10PMode = 2 then raise Exception.Create('synthetic scheduling failure');
  Result := (Schedule10PMode = 0) and (PID <> 0) and (ThreadID <> 0);
  if Result then State := Schedule10PState;
end;

function TestScheduler10P(out Failure: string; out Checks: Integer): Boolean;
var
  M: TSchedulerMonitor;
  Threads: TThreadSampleMap;
  Sample: TThreadSample;
  K: TDetectionKinds;
  Raised: Boolean;
  BeforeHook: TReadSchedule10PHook;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;
  M := nil; Threads := nil;
  BeforeHook := ReadSchedule10PHook;
  try
    try
      M := TSchedulerMonitor.Create;
      Threads := TThreadSampleMap.Create;
      ReadSchedule10PHook := Schedule10PRead;
      Schedule10PMode := 0;
      Sample := Default(TThreadSample); Sample.ThreadID := 17;
      Threads.Add(17, Sample);
      Schedule10PState := Default(TThreadScheduleState);
      Schedule10PState.CreationTime := 100;
      Schedule10PState.PriorityKnown := True;
      Schedule10PState.Priority := 1;
      K := [];
      M.SampleThreads(9, Threads, False, K);
      Check((K = []) and (M.FThreads.Count = 1), 'thread baseline');
      Schedule10PState.Priority := 2;
      M.SampleThreads(9, Threads, False, K);
      Check(dkThreadPriority in K, 'continuous change retained');
      Schedule10PMode := 1; K := [];
      M.SampleThreads(9, Threads, False, K);
      Check((K = []) and (M.FThreads.Count = 0), 'identity failure removes chain');
      Schedule10PMode := 0; Schedule10PState.Priority := 3;
      M.SampleThreads(9, Threads, False, K);
      Check(K = [], 'recovery primes without historical comparison');
      Schedule10PState.Priority := 4;
      M.SampleThreads(9, Threads, False, K);
      Check(dkThreadPriority in K, 'post-recovery change detected');
      K := []; Schedule10PState.CreationTime := 101;
      Schedule10PState.Priority := 7;
      M.SampleThreads(9, Threads, False, K);
      Check(K = [], 'TID reuse does not compare different creation times');
      Schedule10PState.PriorityKnown := False;
      M.SampleThreads(9, Threads, False, K);
      Schedule10PState.PriorityKnown := True;
      Schedule10PState.Priority := 8;
      M.SampleThreads(9, Threads, False, K);
      Check(K = [], 'unknown per-field observation breaks field comparison');
      Schedule10PState.CreationTime := 0;
      M.SampleThreads(9, Threads, False, K);
      Check(M.FThreads.Count = 0, 'zero identity rejected');
      Schedule10PState.CreationTime := 200;
      M.SampleThreads(9, Threads, False, K);
      M.SampleThreads(9, nil, False, K);
      Check(M.FThreads.Count = 0, 'nil snapshot clears continuity');
      M.SampleThreads(9, Threads, False, K);
      Schedule10PMode := 2; K := [dkProcess]; Raised := False;
      try M.SampleThreads(9, Threads, False, K);
      except on E: Exception do Raised := True; end;
      Check(Raised, 'collection exception propagated');
      Check(M.FThreads.Count = 0, 'exception clears cached comparisons');
      Check(K = [dkProcess], 'exception does not publish partial kinds');
      Schedule10PMode := 0;
      M.SampleThreads(9, Threads, False, K);
      Threads.Clear;
      M.SampleThreads(9, Threads, False, K);
      Check(M.FThreads.Count = 0, 'complete empty snapshot removes exited threads');
      Sample.ThreadID := 18; Threads.Add(17, Sample);
      K := []; M.SampleThreads(9, Threads, False, K);
      Check((M.FThreads.Count = 0) and (K = []), 'mismatched snapshot key rejected');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    ReadSchedule10PHook := BeforeHook;
    Threads.Free;
    M.Free;
  end;
end;
