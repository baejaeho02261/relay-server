var
  TimelineTestRegion: TVirtualRegion;
  TimelineTestOK, TimelineTestRaise: Boolean;
function TimelineTestQuery(Address: NativeUInt; out R: TVirtualRegion): Boolean;
begin
  if TimelineTestRaise then raise Exception.Create('synthetic timeline query exception');
  R := TimelineTestRegion;
  Result := TimelineTestOK and (Address = $30040);
end;
function TestThreadTimelineHardening(out Failure: string; out Checks: Integer): Boolean;
var
  S: TThreadTimelineState;
  R: TVirtualRegion;
  M: TThreadTimeline;
  Threads: TThreadSampleMap;
  Sample: TThreadSample;
  D: TDetectionKinds;
  Saved: TTimelineQueryHook;
  Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Setup;
  begin
    S := Default(TThreadTimelineState); S.StartAddress := $30040; S.Eligible := True;
    R := Default(TVirtualRegion); R.BaseAddress := $30000;
    R.AllocationBase := $30000; R.Size := $1000;
    R.State := ALLOC_MEM_COMMIT; R.RegionType := ALLOC_MEM_PRIVATE; R.Protect := $20;
  end;
  procedure Prime;
  begin
    Setup; M.Reset; Threads.Clear; D := [];
    TimelineTestRegion := R; TimelineTestOK := True; TimelineTestRaise := False;
    M.Examine(True, True, True, True, False, Threads, [], 1000, D);
    Sample := Default(TThreadSample); Sample.ThreadID := 10; Sample.StartAddress := S.StartAddress;
    Threads.Add(10, Sample);
  end;
  procedure Observe(Tick: UInt64);
  begin
    D := [];
    M.Examine(True, True, False, True, True, Threads, [dkPECodeIntegrity], Tick, D);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; Threads := nil;
  Saved := TimelineQueryHook;
  try
    try
      Setup;
      Check(ApplyTimelineRegion(S, True, R, 1000) and (S.Confirmations = 1), 'first private observation');
      ApplyTimelineRegion(S, True, R, 1000);
      Check(S.Confirmations = 1, 'same tick is not independent confirmation');
      ApplyTimelineRegion(S, True, R, 2000);
      Check(S.Confirmations = 2, 'later successful read confirms');
      Check(not ApplyTimelineRegion(S, False, R, 3000) and
        (S.Confirmations = 0) and not S.PrivateExecutable, 'failure invalidates prior private result');
      ApplyTimelineRegion(S, True, R, 4000);
      Check(S.Confirmations = 1, 'recovery starts at one');
      R.Protect := $04;
      Check(not ApplyTimelineRegion(S, True, R, 5000) and (S.Confirmations = 0), 'non-executable resets');
      Setup; ApplyTimelineRegion(S, True, R, 1000); R.RegionType := ALLOC_MEM_MAPPED;
      Check(not ApplyTimelineRegion(S, True, R, 2000), 'mapped is not private');
      Setup; ApplyTimelineRegion(S, True, R, 1000); R.State := ALLOC_MEM_RESERVE;
      Check(not ApplyTimelineRegion(S, True, R, 2000), 'reserved page cannot confirm');
      Setup; R.Protect := $120;
      Check(not ApplyTimelineRegion(S, True, R, 1000), 'guard page cannot confirm');
      Setup; R.Size := 0;
      Check(not ApplyTimelineRegion(S, True, R, 1000), 'zero extent rejected');
      Setup; R.BaseAddress := $31000;
      Check(not ApplyTimelineRegion(S, True, R, 1000), 'non-containing region rejected');
      Setup; ApplyTimelineRegion(S, True, R, 1000); R.AllocationBase := $20000;
      ApplyTimelineRegion(S, True, R, 2000);
      Check((S.Confirmations = 1) and (S.AllocationBase = $20000), 'remap starts at one');
      R.Size := $2000; ApplyTimelineRegion(S, True, R, 3000);
      Check(S.Confirmations = 1, 'extent change starts at one');
      ApplyTimelineRegion(S, True, R, 2000);
      Check(S.Confirmations = 1, 'clock rollback resets confirmation');
      S.Confirmations := 255; ApplyTimelineRegion(S, True, R, 4000);
      Check(S.Confirmations = 255, 'byte counter saturates');
      TimelineQueryHook := TimelineTestQuery;
      M := TThreadTimeline.Create; Threads := TThreadSampleMap.Create;
      Prime; Observe(2000);
      Check(not (dkThreadTimeline in D), 'one read does not report');
      TimelineTestOK := False; Observe(3000);
      Check(not (dkThreadTimeline in D), 'failed second query cannot report stale candidate');
      Check(M.FThreads.TryGetValue(10, S) and (S.Confirmations = 0), 'failed state saved as unknown');
      TimelineTestOK := True; Observe(4000);
      Check(not (dkThreadTimeline in D), 'post-failure first read cannot report');
      Observe(5000);
      Check(dkThreadTimeline in D, 'fresh second read still detects');
      Observe(70000);
      Check(not (dkThreadTimeline in D), 'same thread candidate not re-reported');
      Prime; Observe(2000); D := [];
      M.Examine(True, False, False, True, True, Threads, [], 3000, D);
      Check(M.FThreads.TryGetValue(10, S) and (S.Confirmations = 0), 'invalid snapshot breaks sequence');
      Check(M.FThreads.Count = 1, 'invalid snapshot does not retire thread');
      Observe(4000);
      Check(not (dkThreadTimeline in D), 'first after invalid snapshot remains unconfirmed');
      M.Examine(True, True, False, True, True, nil, [], 5000, D);
      Check(M.FThreads.TryGetValue(10, S) and (S.Confirmations = 0), 'nil snapshot safe invalidation');
      Prime; Observe(2000); TimelineTestRaise := True; Raised := False;
      try Observe(3000); except on E: Exception do Raised := True; end;
      Check(Raised, 'query exception remains visible to fault isolation');
      Check(M.FThreads.TryGetValue(10, S) and (S.Confirmations = 0), 'exception cannot retain confidence');
      TimelineTestRaise := False; Threads.Clear; Observe(4000);
      Check(M.FThreads.Count = 0, 'complete disappearance retires state');
      Prime; Observe(2000);
      M.Examine(True, True, True, True, True, Threads, [], 3000, D);
      Check(M.FThreads.TryGetValue(10, S) and not S.Eligible and
        (S.Confirmations = 0), 'explicit baseline remains silent');
      M.Examine(False, True, False, True, True, Threads, [], 4000, D);
      Check((M.FThreads.Count = 0) and (M.Count = 0), 'non-own target resets');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    Threads.Free; M.Free; TimelineQueryHook := Saved;
  end;
end;
