var
  ExecTestValid, ExecTestPrivate, ExecTestRaise: Boolean;
  ExecTestAllocation: NativeUInt;
  ExecTestProtection: Cardinal;
  ExecTestCount: Integer;
  ExecTestVisited: TDictionary<NativeUInt, Byte>;
function ExecTestQuery(Process: THandle; Address: NativeUInt;
  out Region: TThreadOriginRegion): Boolean;
begin
  Inc(ExecTestCount);
  ExecTestVisited.AddOrSetValue(Address, 1);
  Region := Default(TThreadOriginRegion);
  if ExecTestRaise then raise Exception.Create('synthetic region failure');
  if not ExecTestValid then Exit(False);
  Region.Known := True;
  Region.StartAddress := Address;
  Region.BaseAddress := Address and not NativeUInt($FFF);
  if ExecTestAllocation = 0 then Region.AllocationBase := Region.BaseAddress
  else Region.AllocationBase := ExecTestAllocation;
  Region.RegionSize := $1000;
  Region.State := $1000;
  Region.Protect := ExecTestProtection;
  if ExecTestPrivate then Region.RegionType := $20000 else Region.RegionType := $1000000;
  Result := True;
end;
function TestThreadExecutionHardening(out Failure: string;
  out Checks: Integer): Boolean;
var
  Saved: TExecutionQueryHook; M: TThreadExecutionProvenance;
  Threads: TThreadSampleMap; Entry: TExecutionEntry;
  Sample: TThreadSample; D: TDetectionKinds; I, Calls: Integer; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure AddThread(ID: Cardinal; Address: NativeUInt);
  begin
    Sample := Default(TThreadSample); Sample.ThreadID := ID; Sample.StartAddress := Address;
    Threads.AddOrSetValue(ID, Sample);
  end;
  procedure Setup;
  begin
    Threads.Clear; M.Reset; D := [];
    ExecTestValid := True; ExecTestPrivate := True; ExecTestRaise := False;
    ExecTestAllocation := 0; ExecTestProtection := $20; ExecTestCount := 0;
    ExecTestVisited.Clear;
    M.Examine(True, Threads, True, True, 1000, D);
    AddThread(7, $20000);
  end;
  function CurrentEntry: TExecutionEntry;
  begin
    if not M.FSeen.TryGetValue(7, Result) then raise Exception.Create('missing thread entry');
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; Threads := nil;
  Saved := ExecutionQueryHook; ExecTestVisited := nil;
  try
    try
      ExecutionQueryHook := ExecTestQuery;
      ExecTestVisited := TDictionary<NativeUInt, Byte>.Create;
      M := TThreadExecutionProvenance.Create; Threads := TThreadSampleMap.Create;
      Setup; M.Examine(True, Threads, True, False, 2000, D); Entry := CurrentEntry;
      Check(Entry.Eligible and (Entry.Confirmations = 1) and (D = []), 'new thread first private sample');
      ExecTestValid := False; M.Examine(True, Threads, True, False, 3000, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 0) and (Entry.AllocationBase = 0), 'failed query clears old region');
      Check(D = [], 'failed query cannot publish old confirmation');
      ExecTestValid := True; M.Examine(True, Threads, True, False, 4000, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 1) and (D = []), 'first post-failure sample only');
      M.Examine(True, Threads, True, False, 5000, D);
      Check(dkExecutionProvenance in D, 'second successful post-failure observation');
      Setup; M.Examine(True, Threads, True, False, 2000, D);
      ExecTestAllocation := $10000; M.Examine(True, Threads, True, False, 3000, D); Entry := CurrentEntry;
      Check((Entry.AllocationBase = $10000) and (Entry.Confirmations = 1), 'allocation change replaces old candidate');
      Check((Entry.FirstSeen = 3000) and (D = []), 'allocation change starts new window');
      M.Examine(True, Threads, True, False, 4000, D);
      Check(dkExecutionProvenance in D, 'new allocation can be confirmed');
      Setup; M.Examine(True, Threads, True, False, 2000, D);
      ExecTestProtection := $40; M.Examine(True, Threads, True, False, 3000, D); Entry := CurrentEntry;
      Check((Entry.Protection = $40) and (Entry.Confirmations = 1), 'protection change restarts');
      Setup; M.Examine(True, Threads, True, False, 2000, D);
      M.Examine(True, Threads, True, False, 2000, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 1) and (D = []), 'same tick cannot confirm twice');
      M.Examine(True, Threads, True, False, 14001, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 1) and (Entry.FirstSeen = 14001), 'expired candidate starts fresh');
      M.Examine(True, Threads, True, False, 15001, D);
      Check(dkExecutionProvenance in D, 'fresh window confirmed');
      Setup; M.Examine(True, Threads, True, False, 2000, D);
      ExecTestPrivate := False; M.Examine(True, Threads, True, False, 3000, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 0) and (Entry.AllocationBase = 0), 'normal image clears candidate');
      ExecTestPrivate := True; M.Examine(True, Threads, True, False, 4000, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 1) and (D = []), 'return to private starts at one');
      M.Examine(True, Threads, False, False, 5000, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 0) and (M.FSeen.Count = 1), 'incomplete snapshot clears counts not membership');
      M.Examine(True, nil, True, False, 6000, D);
      Check(M.FSeen.Count = 1, 'nil snapshot safely rejected');
      M.Examine(True, Threads, True, False, 7000, D);
      M.Examine(True, Threads, True, False, 100, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 1) and (D = []), 'clock rollback cannot reuse previous confirmations');
      Threads.Clear; M.Examine(True, Threads, True, False, 200, D);
      Check(M.FSeen.Count = 0, 'complete empty snapshot retires missing thread');
      Setup; M.Examine(True, Threads, True, True, 2000, D);
      M.Examine(True, Threads, True, False, 3000, D); M.Examine(True, Threads, True, False, 4000, D);
      Entry := CurrentEntry;
      Check(not Entry.Eligible and (D = []), 'startup thread exclusion preserved');
      AddThread(7, $30000); M.Examine(True, Threads, True, False, 5000, D); Entry := CurrentEntry;
      Check(Entry.Eligible and (Entry.StartAddress = $30000) and (Entry.Confirmations = 1), 'changed start is fresh eligible candidate');
      Setup; M.Examine(True, Threads, True, False, 2000, D);
      ExecTestRaise := True; Raised := False;
      try M.Examine(True, Threads, True, False, 3000, D); except on E: Exception do Raised := True; end;
      Entry := CurrentEntry;
      Check(Raised and (Entry.Confirmations = 0), 'query exception clears confirmation state');
      ExecTestRaise := False; M.Examine(False, Threads, True, False, 4000, D);
      Check(not M.FPrimed and (M.FSeen.Count = 0), 'other target resets own-process state');
      Setup; Sample.ThreadID := 9; Sample.StartAddress := $20000; Threads.AddOrSetValue(7, Sample);
      Calls := ExecTestCount; M.Examine(True, Threads, True, False, 2000, D); Entry := CurrentEntry;
      Check((Entry.Confirmations = 0) and (ExecTestCount = Calls), 'mismatched TID/key never queried');
      Setup; Threads.Clear;
      for I := 1 to 130 do AddThread(Cardinal(I), NativeUInt($10000) + NativeUInt(I) * $1000);
      for I := 0 to 2 do
      begin
        Calls := ExecTestCount; M.Examine(True, Threads, True, False, UInt64(2000 + I * 1000), D);
        Check(ExecTestCount - Calls <= MAX_THREAD_CHECKS_PER_SCAN, 'rotating thread budget respected');
      end;
      Check(ExecTestVisited.Count = 130, 'rotating budget reaches every stable thread');
      Check(ProvenanceConfirmed(True, 2, 100, 12100), 'legacy time boundary inclusive');
      Check(not ProvenanceConfirmed(True, 2, 100, 12101), 'legacy time window enforced');
      Check(not ProvenanceConfirmed(False, 2, 100, 200), 'baseline ineligibility predicate preserved');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    Threads.Free; M.Free; ExecTestVisited.Free; ExecTestVisited := nil;
    ExecutionQueryHook := Saved;
  end;
end;
