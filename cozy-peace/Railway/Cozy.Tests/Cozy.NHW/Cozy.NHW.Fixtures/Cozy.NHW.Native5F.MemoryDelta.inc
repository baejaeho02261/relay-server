var
  DeltaTestRegion: TVirtualRegion;
  DeltaTestOK, DeltaTestAvailable, DeltaTestRaise: Boolean;
function DeltaTestIsAvailable: Boolean;
begin Result := DeltaTestAvailable; end;
function DeltaTestMax: NativeUInt;
begin Result := $20000; end;
function DeltaTestQuery(Address: NativeUInt; out R: TVirtualRegion): Boolean;
begin
  if DeltaTestRaise then raise Exception.Create('synthetic metadata query exception');
  R := Default(TVirtualRegion);
  Result := DeltaTestOK and (Address = DeltaTestRegion.BaseAddress);
  if Result then R := DeltaTestRegion;
end;
function TestMemoryDeltaHardening(out Failure: string;
  out Checks: Integer): Boolean;
var
  SavedAvailable: TDeltaAvailableHook; SavedMax: TDeltaMaxHook; SavedQuery: TDeltaQueryHook;
  M: TIncrementalMemoryDelta; A: TMemoryDeltaMark; R: TVirtualRegion;
  I: Integer; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Setup;
  begin
    A := Default(TMemoryDeltaMark);
    A.BaseAddress := $10000; A.AllocationBase := $10000; A.RegionSize := $1000;
    A.RegionType := ALLOC_MEM_PRIVATE; A.Protect := $04; A.State := ALLOC_MEM_COMMIT;
    R := Default(TVirtualRegion); R.BaseAddress := A.BaseAddress;
    R.AllocationBase := A.AllocationBase; R.Size := A.RegionSize;
    R.RegionType := A.RegionType; R.State := A.State; R.Protect := $20;
  end;
  procedure SetupMonitor;
  begin
    Setup; M.Reset; DeltaTestOK := True; DeltaTestAvailable := True; DeltaTestRaise := False;
    DeltaTestRegion := R; DeltaTestRegion.Protect := $04;
    M.AddMark(DeltaTestRegion); DeltaTestRegion.Protect := $20;
  end;
begin
  Failure := ''; Checks := 0; Result := False; M := nil;
  SavedAvailable := DeltaAvailableHook; SavedMax := DeltaMaxHook; SavedQuery := DeltaQueryHook;
  try
    try
      Setup;
      Check(not ApplyDeltaSample(A, True, R, False, 1000) and
        (A.Confirmations = 1), 'first changed pair');
      Check(not ApplyDeltaSample(A, True, R, False, 1000) and
        (A.Confirmations = 1), 'same tick cannot confirm');
      Check(ApplyDeltaSample(A, True, R, False, 2000) and
        (A.Protect = $20) and (A.State = ALLOC_MEM_COMMIT), 'second distinct read confirms');
      Check((A.Confirmations = 0) and (A.PendingProtect = 0) and
        (A.PendingState = 0), 'confirmed candidate cleared');
      Check(not ApplyDeltaSample(A, True, R, False, 3000), 'unchanged metadata does not recount');
      Setup; ApplyDeltaSample(A, True, R, False, 1000);
      Check(not ApplyDeltaSample(A, False, R, False, 2000) and
        (A.Confirmations = 0) and (A.Protect = $04), 'query failure preserves baseline only');
      Check(not ApplyDeltaSample(A, True, R, False, 3000) and
        (A.Confirmations = 1), 'post-failure restarts confirmation');
      Setup; ApplyDeltaSample(A, True, R, False, 1000); R.Protect := $04;
      Check(not ApplyDeltaSample(A, True, R, False, 2000) and
        (A.Confirmations = 0), 'return to baseline clears');
      Setup;
      Check(not ApplyDeltaSample(A, True, R, True, 1000) and
        (A.Protect = $20) and (A.State = R.State), 'baseline updates actual protection/state');
      Check(not ApplyDeltaSample(A, True, R, False, 2000), 'baseline update not reported as later transition');
      Setup; A.NeedsBaseline := True;
      Check(not ApplyDeltaSample(A, False, R, False, 1000) and A.NeedsBaseline,
        'deferred baseline survives read failure');
      Check(not ApplyDeltaSample(A, True, R, False, 2000) and
        not A.NeedsBaseline and (A.Protect = $20), 'deferred baseline applied silently');
      Setup; R.State := ALLOC_MEM_RESERVE; R.Protect := $04;
      ApplyDeltaSample(A, True, R, False, 1000);
      Check((A.PendingProtect = 0) and (A.PendingState = ALLOC_MEM_RESERVE), 'reserved protection normalized');
      R.State := ALLOC_MEM_COMMIT; R.Protect := 0;
      Check(not ApplyDeltaSample(A, True, R, False, 2000) and
        (A.Confirmations = 1) and (A.PendingState = ALLOC_MEM_COMMIT), 'same protection different state restarts');
      Setup; ApplyDeltaSample(A, True, R, False, 1000);
      Check(not ApplyDeltaSample(A, True, R, False, 121001) and
        (A.Confirmations = 1), 'two-minute candidate expiration');
      Setup; ApplyDeltaSample(A, True, R, False, 1000);
      Check(ApplyDeltaSample(A, True, R, False, 121000), 'exact candidate lifetime boundary');
      Setup; ApplyDeltaSample(A, True, R, False, 1000);
      Check(not ApplyDeltaSample(A, True, R, False, 10) and
        (A.Confirmations = 1), 'rollback starts new candidate');
      Setup; R.AllocationBase := $20000;
      Check(not ApplyDeltaSample(A, True, R, False, 1000) and
        (A.BaseAddress = 0), 'allocation identity mismatch invalidates mark');
      Setup; R.Size := $2000;
      Check(not ApplyDeltaSample(A, True, R, False, 1000) and
        (A.BaseAddress = 0), 'split/merge extent change invalidates mark');
      Setup; R.State := ALLOC_MEM_FREE;
      Check(not ApplyDeltaSample(A, True, R, False, 1000) and
        (A.BaseAddress = 0), 'freed region invalidates mark');
      Setup; ApplyDeltaSample(A, True, R, False, 1000); R.Size := 0;
      Check(not ApplyDeltaSample(A, True, R, False, 2000) and
        (A.Confirmations = 0) and (A.Protect = $04), 'invalid successful query clears pending');
      DeltaAvailableHook := DeltaTestIsAvailable; DeltaMaxHook := DeltaTestMax;
      DeltaQueryHook := DeltaTestQuery; M := TIncrementalMemoryDelta.Create; SetupMonitor;
      M.Examine(True, False, True, 1000);
      Check((M.FMarks[0].Confirmations = 1) and (M.ObservedTransitions = 0), 'one mark visited once per call');
      M.Examine(True, False, True, 1000);
      Check((M.FMarks[0].Confirmations = 1) and (M.ObservedTransitions = 0), 'same-call tick cannot double count');
      M.Examine(True, False, True, 2000);
      Check((M.ObservedTransitions = 1) and (M.LastChangeTick = 2000), 'two invocation transition counted');
      M.Examine(True, False, True, 3000);
      Check(M.ObservedTransitions = 1, 'stable observation not counted repeatedly');
      SetupMonitor; M.Examine(True, True, False, 1000);
      Check(M.FMarks[0].NeedsBaseline, 'skipped baseline pass marks pending refresh');
      M.Examine(True, False, True, 2000);
      Check((M.ObservedTransitions = 0) and not M.FMarks[0].NeedsBaseline and
        (M.FMarks[0].Protect = $20), 'delayed baseline refresh after budget skip');
      SetupMonitor; M.Examine(True, True, True, 1000);
      Check((M.FMarks[0].Protect = $20) and (M.ObservedTransitions = 0), 'monitor baseline refresh');
      M.Examine(True, False, True, 2000);
      Check(M.ObservedTransitions = 0, 'monitor baseline remains silent');
      SetupMonitor; M.Examine(True, False, True, 1000); DeltaTestOK := False;
      M.Examine(True, False, True, 2000);
      Check(M.FMarks[0].Confirmations = 0, 'monitor query failure clears');
      DeltaTestOK := True; M.Examine(True, False, True, 3000);
      Check(M.ObservedTransitions = 0, 'monitor recovery fresh sample');
      DeltaTestAvailable := False; M.Examine(True, False, True, 4000);
      Check(M.FMarks[0].Confirmations = 0, 'sensor unavailable invalidates pending');
      SetupMonitor; M.Examine(True, False, True, 1000); M.Examine(False, False, True, 2000);
      Check(M.FMarks[0].Confirmations = 0, 'non-self target clears pending');
      SetupMonitor; M.Examine(True, False, True, 1000); DeltaTestRaise := True; Raised := False;
      try M.Examine(True, False, True, 2000); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FMarks[0].Confirmations = 0) and
        (M.ObservedTransitions = 0), 'query exception clears before engine handling');
      SetupMonitor;
      for I := 1 to 300 do
      begin R := DeltaTestRegion; R.BaseAddress := NativeUInt($10000) + NativeUInt(I) * $1000;
        R.AllocationBase := R.BaseAddress; M.AddMark(R); end;
      Check((M.FCount = 256) and (M.FNextStore < 256), 'RAM cache stays bounded');
      M.Reset;
      Check((M.FCount = 0) and (M.LastChangeTick = 0) and
        (M.ObservedTransitions = 0), 'reset clears state and metrics');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; DeltaAvailableHook := SavedAvailable; DeltaMaxHook := SavedMax; DeltaQueryHook := SavedQuery;
  end;
end;
