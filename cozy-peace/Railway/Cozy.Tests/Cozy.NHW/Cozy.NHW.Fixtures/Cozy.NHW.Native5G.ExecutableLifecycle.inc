var ExecTestOK, ExecTestAvailable, ExecTestRaise: Boolean;
function ExecTestAvailableCall: Boolean;
begin Result := ExecTestAvailable; end;
function ExecTestLimit: NativeUInt;
begin Result := $20000; end;
function ExecTestQuery(Address: NativeUInt; out R: TVirtualRegion): Boolean;
begin
  if ExecTestRaise then raise Exception.Create('synthetic executable query exception');
  R := Default(TVirtualRegion); R.BaseAddress := $10000; R.AllocationBase := $10000;
  R.Size := $10000; R.State := ALLOC_MEM_COMMIT; R.RegionType := ALLOC_MEM_PRIVATE;
  R.Protect := $20; Result := ExecTestOK and (Address = $10000);
end;
function TestExecutableLifecycleHardening(out Failure: string; out Checks: Integer): Boolean;
var
  M: TExecutableLifecycle;
  D: TDetectionKinds;
  Sample: TExecRegionSample;
  Candidate: TExecTransitionCandidate;
  SavedQuery: TExecQueryHook;
  SavedAvailable: TExecAvailableHook;
  SavedLimit: TExecLimitHook;
  Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Sweep(Protection: TExecProtection; Tick: UInt64;
    Independent, Baseline: Boolean);
  begin
    D := []; Sample := Default(TExecRegionSample);
    Sample.AllocationBase := $10000; Sample.Size := $1000; Sample.Protection := Protection;
    M.FCurrent.Clear; M.FCurrent.Add($10000, Sample);
    if Independent then M.FLastIndependent := Tick;
    M.EndSweep(Baseline, Tick, D);
  end;
  procedure Prime;
  begin
    M.Reset; ExecTestOK := True; ExecTestAvailable := True; ExecTestRaise := False;
    Sweep(epWritable, 1000, False, True);
    Sweep(epExecutable, 2000, False, False);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedQuery := ExecQueryHook; SavedAvailable := ExecAvailableHook; SavedLimit := ExecLimitHook;
  try
    try
      M := TExecutableLifecycle.Create;
      Prime;
      Check((M.FPending.Count = 1) and not (dkExecutableLifecycle in D), 'transition creates unconfirmed pending');
      Check(M.FPending.TryGetValue($10000, Candidate) and
        (Candidate.TransitionTick = 2000) and not Candidate.Reported, 'pending has occurrence and reporting state');
      Sweep(epExecutable, 2000, True, False);
      Check(not (dkExecutableLifecycle in D), 'same time cannot confirm a second sweep');
      Sweep(epExecutable, 3000, True, False);
      Check(dkExecutableLifecycle in D, 'later matching sweep and evidence detect');
      Check(M.FPending.TryGetValue($10000, Candidate) and Candidate.Reported,
        'reported candidate marked');
      Sweep(epExecutable, 65000, True, False);
      Check(not (dkExecutableLifecycle in D), 'reported candidate not repeated after cooldown');
      Sweep(epExecutable, 122001, True, False);
      Check((M.FPending.Count = 0) and not (dkExecutableLifecycle in D), 'expired transition removed');
      Sweep(epExecutable, 200000, True, False);
      Check((M.FPending.Count = 0) and not (dkExecutableLifecycle in D), 'unchanged old state not resurrected by new evidence');
      Sweep(epWritable, 201000, False, False);
      Sweep(epExecutable, 202000, True, False);
      Sweep(epExecutable, 203000, True, False);
      Check(dkExecutableLifecycle in D, 'a new real transition can still report');
      Prime; Sweep(epExecutable, 122000, True, False);
      Check(dkExecutableLifecycle in D, 'exact two-minute lifetime is allowed');
      Prime; Sweep(epExecutable, 122001, True, False);
      Check(not (dkExecutableLifecycle in D) and (M.FPending.Count = 0), 'one tick beyond lifetime rejected');
      Prime; Sweep(epExecutable, 3000, False, False);
      Check(not (dkExecutableLifecycle in D), 'no independent evidence no report');
      Check(M.FPending.TryGetValue($10000, Candidate) and Candidate.Confirmed,
        'confirmation can wait boundedly for corroboration');
      Sweep(epExecutable, 4000, True, False);
      Check(dkExecutableLifecycle in D, 'fresh evidence within lifetime can corroborate');
      Prime; Sweep(epWritable, 3000, True, False);
      Check((M.FPending.Count = 0) and not (dkExecutableLifecycle in D), 'reverted protection clears');
      Prime; Sweep(epExecutable, 3000, True, True);
      Check((M.FPending.Count = 0) and not (dkExecutableLifecycle in D), 'explicit baseline clears');
      Prime; M.FSweepBaseline := True; Sweep(epExecutable, 3000, True, False);
      Check((M.FPending.Count = 0) and not (dkExecutableLifecycle in D), 'baseline seen in any sweep step suppresses candidate');
      Prime; M.FCurrent.Clear; M.FLastIndependent := 3000;
      M.EndSweep(False, 3000, D);
      Check(M.FPending.Count = 0, 'missing region retires transition');
      Prime; Sample := M.FPrevious[$10000]; Sample.AllocationBase := $8000;
      M.FCurrent.Add($10000, Sample); D := []; M.FLastIndependent := 3000;
      M.EndSweep(False, 3000, D);
      Check(M.FPending.Count = 0, 'changed allocation cannot confirm');
      Prime; Sample := M.FPrevious[$10000]; Sample.Size := $2000;
      M.FCurrent.Add($10000, Sample); D := []; M.EndSweep(False, 3000, D);
      Check(M.FPending.Count = 0, 'changed extent cannot confirm');
      Prime; Sweep(epExecutable, 100, True, False);
      Check((M.FPending.Count = 0) and not (dkExecutableLifecycle in D), 'rollback drops future candidate');
      Prime; M.CancelSweep;
      Check((M.FPending.Count = 0) and not M.FRunning, 'cancel clears pending state');
      Check(M.FPrevious.Count = 1, 'cancel preserves last complete snapshot');
      ExecQueryHook := ExecTestQuery; ExecAvailableHook := ExecTestAvailableCall;
      ExecLimitHook := ExecTestLimit;
      Prime; ExecTestOK := False; D := []; M.Examine(False, True, 8000, D);
      Check((M.FPending.Count = 0) and not M.FRunning and not (dkExecutableLifecycle in D), 'failed sweep cannot use pending candidate');
      Prime; ExecTestAvailable := False; D := []; M.Examine(False, True, 8000, D);
      Check(M.FPending.Count = 0, 'unavailable collector invalidates pending');
      Prime; ExecTestRaise := True; Raised := False;
      try M.Examine(False, True, 8000, D); except on E: Exception do Raised := True; end;
      Check(Raised, 'query exception remains visible');
      Check((M.FPending.Count = 0) and not M.FRunning, 'query exception cancels partial sweep');
      Check(ClassifyPrivateProtection($20) = epExecutable, 'RX classification preserved');
      Check(ClassifyPrivateProtection($140) = epOther, 'guard page exclusion preserved');
      Check(IsExecutableTransition(epWritable, epRWX), 'RW to RWX preserved');
      Check(not IsExecutableTransition(epExecutable, epExecutable), 'unchanged state not transition');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; ExecQueryHook := SavedQuery; ExecAvailableHook := SavedAvailable; ExecLimitHook := SavedLimit;
  end;
end;
