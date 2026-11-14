var
  SectionTestRegion: TVirtualRegion;
  SectionTestOK, SectionTestRaise: Boolean;
function SectionTestQuery(Address: NativeUInt; out R: TVirtualRegion): Boolean;
begin
  if SectionTestRaise then raise Exception.Create('synthetic section query exception');
  R := SectionTestRegion;
  Result := SectionTestOK and (Address = $30040);
end;
function TestSectionCorrelationHardening(out Failure: string; out Checks: Integer): Boolean;
var
  N: TSectionThreadNode;
  R: TVirtualRegion;
  M: TSectionCorrelation;
  Threads: TThreadSampleMap;
  Sections: TList<TIPCObservation>;
  Thread: TThreadSample;
  S: TIPCObservation;
  D: TDetectionKinds;
  Saved: TSectionQueryHook;
  Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Setup;
  begin
    N := Default(TSectionThreadNode); N.StartAddress := $30040; N.Eligible := True;
    R := Default(TVirtualRegion); R.BaseAddress := $30000;
    R.AllocationBase := $30000; R.Size := $1000;
    R.State := ALLOC_MEM_COMMIT; R.RegionType := ALLOC_MEM_MAPPED; R.Protect := $20;
  end;
  procedure Prime;
  begin
    Setup; M.Reset; Threads.Clear; D := [];
    SectionTestRegion := R; SectionTestOK := True; SectionTestRaise := False;
    M.Examine(True, True, True, True, False, 1, Threads, nil, [], 1000, D);
    Thread := Default(TThreadSample); Thread.ThreadID := 10; Thread.StartAddress := $30040;
    Threads.Add(10, Thread);
  end;
  procedure Observe(Tick: UInt64);
  begin
    D := [];
    M.Examine(True, True, False, True, True, 1, Threads, Sections,
      [dkMappedView], Tick, D);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil; Threads := nil; Sections := nil; Saved := SectionQueryHook;
  try
    try
      Setup; Check(ApplySectionRegion(N, True, R, 1000) and
        (N.AllocationBase = $30000) and (N.Confirmations = 1), 'first mapping installed');
      ApplySectionRegion(N, True, R, 1000);
      Check(N.Confirmations = 1, 'same tick not recounted');
      ApplySectionRegion(N, True, R, 2000);
      Check(N.Confirmations = 2, 'same mapping confirms');
      N.Reported := True; R.AllocationBase := $20000;
      ApplySectionRegion(N, True, R, 3000);
      Check((N.AllocationBase = $20000) and (N.Confirmations = 1) and
        not N.Reported, 'remap replaces old base and opens new candidate');
      ApplySectionRegion(N, True, R, 4000);
      Check(N.Confirmations = 2, 'new base can confirm instead of resetting forever');
      Check(not ApplySectionRegion(N, False, R, 5000) and
        (N.Confirmations = 0), 'query failure breaks sequence');
      ApplySectionRegion(N, True, R, 6000);
      Check(N.Confirmations = 1, 'post-failure first read');
      ApplySectionRegion(N, True, R, 21000);
      Check(N.Confirmations = 2, 'exact candidate lifetime boundary');
      ApplySectionRegion(N, True, R, 21001);
      Check(N.Confirmations = 1, 'expired candidate starts anew');
      ApplySectionRegion(N, True, R, 100);
      Check(N.Confirmations = 1, 'rollback does not carry count');
      R.Protect := $40; ApplySectionRegion(N, True, R, 200);
      Check(N.Confirmations = 1, 'protection change is a distinct observation');
      R.Size := $2000; ApplySectionRegion(N, True, R, 300);
      Check(N.Confirmations = 1, 'extent change starts new candidate');
      R.RegionType := ALLOC_MEM_PRIVATE;
      Check(not ApplySectionRegion(N, True, R, 400) and (N.Confirmations = 0), 'private is not section mapping');
      Setup; R.Size := 0; Check(not ApplySectionRegion(N, True, R, 100), 'empty region rejected');
      Setup; R.AllocationBase := $40000;
      Check(not ApplySectionRegion(N, True, R, 100), 'invalid allocation relationship rejected');
      Setup; R.Protect := $120;
      Check(not ApplySectionRegion(N, True, R, 100), 'guard mapping rejected');
      SectionQueryHook := SectionTestQuery;
      M := TSectionCorrelation.Create; Threads := TThreadSampleMap.Create;
      Sections := TList<TIPCObservation>.Create;
      S := Default(TIPCObservation); S.Kind := ikSection; S.OwnerPID := 2;
      S.ObjectIdentity := $123; Sections.Add(S);
      Prime; Observe(2000); Check(not (dkSectionCorrelation in D), 'one sample not enough');
      SectionTestRegion.AllocationBase := $20000; Observe(3000);
      Check(not (dkSectionCorrelation in D), 'remap needs new confirmation');
      Observe(4000); Check(dkSectionCorrelation in D, 'confirmed remap still detects');
      Prime; Observe(2000); SectionTestOK := False; Observe(3000);
      Check(not (dkSectionCorrelation in D), 'failure cannot report');
      Check(M.FNodes.TryGetValue(10, N) and (N.Confirmations = 0), 'failed candidate cleared');
      SectionTestOK := True; Observe(4000); Check(not (dkSectionCorrelation in D), 'first recovery not detection');
      Observe(5000); Check(dkSectionCorrelation in D, 'fresh recovery confirms');
      Prime; Observe(2000);
      M.Examine(True, False, False, True, True, 1, Threads, Sections, [], 3000, D);
      Check(M.FNodes.TryGetValue(10, N) and (N.Confirmations = 0), 'incomplete snapshot invalidates');
      Check(M.FNodes.Count = 1, 'incomplete snapshot is not disappearance');
      M.Examine(True, True, False, True, True, 1, nil, Sections, [], 3500, D);
      Check(M.FNodes.Count = 1, 'nil snapshot handled safely');
      Prime; Observe(2000); SectionTestRaise := True; Raised := False;
      try Observe(3000); except on E: Exception do Raised := True; end;
      Check(Raised, 'exception propagated');
      Check(M.FNodes.TryGetValue(10, N) and (N.Confirmations = 0), 'exception clears pending confirmations');
      SectionTestRaise := False; Threads.Clear; Observe(4000);
      Check(M.FNodes.Count = 0, 'complete disappearance retires node');
      Prime; Observe(2000);
      M.Examine(True, True, True, True, True, 1, Threads, Sections, [], 3000, D);
      Check(M.FNodes.TryGetValue(10, N) and not N.Eligible and (N.Confirmations = 0), 'baseline does not collect candidate confidence');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    Sections.Free; Threads.Free; M.Free; SectionQueryHook := Saved;
  end;
end;
