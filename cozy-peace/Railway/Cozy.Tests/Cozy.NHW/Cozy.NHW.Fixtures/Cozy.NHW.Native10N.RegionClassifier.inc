function TestRegionClassifier10N(out Failure: string; out Checks: Integer): Boolean;
var G: TMemoryRegionClassifier; A: TRegionObservation; D: TDetectionKinds;
    Failed: Boolean;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  G := nil; RegionFailCommit10N := False;
  try
    try
      G := TMemoryRegionClassifier.Create;
      A := Default(TRegionObservation); A.BaseAddress := $20000;
      A.AllocationBase := A.BaseAddress; A.Size := 4096; A.Kind := rcPrivateWritable;
      G.FCurrent.Add(A.BaseAddress, A); D := []; G.EndSweep(True, 100, D);
      Check((D = []) and G.FHaveBaseline and (G.FPrevious.Count = 1), 'complete initial baseline');
      A.Kind := rcPrivateExecutable; G.FCurrent.Add(A.BaseAddress, A);
      G.FPending.Add(A.BaseAddress, A);
      RegionFailCommit10N := True; Failed := False;
      try G.EndSweep(False, 200, D); except on E: EOutOfMemory do Failed := True; end;
      RegionFailCommit10N := False;
      Check(Failed, 'commit allocation-failure seam exercised');
      Check(G.FPrevious[A.BaseAddress].Kind = rcPrivateWritable, 'failed commit preserves whole old baseline');
      Check((G.FCurrent.Count = 0) and (G.FPending.Count = 0), 'failed observation clears working/candidate state');
      Check((D = []) and (G.FLastCompleteTick = 100), 'no partial report or complete timestamp on failure');
      G.FCurrent.Add(A.BaseAddress, A); G.EndSweep(False, 300, D);
      Check((D = []) and (G.FPending.Count = 1), 'first fresh transition remains pending');
      Check(G.FPrevious[A.BaseAddress].Kind = rcPrivateExecutable, 'successful commit adopts complete current data');
      G.FCurrent.Add(A.BaseAddress, A); G.EndSweep(False, 400, D);
      Check(dkPrivateExecRegion in D, 'second complete transition confirmation preserved');
      Check(G.FCurrent.Count = 0, 'old baseline storage recycled after ownership swap');
      G.FWorkingCounts.PrivateRWX := 5; G.CancelSweep;
      Check(G.Counts.PrivateRWX = 0, 'partial counts not published');
      Check(G.FPrevious.Count = 1, 'cancel does not erase accepted baseline');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    RegionFailCommit10N := False; G.Free;
  end;
end;
