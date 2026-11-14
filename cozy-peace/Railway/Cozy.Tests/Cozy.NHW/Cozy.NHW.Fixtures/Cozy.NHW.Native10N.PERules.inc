function TestPERules10N(out Failure: string; out Checks: Integer): Boolean;
var C: TPEWatchCell; F: TPEFeature;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
begin
  Result := False; Failure := ''; Checks := 0;

  try
    try
      C := Default(TPEWatchCell); F := Default(TPEFeature);
      F.Available := True; F.Valid := True; F.Digest := 100;
      Check(not PEObserve(C, F, True), 'baseline is not a detection');
      Check(C.Fingerprint.HasBaseline and (C.Fingerprint.Baseline = 100), 'good baseline established');
      F.Digest := 200; Check(not PEObserve(C, F, False), 'first changed digest pending');
      F.Available := False; Check(not PEObserve(C, F, False), 'unavailable is unknown');
      Check((C.Fingerprint.CandidateCount = 0) and (C.Fingerprint.Baseline = 100), 'gap clears pending only');
      F.Available := True; Check(not PEObserve(C, F, False), 'new first after gap');
      Check(PEObserve(C, F, False), 'two fresh valid changes still detect');
      PEObservationGap(C); Check(C.Fingerprint.AlreadyReported, 'gap does not rearm reported fingerprint');
      Check(not PEObserve(C, F, False), 'same reported fingerprint not re-reported after gap');
      C := Default(TPEWatchCell); F.Digest := 100; PEObserve(C, F, True);
      F.Valid := False; Check(not PEObserve(C, F, False), 'first structural invalid sample');
      F.Available := False; PEObserve(C, F, False);
      Check(C.Invalid.Consecutive = 0, 'invalid condition interrupted by unavailable data');
      F.Available := True; Check(not PEObserve(C, F, False), 'invalid confirmation restarts');
      Check(PEObserve(C, F, False), 'two fresh structural invalid samples detect');
      PEObservationGap(C); Check(C.Invalid.Reported, 'unknown interval preserves reported-invalid latch');
      F.Valid := True; F.Digest := 100; PEObserve(C, F, False);
      Check(not C.Invalid.Reported, 'actual valid metadata clears invalid latch');
      F.Digest := 200; PEObserve(C, F, False); F.Valid := False; PEObserve(C, F, False);
      F.Valid := True; Check(not PEObserve(C, F, False), 'invalid sample cannot be a valid digest confirmation');
      Check(C.Invalid.Consecutive = 0, 'valid sample breaks invalid sequence');
      F.Digest := 300; PEObserve(C, F, True);
      Check((C.Fingerprint.Baseline = 100) and (C.Fingerprint.CandidateCount = 0), 'baseline mode does not auto-approve changed existing baseline');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    { no resources }
  end;
end;
