function TestPELoader10M(out Failure: string; out Checks: Integer): Boolean;
var Cell: TPEWatchCell; Feature: TPEFeature;
    M: TPELoaderMonitor; D: TDetectionKinds; Raised: Boolean;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil;
  try
    try
      Cell := Default(TPEWatchCell); Feature := Default(TPEFeature);
      Feature.Available := True; Feature.Valid := True; Feature.Digest := 10;
      Check(not ObservePEFeature(Cell, Feature, True), 'initial PE reference');
      Feature.Digest := 20;
      Check(not ObservePEFeature(Cell, Feature, False), 'first digest change candidate');
      Check(Cell.Fingerprint.CandidateCount = 1, 'one confirmation');
      Feature.Available := False;
      Check(not ObservePEFeature(Cell, Feature, False), 'unavailable feature not detected');
      Check(Cell.Fingerprint.HasBaseline and (Cell.Fingerprint.Baseline = 10), 'accepted digest preserved');
      Check(Cell.Fingerprint.CandidateCount = 0, 'unknown clears pending digest count');
      Feature.Available := True;
      Check(not ObservePEFeature(Cell, Feature, False), 'first fresh change cannot confirm');
      Check(ObservePEFeature(Cell, Feature, False), 'second fresh change confirms');
      BreakPEObservation(Cell);
      Check(Cell.Fingerprint.AlreadyReported, 'reported digest latch preserved');
      Check(not ObservePEFeature(Cell, Feature, False), 'no repeat after unknown');
      Feature.Valid := False;
      Check(not ObservePEFeature(Cell, Feature, False), 'first invalid metadata candidate');
      Feature.Available := False; ObservePEFeature(Cell, Feature, False);
      Check(Cell.Invalid.Consecutive = 0, 'invalid metadata run interrupted');
      M := TPELoaderMonitor.Create; M.FHeader := Cell;
      M.FHeader.Fingerprint.CandidateCount := 1;
      M.FSections := M.FHeader; PE10MMode := 1; D := [dkHeapState];
      M.Examine(False, 10000, D);
      Check((M.FHeader.Fingerprint.CandidateCount = 0) and
        (M.FSections.Fingerprint.CandidateCount = 0), 'whole capture failure clears all candidates');
      Check(D = [dkHeapState], 'other sensor detections retained');
      M.FHeader.Fingerprint.CandidateCount := 1; PE10MMode := 2; Raised := False;
      try M.Examine(False, 13000, D); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FHeader.Fingerprint.CandidateCount = 0), 'exception also breaks confirmation');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    PE10MMode := 0; M.Free;
  end;
end;
