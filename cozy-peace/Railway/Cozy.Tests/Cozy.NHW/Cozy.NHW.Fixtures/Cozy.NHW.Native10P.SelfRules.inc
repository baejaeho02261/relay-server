function TestSelfRules10P(out Failure: string; out Checks: Integer): Boolean;
var
  S: TStableFingerprint;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;

  try
    try
      S := Default(TStableFingerprint);
      Check(not ObserveFingerprint(S, 99, False), 'invalid is not baseline');
      Check(not S.HasBaseline, 'baseline remains unknown');
      Check(not ObserveFingerprint(S, 10, True), 'first baseline');
      Check(not ObserveFingerprint(S, 20, True), 'first change');
      Check(S.CandidateCount = 1, 'candidate starts at one');
      Check(not ObserveFingerprint(S, 999, False), 'failed observation');
      Check(S.HasBaseline and (S.Baseline = 10), 'approved baseline preserved');
      Check(S.CandidateCount = 0, 'failure breaks candidate');
      Check(not ObserveFingerprint(S, 20, True), 'recovery needs first sample');
      Check(ObserveFingerprint(S, 20, True), 'second fresh sample reports');
      Check(not ObserveFingerprint(S, 20, False), 'failure after report');
      Check(not ObserveFingerprint(S, 20, True), 'no duplicate report after gap');
      Check(not ObserveFingerprint(S, 20, True), 'dedupe survives second read');
      Check(not ObserveFingerprint(S, 10, True), 'normal restoration');
      Check(not S.AlreadyReported, 'restoration re-arms');
      Check(not ObserveFingerprint(S, 20, True), 'new sequence');
      Check(ObserveFingerprint(S, 20, True), 'new sequence reports');
      Check(not ObserveFingerprint(S, 30, True), 'different candidate');
      Check(not ObserveFingerprint(S, 40, True), 'candidate replaced');
      Check(ObserveFingerprint(S, 40, True), 'replacement confirmed');
      Check(not WithinBoundaryWindow(5, 10, 100), 'reverse time excluded');
      Check(WithinBoundaryWindow(110, 10, 100), 'inclusive boundary');
      Check(not WithinBoundaryWindow(111, 10, 100), 'expired boundary');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    // No owned resources.
  end;
end;
