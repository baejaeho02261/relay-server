function TestPathRules10Q(out Failure: string; out Checks: Integer): Boolean;
var
  R: TPathSignalRules; D: TDetectionKinds; I: Integer; E: TPathChangeEvent;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  R := nil;
  try
    try
      R := TPathSignalRules.Create; D := [];
      R.Signal(pcRoute, 1000, D);
      R.Signal(pcRoute, 1000, D);
      Check((R.FRecent.Count = 1) and (D = []), 'same category/time deduplicated');
      R.Signal(pcDNSPolicy, 1000, D);
      Check(dkPathCorrelation in D, 'different category same-time remains meaningful');
      Check(R.FRecent.Count = 2, 'different subsystems retained');
      D := []; R.Signal(pcWinsock, 900, D);
      Check((D = []) and (R.FRecent.Count = 2), 'late event does not alter timeline');
      R.Signal(pcWinsock, 1100, D);
      Check(dkNetworkIntegrity in D, 'three unique confirmed changes still burst');
      D := []; R.Signal(pcInterface, 1200, D); Check(D = [], 'burst cooldown maintained');
      R.Reset; D := [];
      for I := 1 to 1000 do R.Signal(pcRoute, UInt64(I), D);
      Check(R.FRecent.Count = PATH_HISTORY_LIMIT, 'bounded RAM under high event volume');
      Check(R.FRecent[0].Tick = 745, 'oldest event replaced at capacity');
      Check(R.FRecent[PATH_HISTORY_LIMIT-1].Tick = 1000, 'newest event retained');
      Check(not (dkNetworkIntegrity in D), 'one subsystem does not manufacture independent burst');
      R.Signal(pcRoute, 1000, D); Check(R.FRecent.Count = PATH_HISTORY_LIMIT, 'duplicate at capacity no eviction');
      R.Signal(pcRoute, 1000000, D); Check(R.FRecent.Count = 1, 'expired history fully pruned');
      R.Reset;
      E.Kind := pcRoute; E.Tick := 100000; R.FRecent.Add(E);
      E.Kind := pcWinsock; E.Tick := 1; R.FRecent.Add(E);
      E.Kind := pcInterface; E.Tick := 99999; R.FRecent.Add(E);
      R.Trim(100000); Check(R.FRecent.Count = 2, 'stale middle element removed, not just prefix');
      D := []; R.Signal(pcDNSPolicy, 0, D); Check(D = [], 'zero tick rejected');
      R.Reset; D := []; R.Signal(pcRoute, 1000, D); R.Signal(pcDNSPolicy, 35000, D);
      Check(not (dkPathCorrelation in D), 'correlation window unchanged');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    R.Free;
  end;
end;
