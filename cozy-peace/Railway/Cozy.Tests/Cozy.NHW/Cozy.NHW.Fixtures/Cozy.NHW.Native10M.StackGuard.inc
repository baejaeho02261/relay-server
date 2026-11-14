function TestStackGuard10M(out Failure: string; out Checks: Integer): Boolean;
var M: TStackGuardMonitor; State: TThreadStackState;
    Current, Unknown: TNativeStackSnapshot; S: TStackSignals; D: TDetectionKinds;
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
      M := TStackGuardMonitor.Create;
      Current := Default(TNativeStackSnapshot); Current.Known := True;
      Current.BoundsValid := True; Current.HasGuard := True; Current.CreateTime := 7;
      Current.StackBase := $40000; Current.StackLimit := $30000;
      Current.AllocationBase := $20000; Current.CommittedBytes := $10000;
      State := Default(TThreadStackState); State.Snapshot := Current;
      Current.HasGuard := False;
      S := AnalyzeStackTransition(State, Current, 1000);
      Check((State.GuardMissing = 1) and (S = []), 'one missing guard is only a candidate');
      S := AnalyzeStackTransition(State, Current, 2000);
      Check((State.GuardMissing = 2) and not (ssGuard in S), 'two observations below threshold');
      Unknown := Default(TNativeStackSnapshot);
      S := AnalyzeStackTransition(State, Unknown, 3000);
      Check((S = []) and (State.GuardMissing = 0) and State.ObservationGap, 'unknown breaks confirmation');
      Check(State.Snapshot.CreateTime = 7, 'reference identity survives unknown');
      S := AnalyzeStackTransition(State, Current, 4000);
      Check((S = []) and (State.GuardMissing = 1), 'recovery starts a fresh run');
      S := AnalyzeStackTransition(State, Current, 5000);
      Check(not (ssGuard in S), 'no old count reused');
      S := AnalyzeStackTransition(State, Current, 6000);
      Check(ssGuard in S, 'three fresh observations still detect');
      BreakStackObservation(State);
      S := AnalyzeStackTransition(State, Current, 7000);
      S := S + AnalyzeStackTransition(State, Current, 8000);
      S := S + AnalyzeStackTransition(State, Current, 9000);
      Check(not (ssGuard in S), 'unknown does not erase reported latch');
      Current.HasGuard := True; S := AnalyzeStackTransition(State, Current, 10000);
      Check((State.GuardMissing = 0) and not State.GuardReported, 'positive guard re-arms normally');
      State.BoundsMissing := 2; State.WindowTick := 100;
      M.FKnown.Add(1, State); D := [dkHeapState];
      M.Examine(42, nil, False, 11000, False, False, D);
      State := M.FKnown[1];
      Check((State.BoundsMissing = 0) and State.ObservationGap, 'invalid snapshot invalidates all pending state');
      Check(State.WindowTick = 0, 'growth window broken by failure');
      Check(D = [dkHeapState], 'unrelated detections preserved');
      M.InvalidateCandidate(99);
      Check(M.FKnown.Count = 1, 'missing ID invalidation is a no-op');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
