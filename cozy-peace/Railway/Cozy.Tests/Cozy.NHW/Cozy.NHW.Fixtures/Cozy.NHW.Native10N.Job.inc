var JobCalls10N: Integer; JobSuccess10N, JobValue10N: Boolean;
function JobMock10N(H: THandle; out InJob: Boolean): Boolean;
begin
  Inc(JobCalls10N); InJob := JobValue10N;
  Result := JobSuccess10N and (H <> 0);
end;
function TestJob10N(out Failure: string; out Checks: Integer): Boolean;
var G: TJobMonitor; D: TDetectionKinds;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  G := nil;
  try
    try
      G := TJobMonitor.Create; G.Reset; JobQuery10N := JobMock10N;
      JobCalls10N := 0; JobSuccess10N := False; JobValue10N := True; D := [];
      G.Examine(1, 0, D); Check(JobCalls10N = 1, 'initial failure counted as attempt at zero tick');
      G.Examine(1, 0, D); G.Examine(1, 1999, D);
      Check(JobCalls10N = 1, 'failed attempts honor interval including zero tick');
      JobSuccess10N := True; G.Examine(1, 2000, D);
      Check((JobCalls10N = 2) and G.FPrimed and (D = []), 'first success seeds baseline');
      JobSuccess10N := False; G.Examine(1, 4000, D); G.Examine(1, 4001, D);
      Check((JobCalls10N = 3) and G.FLastInJob, 'failed refresh preserves last success and throttles');
      JobSuccess10N := True; JobValue10N := False; G.Examine(1, 6000, D);
      Check(dkJob in D, 'real observed membership transition still reports');
      D := []; G.Examine(1, 6001, D); Check(D = [], 'throttled call has no fabricated change');
      G.Examine(1, 100, D); Check(JobCalls10N = 5, 'backward clock starts a new attempt window');
      G.Reset; Check(not G.FPrimed and not G.FHaveAttempt, 'reset clears attempt and success independently');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    JobQuery10N := nil; G.Free;
  end;
end;
