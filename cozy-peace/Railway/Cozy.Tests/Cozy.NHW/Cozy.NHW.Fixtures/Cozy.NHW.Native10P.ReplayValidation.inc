function TestReplayValidation10P(out Failure: string; out Checks: Integer): Boolean;
var
  Steps: array[0..2] of TReplayStep;
  K: TDetectionKinds;
  N, I: Integer;
  Raised: Boolean;
  Detail: string;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;
  ReplayFailStage10P := 0;
  try
    try
      Steps[0] := Default(TReplayStep); Steps[0].Tick := 100;
      Steps[0].Observed := [dkProcess];
      Steps[1] := Default(TReplayStep); Steps[1].Tick := 200;
      Steps[1].Observed := [dkPrivateThread];
      Steps[2] := Default(TReplayStep); Steps[2].Tick := 150;
      K := [dkIAT]; N := 99;
      Check(not ReplayDetections(Steps, K, N), 'prevalidate reversed order');
      Check((K = []) and (N = 0), 'no partial outputs on invalid order');
      Steps[2].Tick := 300;
      for I := 1 to 4 do
      begin
        ReplayFailStage10P := I; Raised := False;
        K := [dkIAT]; N := 99;
        try ReplayDetections(Steps, K, N);
        except on E: Exception do Raised := True; end;
        Check(Raised, 'synthetic replay failure propagated');
        Check((K = []) and (N = 0), 'failure before publication leaves outputs empty');
      end;
      ReplayFailStage10P := 0;
      Check(ReplayDetections(Steps, K, N), 'ordered input');
      Check((N = 3) and (dkProcess in K), 'ordered output committed');
      Check(ReplayDetections([], K, N) and (K = []) and (N = 0), 'empty replay');
      Steps[2].Tick := 200;
      Check(ReplayDetections(Steps, K, N), 'equal ticks remain accepted for deterministic replay');
      Check(ValidateReplayRules(Detail), 'existing replay suite: ' + Detail);
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    ReplayFailStage10P := 0;
  end;
end;
