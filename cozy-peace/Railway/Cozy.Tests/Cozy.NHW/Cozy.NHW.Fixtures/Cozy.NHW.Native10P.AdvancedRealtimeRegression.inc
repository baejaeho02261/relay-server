function TestAdvancedRealtimeRegression10P(out Failure: string; out Checks: Integer): Boolean;
var
  I: Integer; Detail: string;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;
  RealtimeFailStage10P := 0;
  try
    try
      for I := 1 to 10 do
      begin
        RealtimeFailStage10P := I;
        Check(not ValidateRealtimeV90(Detail), 'synthetic allocation boundary fails cleanly');
        Check(Detail <> '', 'failure reports reason');
      end;
      RealtimeFailStage10P := 0;
      Check(ValidateRealtimeV90(Detail), 'existing realtime suite: ' + Detail);
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    RealtimeFailStage10P := 0;
  end;
end;
