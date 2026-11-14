function TestBehavior10N(out Failure: string; out Checks: Integer): Boolean;
var G: TBehaviorMonitor; H: TTargetHolder; D: TDetectionKinds;
    Raised: Boolean; I: Integer;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  G := nil; BehaviorFailSample10N := False; BehaviorFailState10N := False;
  try
    try
      G := TBehaviorMonitor.Create;
      BehaviorSamplesFreed10N := 0; BehaviorStatesFreed10N := 0;
      G.BeginSnapshot(100, False, False, True);
      H := Default(TTargetHolder); H.PID := 42; H.CreateTime := 100; H.HandleCount := 1;
      BehaviorFailSample10N := True; Raised := False;
      try G.Observe(H, True, False, False, False); except on E: EOutOfMemory do Raised := True; end;
      BehaviorFailSample10N := False;
      Check(Raised and (BehaviorSamplesFreed10N = 1), 'unregistered sample freed on Add failure');
      Check(G.FCurrent.Count = 0, 'failed sample not owned by dictionary');
      G.Observe(H, True, False, False, False);
      Check(G.FCurrent.Count = 1, 'sample registers normally');
      BehaviorFailState10N := True; Raised := False; D := [];
      try G.EndSnapshot(D); except on E: EOutOfMemory do Raised := True; end;
      BehaviorFailState10N := False;
      Check(Raised and (BehaviorStatesFreed10N = 1), 'unregistered owner state freed on Add failure');
      Check((G.FStates.Count = 0) and (D = []), 'failed owner does not generate detection');
      G.EndSnapshot(D); Check(G.FStates.Count = 1, 'normal owner registration survives');
      G.Reset; G.BeginSnapshot(1000, False, False, False);
      for I := 1 to 3 do
      begin H.PID := Cardinal(100+I); G.Observe(H, True, False, False, False); end;
      D := []; G.EndSnapshot(D);
      Check(dkCrossAccess in D, 'existing cross-owner behavior retained');
      Check(G.FStates.Count = 3, 'three independent owners retained');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    BehaviorFailSample10N := False; BehaviorFailState10N := False; G.Free;
  end;
end;
