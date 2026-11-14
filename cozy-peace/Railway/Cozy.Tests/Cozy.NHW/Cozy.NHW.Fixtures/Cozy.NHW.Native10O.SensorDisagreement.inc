function TestSensorDisagreement10O(out Failure: string; out Checks: Integer): Boolean;
var
  G: TSensorDisagreement;
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
      G := TSensorDisagreement.Create;
      G.Observe(True, True, True, False, False, True, 1000);
      Check((G.State.Kind = sdUncorroborated) and (G.State.Consecutive = 1), 'first valid disagreement');
      G.Observe(True, True, True, False, False, True, 1000);
      Check(G.State.Consecutive = 1, 'same tick cannot confirm');
      G.Observe(True, True, True, False, False, True, 1001);
      Check(G.State.Consecutive = 2, 'newer valid sample confirms');
      G.Observe(True, True, True, False, False, True, 900);
      Check((G.State.Kind = sdUnknown) and (G.State.Consecutive = 0), 'reverse tick becomes unknown boundary');
      G.Observe(True, True, True, False, False, True, 901);
      Check(G.State.Consecutive = 1, 'fresh sequence after reversal');
      G.Observe(True, True, True, False, False, True, 40000);
      Check(G.State.Consecutive = 1, 'long gap breaks consecutive sequence');
      G.Observe(False, True, True, False, False, True, 40001);
      Check((G.State.Kind = sdUnknown) and (G.State.Consecutive = 0), 'identity failure is not valid confirmation');
      G.Observe(True, True, True, False, False, True, 40002);
      Check(G.State.Consecutive = 1, 'after failed coverage restart at one');
      G.Observe(True, True, True, False, True, True, 40002);
      Check((G.State.Kind = sdUnknown) and (G.State.Consecutive = 0), 'conflicting duplicate cannot confirm either state');
      G.Observe(True, True, True, True, False, True, 40003);
      Check((G.State.Kind = sdCoverageGap) and (G.State.Consecutive = 0), 'lost trace is gap, not threat count');
      G.Observe(True, True, True, True, False, True, 40004);
      Check(G.State.Consecutive = 0, 'repeated losses never count as independent valid samples');
      G.Reset; G.Observe(True, True, True, False, True, False, 0);
      Check(G.State.Consecutive = 1, 'tick zero is a valid first timestamp');
      G.Observe(True, True, True, False, True, False, 0);
      Check(G.State.Consecutive = 1, 'duplicate zero timestamp ignored');
      G.FState.Consecutive := High(Cardinal);
      G.Observe(True, True, True, False, True, False, 1);
      Check(G.State.Consecutive = High(Cardinal), 'counter saturation avoids wrap');
      G.Observe(True, False, True, False, False, True, 2);
      Check(G.State.Consecutive = 0, 'invalid threads break coverage');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    G.Free;
  end;
end;
