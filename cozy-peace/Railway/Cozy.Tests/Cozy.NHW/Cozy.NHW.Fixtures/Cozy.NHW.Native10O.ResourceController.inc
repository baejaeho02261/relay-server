function TestResourceController10O(out Failure: string; out Checks: Integer): Boolean;
var
  G: TResourceAwareController;
  D: TDetectionKinds;
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
      G := TResourceAwareController.Create; D := [];
      Check(G.Load = slNormal, 'initial state');
      Check(G.ShouldRunHeavy(False, 0), 'initial zero tick grant');
      Check(not G.ShouldRunHeavy(False, 1), 'zero tick does not bypass interval');
      G.Reset;
      G.ObserveScan(1000, 0, 250, 1000, D);
      G.ObserveScan(1000, 0, 250, 2000, D);
      Check(G.Load = slNormal, 'pressure requires three observations');
      G.ObserveScan(1000, 0, 250, 3000, D);
      Check((G.Load = slDegraded) and (dkSensorPressure in D), 'third pressure observation activates degraded');
      G.ShouldRunHeavy(True, 20000);
      Check(G.Load = slDegraded, 'hot event cannot override pressure');
      G.ShouldRunHeavy(False, 33000);
      Check(G.Load = slDegraded, 'degraded deadline inclusive');
      G.ShouldRunHeavy(False, 33001);
      Check(G.Load = slHot, 'degraded expiry restores still-live hot state');
      G.ShouldRunHeavy(False, 40000);
      Check(G.Load = slHot, 'hot deadline inclusive');
      G.ShouldRunHeavy(False, 40001);
      Check(G.Load = slNormal, 'normal only after both deadlines expire');
      G.ShouldRunHeavy(True, 50000);
      Check(G.Load = slHot, 'new event activates hot state');
      G.ShouldRunHeavy(False, 100);
      Check(G.Load = slNormal, 'clock reversal resets stale time windows');
      G.ShouldRunHeavy(True, High(UInt64) - 1);
      Check(G.FHotUntil = High(UInt64), 'hot deadline saturation');
      Check(OptionalInspectionInterval(slDegraded) = 15000, 'pressure cadence unchanged');
      Check(OptionalInspectionInterval(slHot) = 2000, 'hot cadence unchanged');
      Check(OptionalInspectionInterval(slNormal) = 8000, 'normal cadence unchanged');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    G.Free;
  end;
end;
