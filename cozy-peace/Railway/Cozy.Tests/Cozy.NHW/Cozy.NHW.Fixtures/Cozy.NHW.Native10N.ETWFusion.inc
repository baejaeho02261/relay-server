function TestETWFusion10N(out Failure: string; out Checks: Integer): Boolean;
var G: TETWFusion; Events: TKernelEventList; Threads: TThreadSampleMap;
    E: TKernelEvent; D: TDetectionKinds;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  G := nil; Events := nil; Threads := nil;
  try
    try
      G := TETWFusion.Create; Events := TKernelEventList.Create; Threads := TThreadSampleMap.Create;
      E := Default(TKernelEvent); E.PID := 42; E.ThreadID := 7;
      E.Kind := keThreadStart; E.Tick := 100; Events.Add(E); D := [];
      G.Examine(Events, 42, Threads, True, False, False, False, 100, D);
      Check(G.FThreadBegins.Count = 1, 'valid start stored');
      Events.Clear; E.Kind := keThreadEnd; E.Tick := 200; Events.Add(E);
      G.Examine(Events, 42, Threads, False, False, False, False, 200, D);
      Check(not (dkTransientThread in D), 'failed snapshot is not evidence of absence');
      Check(G.FThreadBegins.Count = 0, 'failed snapshot invalidates prior thread pair');
      G.Examine(Events, 42, nil, True, False, False, False, 201, D);
      Check(not (dkTransientThread in D), 'nil snapshot cannot prove absence');
      Events.Clear; E.Kind := keThreadStart; E.Tick := 300; Events.Add(E);
      E.Kind := keThreadEnd; E.Tick := 400; Events.Add(E);
      D := []; G.Examine(Events, 42, Threads, True, False, False, False, 400, D);
      Check(dkTransientThread in D, 'valid fresh start/end and absent thread still detect');
      Events.Clear; E.Kind := keThreadStart; E.Tick := 500; Events.Add(E);
      D := []; G.Examine(Events, 42, Threads, True, True, False, False, 500, D);
      G.Examine(Events, 42, Threads, True, True, False, True, 600, D);
      Check(dkTraceGap in D, 'loss warning retained');
      Check((G.FThreadBegins.Count = 0) and (G.FLastExternalTick = 0) and
        (G.FLastRelevantTick = 0), 'loss clears correlation state');
      D := []; G.Examine(Events, 42, Threads, True, False, False, False, 700, D);
      Check(G.FThreadBegins.Count = 0, 'old event after loss cannot reseed evidence');
      Events.Clear; E.Tick := 800; E.Kind := keThreadStart; Events.Add(E);
      E.Tick := 750; Events.Add(E);
      G.Examine(Events, 42, Threads, True, False, False, False, 800, D);
      Check(G.FThreadBegins[7] = 800, 'late start cannot rewind newest start');
      Events.Clear; E.Tick := 770; E.Kind := keThreadEnd; Events.Add(E);
      G.Examine(Events, 42, Threads, True, False, False, False, 900, D);
      Check(G.FThreadBegins.ContainsKey(7), 'older end cannot erase newer start');
      G.Examine(nil, 42, Threads, True, False, False, False, 901, D);
      Check(G.FThreadBegins.Count = 1, 'nil event batch handled safely');
      G.Examine(nil, 42, Threads, True, False, True, False, 902, D);
      Check((G.FThreadBegins.Count = 0) and not G.FHaveGap, 'baseline resets evidence');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Threads.Free; Events.Free; G.Free;
  end;
end;
