function TestRealtimeFusion10M(out Failure: string; out Checks: Integer): Boolean;
var M: TRealtimeFusion; Items: TFastKernelSampleList;
    Item: TFastKernelSample; Relevant: Boolean;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil; Items := nil;
  try
    try
      M := TRealtimeFusion.Create; Items := TFastKernelSampleList.Create;
      Item := Default(TFastKernelSample); Item.Event.PID := 42; Item.Event.Kind := keThreadStart;
      Item.Event.Tick := 5000; Items.Add(Item); Item.Event.Tick := 1000; Items.Add(Item);
      M.Observe(Items, 42, Relevant);
      Check(Relevant and (M.FLastThread = 5000), 'late old thread event cannot rewind maximum');
      Check(M.CorrelatedWithExternal(True, 7000), 'latest thread evidence still correlates');
      Check(not M.CorrelatedWithExternal(True, 7501), 'original window still expires');
      Items.Clear; Item.Event.Kind := keImageLoad; Item.Event.Tick := 9000; Items.Add(Item);
      Item.Event.Tick := 8000; Items.Add(Item); M.Observe(Items, 42, Relevant);
      Check((M.FLastImage = 9000) and (M.FLastThread = 5000), 'image/thread maxima independent');
      Check(not M.CorrelatedWithExternal(False, 9000), 'external rights requirement retained');
      M.Reset; Items.Clear; Item.Event.Tick := 10000; Items.Add(Item); M.Observe(Items, 42, Relevant);
      Check(not M.CorrelatedWithExternal(True, 9999), 'future event cannot underflow age');
      Items.Clear; Item.Event.PID := 99; Item.Event.ParentPID := 0; Item.Event.Tick := 20000;
      Items.Add(Item); M.Observe(Items, 42, Relevant);
      Check(not Relevant and (M.FLastImage = 10000), 'unrelated process ignored');
      Items.Clear; Item.Event.PID := 42; Items.Add(Item); M.FObservedCount := High(UInt64);
      M.Observe(Items, 42, Relevant);
      Check(M.ObservedCount = High(UInt64), 'observational counter saturates');
      M.Observe(nil, 42, Relevant); Check(not Relevant, 'nil list');
      M.Observe(Items, 0, Relevant); Check(not Relevant, 'zero target rejected');
      M.Reset;
      Check((M.FLastThread = 0) and (M.FLastImage = 0) and (M.ObservedCount = 0), 'session reset');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Items.Free; M.Free;
  end;
end;
