function TestFastEventRing10Q(out Failure: string; out Checks: Integer): Boolean;
var
  R: TFastEventRing; E: TKernelEvent; Sample, Empty: TFastKernelSample; I: Integer;
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
      R := TFastEventRing.Create; E := Default(TKernelEvent); E.PID := 123;
      Check(R.Pending = 0, 'empty ring');
      Check(not R.Pop(Sample), 'empty pop');
      Check(not R.ConsumeLoss, 'initial loss latch empty');
      for I := 1 to NHW_FAST_RING_CAPACITY - 1 do
      begin
        E.ThreadID := Cardinal(I);
        Check(R.Push(E, I), 'bounded fill');
      end;
      Check(not R.Push(E, 2000), 'full push rejected');
      Check(R.DroppedTotal = 1, 'loss total increases');
      Check(R.ConsumeLoss, 'full queue announces loss');
      Check(not R.ConsumeLoss, 'latch consumed only once');
      for I := 1 to NHW_FAST_RING_CAPACITY - 1 do
      begin
        Check(R.Pop(Sample), 'all accepted samples delivered');
        Check(Sample.Event.ThreadID = Cardinal(I), 'event order preserved');
        Check(Sample.Serial = Cardinal(I), 'serial order preserved');
      end;
      Check(R.Pending = 0, 'drained queue');
      Empty := Default(TFastKernelSample);
      for I := 0 to NHW_FAST_RING_CAPACITY - 1 do
        Check(CompareMem(@R.FSlots[I], @Empty, SizeOf(Empty)), 'consumed slots cleared before reuse');
      R.FSerial := High(Cardinal) - 1;
      Check(R.Push(E, 3000) and R.Pop(Sample), 'serial maximum enqueue');
      Check(Sample.Serial = High(Cardinal), 'maximum serial emitted');
      Check(R.Push(E, 3001) and R.Pop(Sample), 'serial wrap under Q+/R+');
      Check(Sample.Serial = 0, 'explicit unsigned protocol wrap');
      Check(R.Push(E, 3002) and R.Pop(Sample), 'after wrap enqueue');
      Check(Sample.Serial = 1, 'sequence resumes at one');
      for I := 1 to NHW_FAST_RING_CAPACITY - 1 do R.Push(E, 4000);
      TInterlocked.Exchange(R.FDropped, Int64(High(Cardinal)) - 1);
      Check(not R.Push(E, 4001), 'penultimate loss');
      Check(R.DroppedTotal = High(Cardinal), 'counter reaches full unsigned maximum');
      Check(R.ConsumeLoss, 'saturation transition announced');
      Check(not R.Push(E, 4002), 'loss after saturation');
      Check(R.DroppedTotal = High(Cardinal), 'total does not wrap');
      Check(R.ConsumeLoss, 'new loss still announced at saturation');
      Check(not R.ConsumeLoss, 'new latch also consumed once');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    R.Free;
  end;
end;
