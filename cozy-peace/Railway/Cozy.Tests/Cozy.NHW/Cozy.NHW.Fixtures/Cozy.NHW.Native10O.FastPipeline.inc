function TestFastPipeline10O(out Failure: string; out Checks: Integer): Boolean;
var
  G: TFastDeferredPipeline;
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
      G := TFastDeferredPipeline.Create;
      Check(not G.Pending(0), 'empty pending state');
      Check(G.AllowDeferred(0, False, False), 'initial tick zero supported');
      G.CompleteDeferred(True);
      Check(not G.AllowDeferred(1, False, False), 'zero timestamp is not uninitialized sentinel');
      G.Reset;
      Check(G.AllowDeferred(1000, False, False), 'initial normal inspection'); G.CompleteDeferred(True);
      G.NotifyRelevant(1100);
      Check(G.Pending(1100), 'notification records request');
      Check(not G.AllowDeferred(11100, False, True), 'pressure keeps original 12-second spacing');
      Check(G.Pending(11100), 'pending request survives 10-second hot hint expiry');
      Check(G.AllowDeferred(13000, False, True), 'pressure interval permits deferred grant');
      Check(G.Pending(13000), 'grant alone does not consume request');
      G.CompleteDeferred(False); Check(G.Pending(13001), 'admission/sensor failure preserves request');
      Check(not G.AllowDeferred(24999, False, True), 'failed execution remains throttled');
      Check(G.AllowDeferred(25000, False, True), 'retry at pressure boundary');
      G.CompleteDeferred(True); Check(not G.Pending(25000), 'completed sensor call acknowledges request');
      G.NotifyRelevant(26000); Check(not G.AllowDeferred(50000, True, False), 'baseline never runs optional heavy work');
      Check(G.Pending(50000), 'baseline does not consume pending request');
      Check(G.AllowDeferred(50001, False, False), 'expired hot hint still schedules ordinary work');
      G.CompleteDeferred(True); G.NotifyRelevant(High(UInt64) - 1);
      Check(G.FPendingUntil = High(UInt64), 'hot deadline saturates instead of wrapping');
      G.NotifyRelevant(1); Check(G.FPendingUntil = High(UInt64), 'late old notification cannot shorten hint');
      G.Reset; Check(not G.Pending(0) and not G.FHasHeavy, 'reset clears scheduler state');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    G.Free;
  end;
end;
