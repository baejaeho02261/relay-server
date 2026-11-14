function TestThreadOrigin10M(out Failure: string; out Checks: Integer): Boolean;
var Known: TDictionary<Cardinal, TThreadOriginState>;
    State: TThreadOriginState; Order: TArray<Cardinal>;
    Seen: TDictionary<Cardinal, Byte>; ID: Cardinal; I, Round: Integer;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  Known := nil; Seen := nil;
  try
    try
      Known := TDictionary<Cardinal, TThreadOriginState>.Create;
      Seen := TDictionary<Cardinal, Byte>.Create;
      for I := 1 to 150 do Known.Add(Cardinal(I), Default(TThreadOriginState));
      Order := OriginQueryOrder(Known, 1000);
      Check(Length(Order) = 64, 'native budget is 64');
      Check((Order[0] = 1) and (Order[63] = 64), 'stable deterministic first batch');
      for Round := 1 to 3 do
      begin
        Order := OriginQueryOrder(Known, UInt64(Round) * 1000);
        Check(Length(Order) <= 64, 'each pass bounded');
        for ID in Order do
        begin
          Seen.AddOrSetValue(ID, 1);
          State := Known[ID]; State.QueryAttempted := True;
          State.LastQueryTick := UInt64(Round) * 1000;
          // Simulate denied reads: StartKnown stays false, but attempts age.
          Known[ID] := State;
        end;
      end;
      Check(Seen.Count = 150, 'denied early IDs cannot starve later IDs');
      for I := 1 to 150 do
      begin
        State := Known[Cardinal(I)]; State.StartKnown := True;
        State.LastQueryTick := 5000; Known[Cardinal(I)] := State;
      end;
      Check(Length(OriginQueryOrder(Known, 5000)) = 0, 'same tick not sampled twice');
      Check(Length(OriginQueryOrder(Known, 6499)) = 0, 'known starts honor resample interval');
      Check(Length(OriginQueryOrder(Known, 6500)) = 64, 'interval endpoint eligible');
      State := Default(TThreadOriginState); Known.Add(900, State);
      Order := OriginQueryOrder(Known, 6500);
      Check(Order[0] = 900, 'unattempted ID has priority over rechecks');
      Check(Length(OriginQueryOrder(Known, 1)) = 64, 'clock rollback is bounded');
      Known.Clear;
      Check(Length(OriginQueryOrder(Known, 1000)) = 0, 'empty snapshot');
      State := Default(TThreadOriginState); Known.Add(7, State);
      Order := OriginQueryOrder(Known, 0);
      Check((Length(Order) = 1) and (Order[0] = 7), 'tick zero first observation');
      State.QueryAttempted := True; Known[7] := State;
      Check(Length(OriginQueryOrder(Known, 0)) = 0, 'tick zero duplicate prevented');
      Check(not QualifiesThreadSpawn(8, False, True, False, 3000, 0),
        'ordinary A/B/O worker burst does not imply injection');
      Check(not QualifiesThreadSpawn(7, False, True, False, 3000, 2900),
        'fewer than 8 threads is not a spawn burst');
      Check(not QualifiesThreadSpawn(8, True, True, False, 3000, 2900),
        'startup baseline is not an attack');
      Check(not QualifiesThreadSpawn(8, False, True, True, 3000, 2900),
        'incomplete thread observation is not independent evidence');
      Check(not QualifiesThreadSpawn(8, False, True, False, 8000, 3000),
        'old suspicious origin cannot confirm a later burst');
      Check(not QualifiesThreadSpawn(8, False, True, False, 1000, 2000),
        'clock rollback does not confirm a burst');
      Check(QualifiesThreadSpawn(8, False, True, False, 3100, 3000),
        'burst plus fresh non-image start remains detectable');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Seen.Free; Known.Free;
  end;
end;
