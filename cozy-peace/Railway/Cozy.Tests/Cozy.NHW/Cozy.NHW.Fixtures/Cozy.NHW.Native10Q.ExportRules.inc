function TestExportRules10Q(out Failure: string; out Checks: Integer): Boolean;
var
  W: TExportWatch; D, Bad: TDelaySlotSnapshot; I: Integer;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  W := Default(TExportWatch); D := Default(TDelaySlotSnapshot); Bad := Default(TDelaySlotSnapshot);
  try
    try
      D.Complete := True; D.ImageBase := $180000000; D.LayoutDigest := 100;
      SetLength(D.Slots, 2);
      D.Slots[0].SlotAddress := $180001000;
      D.Slots[0].TargetAddress := $7FF000010000; D.Slots[0].Resolved := True;
      D.Slots[0].UnloadTarget := $180002000;
      D.Slots[1].SlotAddress := $180001008;
      D.Slots[1].TargetAddress := $180002008; D.Slots[1].Resolved := False;
      D.Slots[1].UnloadTarget := $180002008;
      Check(not ObserveDelayImportSlots(W, D, True), 'per-slot baseline');
      Check(Length(W.DelaySlots) = 2, 'two distinct watches');
      D.Slots[0].TargetAddress := $7FF000030000; // existing resolved slot changes
      D.Slots[1].TargetAddress := $7FF000020000; D.Slots[1].Resolved := True;
      Check(not ObserveDelayImportSlots(W, D, False), 'first suspicious change not yet confirmed');
      Check(W.DelaySlots[0].Target.Fingerprint.Baseline = $7FF000010000,
        'new resolution must not replace sibling baseline');
      Check(W.DelaySlots[0].Target.Fingerprint.CandidateCount = 1, 'sibling change retained');
      Check(ObserveDelayImportSlots(W, D, False), 'existing change detected despite newly resolved sibling');
      Check(not ObserveDelayImportSlots(W, D, False), 'stable reported candidate not repeated');
      D.Slots[0].TargetAddress := D.Slots[0].UnloadTarget; D.Slots[0].Resolved := False;
      Check(not ObserveDelayImportSlots(W, D, False), 'legitimate unload helper accepted');
      Check(not W.DelaySlots[0].WasResolved, 'unload rearms this slot only');
      Check(W.DelaySlots[1].WasResolved, 'unload does not reset sibling');
      D.Slots[0].TargetAddress := $7FF000040000; D.Slots[0].Resolved := True;
      Check(not ObserveDelayImportSlots(W, D, False), 'legitimate re-resolution after observed unload');
      D.Slots[0].TargetAddress := $7FF000050000;
      Check(not ObserveDelayImportSlots(W, D, False), 'one new candidate');
      Bad := D; Bad.Complete := False;
      Check(not ObserveDelayImportSlots(W, Bad, False), 'failed capture not a signal');
      Check(W.DelaySlots[0].Target.Fingerprint.CandidateCount = 0, 'gap breaks confirmations');
      Check(not ObserveDelayImportSlots(W, D, False), 'recovery requires new first confirmation');
      Check(ObserveDelayImportSlots(W, D, False), 'second fresh confirmation preserved');
      Bad := D; Bad.Slots := Copy(D.Slots);
      Bad.Slots[1].SlotAddress := Bad.Slots[0].SlotAddress;
      Check(not ObserveDelayImportSlots(W, Bad, False), 'duplicate slot rejected');
      Check(W.DelaySlots[1].SlotAddress = D.Slots[1].SlotAddress, 'invalid view not partially published');
      Bad.Slots[1].SlotAddress := Bad.Slots[0].SlotAddress - 8;
      Check(not ObserveDelayImportSlots(W, Bad, False), 'unsorted view rejected');
      Bad := D; Bad.ImageBase := 0;
      Check(not ObserveDelayImportSlots(W, Bad, False), 'missing module identity rejected');
      Bad := D; Bad.Slots := nil; SetLength(Bad.Slots, NHW_DELAY_SLOT_LIMIT + 1);
      Check(not ObserveDelayImportSlots(W, Bad, False), 'bounded input capacity');
      // Local pointer changes are not blindly accepted as an unload.
      W := Default(TExportWatch); D.Slots[0].Resolved := False;
      D.Slots[0].TargetAddress := D.Slots[0].UnloadTarget;
      Check(not ObserveDelayImportSlots(W, D, True), 'local baseline');
      D.Slots[0].TargetAddress := D.Slots[0].UnloadTarget + $100;
      Check(not ObserveDelayImportSlots(W, D, False), 'different local thunk first observation');
      Check(ObserveDelayImportSlots(W, D, False), 'different local thunk confirmed');
      D.Slots[0].TargetAddress := D.Slots[0].UnloadTarget;
      Check(not ObserveDelayImportSlots(W, D, False), 'known unload thunk restores local state');
      // Layout changes have their own stable fingerprint.
      W := Default(TExportWatch); D.Slots := nil; D.LayoutDigest := 101;
      Check(not ObserveDelayImportSlots(W, D, True), 'empty delay directory baseline');
      D.LayoutDigest := 102;
      Check(not ObserveDelayImportSlots(W, D, False), 'layout change first sample');
      Check(ObserveDelayImportSlots(W, D, False), 'layout change separately confirmed');
      for I := 0 to 3 do Check(not ObserveDelayImportSlots(W, D, False), 'no repeated layout alert');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    W := Default(TExportWatch); D := Default(TDelaySlotSnapshot); Bad := Default(TDelaySlotSnapshot);
  end;
end;
