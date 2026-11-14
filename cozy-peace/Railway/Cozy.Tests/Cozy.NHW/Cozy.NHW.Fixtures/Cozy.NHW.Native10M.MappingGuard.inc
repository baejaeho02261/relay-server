function TestMappingGuard10M(out Failure: string; out Checks: Integer): Boolean;
var M: TMappingGuard; Keys: TList<NativeUInt>;
    Batch, Next: TArray<NativeUInt>; Cursor: NativeUInt; Passes, I, Round: Integer;
    Seen: TDictionary<NativeUInt, Byte>; Key: NativeUInt;
    S, BaseSample, NewSample: TMappingSample;
    D: TDetectionKinds; Track: TMappingTrack;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil; Keys := nil; Seen := nil;
  try
    try
      M := TMappingGuard.Create; Keys := TList<NativeUInt>.Create;
      Seen := TDictionary<NativeUInt, Byte>.Create;
      for I := 1 to 400 do Keys.Add(NativeUInt(I) * $10000);
      Cursor := 0; Passes := 0;
      Batch := SelectMappingBatch(Keys, Cursor, 64);
      Check((Length(Batch) = 64) and (Batch[0] = $10000), 'first backing batch');
      AdvanceMappingBatch(Batch, Cursor, Passes);
      Next := SelectMappingBatch(Keys, Cursor, 64);
      Check((Next[0] = Batch[0]) and (Passes = 1), 'hold batch for confirmation');
      AdvanceMappingBatch(Next, Cursor, Passes);
      Next := SelectMappingBatch(Keys, Cursor, 64);
      Check((Next[0] = 65 * $10000) and (Passes = 0), 'advance after two observations');
      Cursor := 0; Passes := 0;
      for Round := 1 to 14 do
      begin
        Batch := SelectMappingBatch(Keys, Cursor, 64);
        Check(Length(Batch) <= 64, 'backing budget');
        for Key in Batch do Seen.AddOrSetValue(Key, 1);
        AdvanceMappingBatch(Batch, Cursor, Passes);
      end;
      Check(Seen.Count = 400, 'all mappings reached within rotation');
      Batch := SelectMappingBatch(Keys, High(NativeUInt), 192);
      Check((Length(Batch) = 192) and (Batch[0] = Keys[0]), 'page rotation wraps');
      Check(Length(SelectMappingBatch(Keys, 0, 0)) = 0, 'zero budget');
      Check(Length(SelectMappingBatch(nil, 0, 64)) = 0, 'nil keys');
      for I := 1 to 400 do
      begin
        S := Default(TMappingSample); S.Base := NativeUInt(I) * $10000;
        S.ProbePage := S.Base; S.RegionType := ALLOC_MEM_IMAGE; S.MappedBytes := 4096;
        M.FCurrent.Add(S.Base, S);
      end;
      Mapping10MBackingCalls := 0; Mapping10MPageCalls := 0;
      Mapping10MFail := True; M.PopulateMetadata(1);
      Check((Mapping10MBackingCalls = 64) and (Mapping10MPageCalls = 192), 'failed calls consume budget');
      M.PopulateMetadata(1);
      Check((M.FBackingCursor = 64 * $10000) and (M.FPageCursor = 192 * $10000), 'failed reads do not stall rotation');
      M.Reset; Mapping10MFail := False; Mapping10MChanged := False;
      S := Default(TMappingSample); S.Base := $10000; S.ProbePage := S.Base;
      S.RegionType := ALLOC_MEM_IMAGE; S.MappedBytes := 4096;
      for Round := 1 to 2 do
      begin
        M.BeginSweep; M.FCurrent.Add(S.Base, S); D := [];
        M.EndSweep(1, UInt64(Round) * 1000, D);
        Check(D = [], 'warmup does not alert');
      end;
      Mapping10MChanged := True;
      M.BeginSweep; M.FCurrent.Add(S.Base, S); D := []; M.EndSweep(1, 3000, D);
      Check(not (dkMappingBacking in D), 'first changed observation is candidate');
      M.BeginSweep; M.FCurrent.Add(S.Base, S); D := []; M.EndSweep(1, 4000, D);
      Check(dkMappingBacking in D, 'second complete metadata observation confirms');
      Track := M.FTracked[S.Base]; Track.PendingCount := 1; Track.MissingSweeps := 1;
      M.FTracked[S.Base] := Track; M.FBackingPasses := 1; M.FPagePasses := 1;
      M.CancelSweep; Track := M.FTracked[S.Base];
      Check(Track.HasStable and (Track.PendingCount = 0), 'cancel keeps baseline but breaks candidate');
      Check((Track.MissingSweeps = 0) and (M.FBackingPasses = 0) and
        (M.FPagePasses = 0), 'cancel breaks both metadata observation batches');

      // Long-idle regression: a newly lazy-loaded mapped/executable image is
      // normal lifecycle telemetry and is silently established as baseline.
      M.Reset; Mapping10MChanged := False;
      BaseSample := Default(TMappingSample);
      BaseSample.Base := $10000; BaseSample.ProbePage := BaseSample.Base;
      BaseSample.RegionType := ALLOC_MEM_IMAGE; BaseSample.MappedBytes := 4096;
      for Round := 1 to 2 do
      begin
        M.BeginSweep; M.FCurrent.AddOrSetValue(BaseSample.Base, BaseSample); D := [];
        M.EndSweep(1, UInt64(Round) * 1000, D);
      end;
      NewSample := Default(TMappingSample);
      NewSample.Base := $20000; NewSample.ProbePage := NewSample.Base;
      NewSample.RegionType := ALLOC_MEM_IMAGE; NewSample.MappedBytes := 4096;
      NewSample.ExecutableBytes := 4096;
      for Round := 3 to 4 do
      begin
        M.BeginSweep;
        M.FCurrent.AddOrSetValue(BaseSample.Base, BaseSample);
        M.FCurrent.AddOrSetValue(NewSample.Base, NewSample); D := [];
        M.EndSweep(1, UInt64(Round) * 1000, D);
      end;
      Check(not (dkMappedView in D) and not (dkExecutableMapping in D),
        'new stable mapping is not a security alert');
      // Existing mapping becoming executable is still a confirmed transition.
      BaseSample.ExecutableBytes := 4096;
      M.BeginSweep; M.FCurrent.AddOrSetValue(BaseSample.Base, BaseSample); D := [];
      M.EndSweep(1, 5000, D);
      Check(not (dkExecutableMapping in D), 'first executable transition is candidate');
      M.BeginSweep; M.FCurrent.AddOrSetValue(BaseSample.Base, BaseSample); D := [];
      M.EndSweep(1, 6000, D);
      Check(dkExecutableMapping in D, 'confirmed executable transition still reports');

      M.Reset;
      Check((M.FBackingCursor = 0) and (M.FPageCursor = 0), 'reset clears rotation state');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Seen.Free; Keys.Free; M.Free;
  end;
end;
