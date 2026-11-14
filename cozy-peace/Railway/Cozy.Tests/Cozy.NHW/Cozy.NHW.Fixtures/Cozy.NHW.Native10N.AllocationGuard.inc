function TestAllocationGuard10N(out Failure: string; out Checks: Integer): Boolean;
var G: TVirtualAllocationGuard; T: TAllocationTrack; A: TAllocationSample;
    D: TDetectionKinds; Epoch: UInt64;
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
      G := TVirtualAllocationGuard.Create;
      G.FCompletedSweeps := 2;
      T := Default(TAllocationTrack);
      T.Stable.Base := $10000; T.Stable.ReservedBytes := 1024 * 1024;
      T.Stable.RegionSignature := 1; T.HasStable := True;
      T.Pending := T.Stable; T.Pending.CommittedBytes := 65536;
      T.Pending.RegionSignature := 2; T.PendingCount := 1; T.MissingSweeps := 1;
      T.ObservationEpoch := G.FObservationEpoch;
      G.FTracked.Add($10000, T); G.FCurrent.Add($10000, T.Pending);
      G.FBurstTicks.Add(100); G.FRunning := True;
      Epoch := G.FObservationEpoch; G.CancelSweep(1000);
      Check(not G.FRunning and (G.FCurrent.Count = 0), 'cancel discards incomplete sweep');
      Check(G.FObservationEpoch <> Epoch, 'cancel invalidates old candidate epoch without allocation');
      Check((G.FBurstTicks.Count = 0) and (G.FNextSweepTick = 2000), 'gap breaks burst and schedules retry');
      T := G.FTracked[$10000]; G.RefreshTrack(T);
      Check(T.HasStable and (T.Stable.RegionSignature = 1), 'approved baseline survives gap');
      Check((T.PendingCount = 0) and (T.MissingSweeps = 0), 'stale confirmations are not usable');
      A := T.Stable; A.CommittedBytes := 65536; A.RegionSignature := 2;
      G.FCurrent.Add($10000, A); D := []; G.FinishSweep(0, 2100, D);
      Check(D = [], 'first post-gap observation cannot confirm old candidate');
      Check(G.FTracked[$10000].PendingCount = 1, 'post-gap confirmation restarts at one');
      D := []; G.FinishSweep(0, 2200, D);
      Check(dkCommit in D, 'two complete fresh observations still detect commit');
      G.FCurrent.Clear; D := []; G.FinishSweep(0, 2300, D);
      Check(G.FTracked[$10000].MissingSweeps = 1, 'first complete absence counted');
      G.CancelSweep(2400); T := G.FTracked[$10000]; G.RefreshTrack(T);
      Check(T.MissingSweeps = 0, 'absence does not bridge failed sweep');
      G.CancelSweep(High(UInt64));
      Check(G.FNextSweepTick = High(UInt64), 'retry deadline saturates');
      G.Reset;
      Check((G.FTracked.Count = 0) and (G.FCompletedSweeps = 0), 'session reset still clears state');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    G.Free;
  end;
end;
