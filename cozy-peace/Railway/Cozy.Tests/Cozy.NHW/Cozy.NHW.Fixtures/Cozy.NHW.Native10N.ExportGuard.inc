function TestExportGuard10N(out Failure: string; out Checks: Integer): Boolean;
var G: TExportGuardMonitor; F: TPEFeature; D: TDetectionKinds;
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
      G := TExportGuardMonitor.Create; F := Default(TPEFeature);
      F.Available := True; F.Valid := True; F.Digest := 10;
      PEObserve(G.FWatch.Table, F, True); PEObserve(G.FWatch.Forwarder, F, True);
      PEObserve(G.FWatch.ApiSet, F, True); PEObserve(G.FWatch.Target, F, True);
      PEObserve(G.FWatch.Resolution, F, True); PEObserve(G.FWatch.DelayImport, F, True);
      F.Digest := 20;
      PEObserve(G.FWatch.Table, F, False); PEObserve(G.FWatch.Forwarder, F, False);
      PEObserve(G.FWatch.ApiSet, F, False); PEObserve(G.FWatch.Target, F, False);
      PEObserve(G.FWatch.Resolution, F, False); PEObserve(G.FWatch.DelayImport, F, False);
      G.FWatch.DelayPrimed := True; G.FWatch.PreviousResolvedSlots := 3;
      G.BreakCandidates;
      Check(G.FWatch.Table.Fingerprint.CandidateCount = 0, 'table gap');
      Check(G.FWatch.Forwarder.Fingerprint.CandidateCount = 0, 'forwarder gap');
      Check(G.FWatch.ApiSet.Fingerprint.CandidateCount = 0, 'API-set gap');
      Check(G.FWatch.Target.Fingerprint.CandidateCount = 0, 'target gap');
      Check(G.FWatch.Resolution.Fingerprint.CandidateCount = 0, 'resolution gap');
      Check(G.FWatch.DelayImport.Fingerprint.CandidateCount = 0, 'delay gap');
      Check(G.FWatch.DelayPrimed and (G.FWatch.PreviousResolvedSlots = 3), 'accepted delay baseline retained');
      Check(G.FWatch.Table.Fingerprint.Baseline = 10, 'accepted table baseline retained');
      PEObserve(G.FWatch.Table, F, False);
      FillChar(G.FBases, SizeOf(G.FBases), 0); G.FBases[0] := 1;
      G.FReady := True; D := []; G.Examine(False, 10000, D);
      Check((D = []) and (G.FWatch.Table.Fingerprint.CandidateCount = 0), 'failed whole capture clears old confirmation');
      Check(G.FWatch.Table.Fingerprint.Baseline = 10, 'failed capture never resets known-good baseline');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    G.Free;
  end;
end;
