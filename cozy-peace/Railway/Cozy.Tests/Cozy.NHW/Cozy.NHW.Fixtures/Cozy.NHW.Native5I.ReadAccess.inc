var
  CanaryTestQueryOK, CanaryTestGuarded, CanaryTestArmOK, CanaryTestRaise: Boolean;
  CanaryTestArms: Integer;
function CanaryTestQuery(Page: Pointer; out Guarded: Boolean): Boolean;
begin
  if CanaryTestRaise then raise Exception.Create('synthetic guard query failure');
  Guarded := CanaryTestGuarded;
  Result := CanaryTestQueryOK and (Page <> nil);
end;
function CanaryTestArm(Page: Pointer): Boolean;
begin
  Inc(CanaryTestArms); Result := CanaryTestArmOK and (Page <> nil);
end;
function TestReadAccess5I(out Failure: string; out Checks: Integer): Boolean;
var
  M: TReadAccessMonitor;
  D: TDetectionKinds;
  H: TTargetHolder;
  SavedQuery: TCanaryQueryHook; SavedArm: TCanaryArmHook;
  Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Prime;
  begin
    M.FCanary := nil; M.Reset(0);
    M.FCanary := Pointer(NativeUInt($10000)); M.FCanaryActive := True;
    CanaryTestQueryOK := True; CanaryTestGuarded := True; CanaryTestArmOK := True;
    CanaryTestRaise := False; CanaryTestArms := 0; D := [];
  end;
  procedure Observe(Tick: UInt64);
  begin D := []; M.ExamineCanary(WinCurrentProcessId, Tick, D); end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedQuery := CanaryQueryHook; SavedArm := CanaryArmHook;
  try
    try
      CanaryQueryHook := CanaryTestQuery; CanaryArmHook := CanaryTestArm;
      M := TReadAccessMonitor.Create;
      Prime; Observe(1000);
      Check(M.FGuardBaseline and (M.FCanaryState = cosGuarded), 'successful guarded query establishes baseline');
      Check(D = [], 'baseline is not access evidence');
      CanaryTestGuarded := False; Observe(2000);
      Check(dkCanaryAccess in D, 'known guarded-to-unguarded transition reports');
      Check(CanaryTestArms = 0, 'lost guard respects rearm delay');
      Observe(2500); Check(not (dkCanaryAccess in D), 'unchanged unguarded state not repeated');
      Observe(3500);
      Check((CanaryTestArms = 1) and (M.FCanaryState = cosArming), 'successful arm is only pending baseline');
      Check(not M.FGuardBaseline and not M.FPreviousGuarded, 'arm success not treated as observed guard');
      Observe(4000); Check(not (dkCanaryAccess in D), 'unobserved guard after rearm cannot yield access');
      CanaryTestGuarded := True; Observe(4500);
      Check(M.FGuardBaseline and (M.FCanaryState = cosGuarded), 'guarded query confirms rearm');
      CanaryTestGuarded := False; Observe(5500);
      Check(dkCanaryAccess in D, 'confirmed new cycle still detects');
      Prime; Observe(1000); M.FLastFreshReadTick := 1100; M.FCanaryEpisodes.Add(1000);
      CanaryTestQueryOK := False; Observe(2000);
      Check(not M.FGuardBaseline and (M.FCanaryState = cosUnknown), 'failed query breaks known baseline');
      Check((M.FCanaryEpisodes.Count = 0) and (M.FLastFreshReadTick = 0), 'query gap clears dependent correlation');
      CanaryTestQueryOK := True; CanaryTestGuarded := False; Observe(3000);
      Check(not (dkCanaryAccess in D) and not (dkReadCorrelation in D), 'recovery cannot bridge failed observation');
      Check(M.FCanaryState = cosArming, 'recovered unguarded page requests arm');
      Prime; CanaryTestGuarded := False; CanaryTestArmOK := False; Observe(1000);
      Check((M.FCanaryState = cosUnknown) and not M.FGuardBaseline, 'failed arm leaves unknown state');
      Check(CanaryTestArms = 1, 'first arm attempt');
      Observe(1500); Check(CanaryTestArms = 1, 'arm failures rate limited');
      CanaryTestArmOK := True; Observe(2500);
      Check((CanaryTestArms = 2) and (M.FCanaryState = cosArming), 'eligible retry accepted');
      Prime; Observe(1000); H := Default(TTargetHolder); H.RightsUnion := ACCESS_VM_READ;
      D := []; M.ObserveHolder(H, True, False, False, 0, 1500, D);
      Check(dkReadAccess in D, 'original external read capability signal preserved');
      CanaryTestGuarded := False; Observe(2000);
      Check(dkReadCorrelation in D, 'valid fresh holder and confirmed loss still correlate');
      Prime; M.FReadEpisodes.Add(1); M.FReadEpisodes.Add(2);
      M.FReadEpisodes.Add(3); M.FReadEpisodes.Add(4); M.FCanaryEpisodes.Add(20000);
      D := []; M.CheckPattern(20000, D);
      Check(not (dkReadPattern in D), 'expired other history cannot revive pattern');
      Check(M.FReadEpisodes.Count = 0, 'both histories pruned before pattern decision');
      Prime; M.FReadEpisodes.Add(900); Observe(1000); CanaryTestQueryOK := False; Observe(2000);
      Check(M.FReadEpisodes.Count = 1, 'independent valid handle history retained through canary gap');
      Prime; Observe(5000); CanaryTestGuarded := False; Observe(4000);
      Check(not (dkCanaryAccess in D), 'clock rollback cannot complete prior guard transition');
      Prime; Observe(1000); CanaryTestRaise := True; Raised := False;
      try Observe(2000); except on X: Exception do Raised := True; end;
      Check(Raised and not M.FGuardBaseline, 'query exception invalidates before propagation');
      Prime; CanaryTestGuarded := False; Observe(High(UInt64) - 100);
      Check(M.FNextRearmTick = High(UInt64), 'rearm deadline saturates rather than wrapping');
      Prime; D := []; M.ExamineCanary(0, 1000, D);
      Check((D = []) and not M.FGuardBaseline, 'self-only target guard retained');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    if M <> nil then begin M.FCanary := nil; M.FCanaryActive := False; end;
    M.Free; CanaryQueryHook := SavedQuery; CanaryArmHook := SavedArm;
  end;
end;
