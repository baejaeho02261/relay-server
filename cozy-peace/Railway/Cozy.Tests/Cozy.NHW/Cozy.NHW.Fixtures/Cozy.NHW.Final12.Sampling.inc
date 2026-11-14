
function TestSamplingFinal12(out Failure: string; out Checks: Integer): Boolean;
var
  H: TSamplingHealth;
  S: TScanStats;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try
    Check(not SamplingExceedsExpected(6500, 500), 'exact 6 seconds not greater');
    Check(SamplingExceedsExpected(6501, 500), '6 seconds plus one');
    Check(not SamplingExceedsExpected(High(UInt64), High(UInt64)), 'max expected no overflow');
    Check(not SamplingExceedsExpected(High(UInt64), High(UInt64)-6000), 'max boundary exact');
    Check(SamplingExceedsExpected(High(UInt64), High(UInt64)-6001), 'max boundary plus one');
    H := Default(TSamplingHealth); S := Default(TScanStats);
    S.ScanMS := 20; S.GapMS := 500;
    UpdateSampling(H, S, 500, 1000);
    Check(not H.WarningPending, 'normal sample');
    Check(H.HasPreviousScan and H.HasCurrentTick, 'first sample initialized');
    S.ScanMS := 100000; UpdateSampling(H, S, 500, 1000);
    Check(not H.WarningPending, 'same tick does not add warning');
    Check(H.PreviousScanMS = 20, 'same tick does not replace duration');
    S.ScanMS := 6501; UpdateSampling(H, S, 500, 1500);
    Check(H.WarningPending and SamplingWarningDue(H), 'large scan warning due');
    H.HasReportedWarning := True; H.LastWarningTick := 1500;
    Check(not SamplingWarningDue(H), 'cooldown blocks immediate warning');
    H.CurrentTick := 31499; Check(not SamplingWarningDue(H), 'cooldown minus one');
    H.CurrentTick := 31500; Check(SamplingWarningDue(H), 'cooldown exact');
    H.CurrentTick := 32000; H.LastWarningTick := 31500;
    UpdateSampling(H, S, 500, 2000);
    Check(not H.WarningPending and not H.HasPreviousScan, 'backwards epoch clears pending history');
    Check(H.LastWarningTick = 2000, 'cooldown rebased without immediate warning');
    S.ScanMS := 20; S.GapMS := 500; UpdateSampling(H, S, 500, 2500);
    Check(not H.WarningPending, 'new epoch normal sample');
    UpdateSampling(H, S, 500, 0);
    Check(not H.HasPreviousScan and not H.HasCurrentTick, 'zero tick invalidates baseline');
    Check(not SamplingWarningDue(H), 'zero tick never emits');
    H := Default(TSamplingHealth); H.HasPreviousScan := True;
    H.PreviousScanMS := High(UInt64); S.ScanMS := High(UInt64); S.GapMS := High(UInt64);
    UpdateSampling(H, S, 500, 1);
    Check(not H.WarningPending, 'unrepresentable expected threshold does not wrap');
    // Do not invoke the console writer: logging policy is checked separately.
    Result := True;
  except on E: Exception do Failure := E.Message; end;
end;
