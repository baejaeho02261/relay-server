var
  Exception5KState: TExceptionImageState;
  Exception5KCaptureOK, Exception5KCallbackOK, Exception5KRaise: Boolean;
  Exception5KCallbackValue: UInt64;
function MockExceptionCapture5K(out S: TExceptionImageState): Boolean;
begin
  if Exception5KRaise then raise Exception.Create('Synthetic capture failure');
  S := Exception5KState; Result := Exception5KCaptureOK;
end;
function MockExceptionCallback5K(out Hash: UInt64): Boolean;
begin Hash := Exception5KCallbackValue; Result := Exception5KCallbackOK; end;

function TestExceptionGuard5K(out Failure: string; out Checks: Integer): Boolean;
var M: TExceptionGuardMonitor; K: TDetectionKinds; Raised: Boolean;
  procedure Check(C: Boolean; const Name: string);
  begin Inc(Checks); if not C then raise Exception.Create(Name); end;
  procedure Run(Tick: UInt64; Base: Boolean = False);
  begin K := []; M.Examine(Base, Tick, False, K); end;
  procedure Prime;
  begin
    M.Reset;
    Exception5KCaptureOK := True; Exception5KCallbackOK := True;
    Exception5KRaise := False; Exception5KCallbackValue := 10;
    Exception5KState := Default(TExceptionImageState);
    Exception5KState.TableDigest := 1; Exception5KState.RangeDigest := 2;
    Exception5KState.UnwindDigest := 3; Exception5KState.RangeValid := True;
    Exception5KState.UnwindValid := True; Exception5KState.HasUnwindSamples := True;
    Exception5KState.HasLookupSamples := True; Exception5KState.LookupConsistent := True;
    Run(1000, True);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  ExceptionNoRegister5K := True;
  ExceptionCapture5KHook := MockExceptionCapture5K;
  ExceptionCallback5KHook := MockExceptionCallback5K;
  try
    try
      M := TExceptionGuardMonitor.Create; Prime;
      Check(M.FInitialized and M.FTable.HasBaseline, 'valid baseline retained');
      Exception5KState.TableDigest := 100; Run(4000);
      Check((K = []) and (M.FTable.CandidateCount = 1), 'first table change is pending');
      Exception5KCaptureOK := False; Run(6000);
      Check(M.FTable.CandidateCount = 0, 'capture failure breaks candidate');
      Check(M.FTable.Baseline = 1, 'failure never replaces approved table');
      Exception5KCaptureOK := True; Run(8000);
      Check(K = [], 'first recovery cannot complete old candidate');
      Run(10000); Check(dkFunctionTable in K, 'two fresh changes still detect');
      Exception5KCaptureOK := False; Run(12000);
      Exception5KCaptureOK := True; Run(14000); Run(16000);
      Check(K = [], 'already reported change does not repeat after unknown gap');
      Prime; Exception5KState.UnwindDigest := 30; Run(4000);
      Exception5KState.HasUnwindSamples := False; Run(6000);
      Check(M.FUnwind.CandidateCount = 0, 'missing unwind samples break continuity');
      Check(M.FUnwind.Baseline = 3, 'unwind baseline preserved');
      Exception5KState.HasUnwindSamples := True; Run(8000); Check(K = [], 'fresh unwind recovery only once');
      Run(10000); Check(dkUnwind in K, 'unwind confirms on next complete sample');
      Prime; Exception5KCallbackValue := 20; Run(4000);
      Exception5KCallbackOK := False; Run(6000);
      Check(M.FCallback.CandidateCount = 0, 'callback failure invalidates pending');
      Exception5KCallbackOK := True; Run(8000); Check(K = [], 'callback recovery restarts');
      Run(10000); Check(dkExceptionCallback in K, 'callback confirms after two successes');
      Prime; Exception5KState.RangeValid := False; Run(4000);
      Check(M.FRangeFault.Consecutive = 1, 'invalid range still observed as evidence');
      Exception5KCaptureOK := False; Run(6000);
      Check(M.FRangeFault.Consecutive = 0, 'range confirmation reset on failed capture');
      Exception5KCaptureOK := True; Run(8000); Check(K = [], 'range recovery first only');
      Run(10000); Check(dkExceptionRange in K, 'range confirmation retained');
      Prime; Exception5KState.TableDigest := 100; Run(4000);
      Exception5KRaise := True; Raised := False;
      try Run(6000); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FTable.CandidateCount = 0), 'exception clears candidate then propagates');
      Check(M.FTable.Baseline = 1, 'exception preserves trusted baseline');
      Exception5KRaise := False; Run(8000); Check(K = [], 'exception recovery starts over');
      Prime; Exception5KState.TableDigest := 100; Run(4000); Run(20000);
      Check(K = [], 'long observation gap cannot confirm stale candidate');
      Run(22000); Check(dkFunctionTable in K, 'two post-gap samples can confirm');
      Prime; Exception5KCaptureOK := False; K := [dkFileSwap];
      M.Examine(False, 4000, False, K);
      Check(K = [dkFileSwap], 'unrelated evidence preserved on failure');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; ExceptionCapture5KHook := nil; ExceptionCallback5KHook := nil;
    ExceptionNoRegister5K := False;
  end;
end;
