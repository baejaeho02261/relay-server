program CozyNHWValidationRunner;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build the validation runner with Delphi Win64.'}
{$ENDIF}

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Validation.Process in 'Cozy.NHW.Validation.Process.pas',
  Cozy.NHW.Engine,
  Cozy.NHW.Logging,
  Cozy.NHW.Options,
  Cozy.NHW.Types,
  Cozy.NHW.WinPointers,
  Cozy.NHW.Native,
  Cozy.NHW.DualObserver;

{$I Cozy.NHW.Validation.Catalog.inc}

const
  INTEGRATION_JOURNAL_TEST = 'Cozy.NHW.DetectionJournal';
  TOTAL_VALIDATION_TEST_COUNT = VALIDATION_TEST_COUNT + 1;
  FP1_IDLE_REPEATED_EXIT = 18;
  FP1_IDLE_KINDS: TDetectionKinds = [dkMappedView, dkExecutableMapping,
    dkWriteWatch, dkWriteBurst, dkProcess, dkOwnership];

type
  TRunMode = (rmSuite, rmSoak, rmAll, rmSelfTest);
  TRunOptions = record
    Mode: TRunMode;
    Rounds, Minutes, TimeoutSeconds: Integer;
  end;

function ConsoleControl(Code: Cardinal): BOOL; stdcall;
begin
  Result := (Code = CTRL_C_EVENT) or (Code = CTRL_BREAK_EVENT);
  if Result then RequestValidationStop;
end;

procedure ShowHelp;
begin
  Writeln('Cozy NHW validation runner - Delphi Win64 / no generated log files');
  Writeln('Default: --suite --rounds=1 --timeout=120');
  Writeln('Modes: --suite | --soak | --all | --self-test');
  Writeln('  --rounds=1..10000   Repeat all ', TOTAL_VALIDATION_TEST_COUNT, ' regression/smoke executables');
  Writeln('  --timeout=1..3600  Maximum seconds for each test');
  Writeln('  --minutes=1..1440  Integrated sensor soak duration (default 60)');
  Writeln('Examples:');
  Writeln('  --all --rounds=3 --minutes=60');
  Writeln('  --soak --minutes=240');
  Writeln('Build Cozy.NHW.FullValidation.groupproj / Win64 / Release / Build All first.');
  Writeln('Use Run > Parameters in Delphi; no BAT/CMD/PowerShell is needed.');
  Writeln('Ctrl+C requests cancellation. Only owned child processes are stopped.');
  Writeln('A soak observes liveness, resources, and shutdown, not sensor correctness.');
end;

function ReadBounded(const Text: string; MinValue, MaxValue: Integer): Integer;
begin
  if not TryStrToInt(Text, Result) or (Result < MinValue) or (Result > MaxValue) then
    raise Exception.Create('Invalid numeric option: ' + Text);
end;

function ParseOptions: TRunOptions;
var
  I: Integer;
  A: string;
  ModeSeen: Boolean;
begin
  Result.Mode := rmSuite;
  Result.Rounds := 1;
  Result.Minutes := 60;
  Result.TimeoutSeconds := 120;
  ModeSeen := False;
  for I := 1 to ParamCount do
  begin
    A := ParamStr(I);
    if (A = '--suite') or (A = '--soak') or (A = '--all') or (A = '--self-test') then
    begin
      if ModeSeen then raise Exception.Create('Choose one run mode only');
      ModeSeen := True;
      if A = '--soak' then Result.Mode := rmSoak
      else if A = '--all' then Result.Mode := rmAll
      else if A = '--self-test' then Result.Mode := rmSelfTest
      else Result.Mode := rmSuite;
    end
    else if Copy(A, 1, 9) = '--rounds=' then
      Result.Rounds := ReadBounded(Copy(A, 10, MaxInt), 1, 10000)
    else if Copy(A, 1, 10) = '--minutes=' then
      Result.Minutes := ReadBounded(Copy(A, 11, MaxInt), 1, 1440)
    else if Copy(A, 1, 10) = '--timeout=' then
      Result.TimeoutSeconds := ReadBounded(Copy(A, 11, MaxInt), 1, 3600)
    else raise Exception.Create('Unknown option: ' + A);
  end;
end;

procedure PrintChild(const R: TValidationRun);
begin
  Writeln('  started=', BoolToStr(R.Started, True),
    ' exited=', BoolToStr(R.Exited, True), ' exit_code=', R.ExitCode,
    ' elapsed_ms=', R.ElapsedMS);
  if R.ErrorText <> '' then
    Writeln('  ERROR: ', R.ErrorText, ' native_code=', R.NativeError);
  if R.TimedOut then Writeln('  TIMEOUT');
  if R.Cancelled then Writeln('  CANCELLED');
  if R.ForcedTermination then Writeln('  FORCED OWNED CHILD SHUTDOWN');
  if R.DescendantsForced then Writeln('  FORCED OWNED DESCENDANT CLEANUP');
  if not R.JobDrained then Writeln('  JOB DRAIN NOT CONFIRMED');
  if R.OutputReadError then Writeln('  OUTPUT READ ERROR');
  if R.Output <> '' then Write(string(R.Output));
  if R.OutputTruncated then
    Writeln(#13#10'  Output retention capped at 256 KiB; remaining bytes were drained.');
end;

function CleanTestExit(const R: TValidationRun): Boolean;
begin
  Result := R.Started and R.Exited and (R.ExitCode = 0) and
    (R.ErrorText = '') and not R.TimedOut and not R.Cancelled and
    not R.ForcedTermination and not R.DescendantsForced and
    R.JobDrained and not R.OutputReadError;
end;

function RunHarnessSelfTests: Boolean;
var
  R: TValidationRun;
  SelfExe: string;
  OK: Boolean;
begin
  Result := False;
  SelfExe := ExpandFileName(ParamStr(0));
  Writeln('Harness self-check: exit codes, bounded output, timeout, missing binary.');
  R := RunValidationChild(SelfExe, '--child-ok', 10000, False);
  OK := CleanTestExit(R);
  Writeln('SELFTEST normal exit: ', BoolToStr(OK, True));
  if not OK then begin PrintChild(R); Exit; end;
  R := RunValidationChild(SelfExe, '--child-fail', 10000, False);
  OK := R.Exited and (R.ExitCode = 17) and not R.TimedOut and
    not R.ForcedTermination and R.JobDrained and (R.ErrorText = '');
  Writeln('SELFTEST nonzero exit retained: ', BoolToStr(OK, True));
  if not OK then begin PrintChild(R); Exit; end;
  R := RunValidationChild(SelfExe, '--child-output', 15000, False);
  OK := CleanTestExit(R) and R.OutputTruncated and (Length(R.Output) = 262144);
  Writeln('SELFTEST output cap and pipe drainage: ', BoolToStr(OK, True));
  if not OK then begin PrintChild(R); Exit; end;
  R := RunValidationChild(SelfExe, '--child-wait', 500, False);
  OK := R.Started and R.Exited and R.TimedOut and R.JobDrained;
  Writeln('SELFTEST timeout is not pass: ', BoolToStr(OK, True));
  if not OK then begin PrintChild(R); Exit; end;
  R := RunValidationChild(ExtractFilePath(SelfExe) + 'NHW.Nonexistent.SelfCheck.exe', '', 1000, False);
  OK := not R.Started and (R.NativeError = ERROR_FILE_NOT_FOUND);
  Writeln('SELFTEST missing binary is blocked: ', BoolToStr(OK, True));
  if not OK then begin PrintChild(R); Exit; end;
  Result := not ValidationStopRequested;
end;

function TestExecutable(const Root, Name: string): string;
begin
  Result := Root + Name + '\' + Name + '.exe';
end;

function RunSuite(const Root: string; const Options: TRunOptions): Integer;
var
  I, Round, Missing: Integer;
  Passed, Failed, Completed: Cardinal;
  Exe: string;
  R: TValidationRun;
begin
  Missing := 0;
  for I := 0 to VALIDATION_TEST_COUNT - 1 do
  begin
    Exe := TestExecutable(Root, VALIDATION_TEST_NAMES[I]);
    if not FileExists(Exe) then
    begin
      Inc(Missing);
      Writeln('MISSING: ', Exe);
    end;
  end;
  { Retain the original 79-case catalog unchanged, and require the added
    integration regression before starting any suite round. }
  Exe := TestExecutable(Root, INTEGRATION_JOURNAL_TEST);
  if not FileExists(Exe) then
  begin
    Inc(Missing);
    Writeln('MISSING: ', Exe);
  end;
  if Missing > 0 then
  begin
    Writeln('BLOCKED: ', Missing, ' binaries are absent; none counted as passed.');
    Exit(2);
  end;
  Passed := 0; Failed := 0; Completed := 0;
  for Round := 1 to Options.Rounds do
  begin
    for I := 0 to VALIDATION_TEST_COUNT - 1 do
    begin
      if ValidationStopRequested then
      begin
        Writeln('CANCELLED after ', Completed, ' tests; suite is incomplete.');
        Exit(3);
      end;
      Writeln('RUN round=', Round, '/', Options.Rounds, ' ',
        I + 1, '/', TOTAL_VALIDATION_TEST_COUNT, ' ', VALIDATION_TEST_NAMES[I]);
      Exe := TestExecutable(Root, VALIDATION_TEST_NAMES[I]);
      try
        R := RunValidationChild(Exe, '', Cardinal(Options.TimeoutSeconds) * 1000, False);
        PrintChild(R);
        if CleanTestExit(R) then
        begin
          Inc(Passed); Writeln('PASS: ', VALIDATION_TEST_NAMES[I]);
        end
        else
        begin
          Inc(Failed); Writeln('FAIL/INCOMPLETE: ', VALIDATION_TEST_NAMES[I]);
        end;
      except
        on E: Exception do
        begin
          Inc(Failed);
          Writeln('HARNESS ERROR: ', E.ClassName, ': ', E.Message);
        end;
      end;
      Inc(Completed);
    end;
    { This is a real owned child execution in every round, not merely a
      Build-All entry or an asserted PASS in the completion-evidence gate. }
    if ValidationStopRequested then
    begin
      Writeln('CANCELLED after ', Completed, ' tests; suite is incomplete.');
      Exit(3);
    end;
    Writeln('RUN round=', Round, '/', Options.Rounds, ' ',
      TOTAL_VALIDATION_TEST_COUNT, '/', TOTAL_VALIDATION_TEST_COUNT, ' ',
      INTEGRATION_JOURNAL_TEST);
    Exe := TestExecutable(Root, INTEGRATION_JOURNAL_TEST);
    try
      R := RunValidationChild(Exe, '', Cardinal(Options.TimeoutSeconds) * 1000, False);
      PrintChild(R);
      if CleanTestExit(R) then
      begin
        Inc(Passed); Writeln('PASS: ', INTEGRATION_JOURNAL_TEST);
      end
      else
      begin
        Inc(Failed); Writeln('FAIL/INCOMPLETE: ', INTEGRATION_JOURNAL_TEST);
      end;
    except
      on E: Exception do
      begin
        Inc(Failed);
        Writeln('HARNESS ERROR: ', E.ClassName, ': ', E.Message);
      end;
    end;
    Inc(Completed);
  end;
  Writeln('SUITE RESULT: tests_run=', Completed, ' passed=', Passed, ' failed=', Failed);
  Writeln('Optional live-check counts in test output are not counted as full sensor coverage.');
  if ValidationStopRequested then Exit(3);
  if Failed <> 0 then Result := 1 else Result := 0;
end;

function RunSoak(Minutes: Integer): Integer;
var
  R: TValidationRun;
  Exe: string;
  M: TValidationMetrics;
begin
  Exe := ExpandFileName(ParamStr(0));
  Writeln('SOAK: duration_minutes=', Minutes, ' telemetry=RAM_only, interval=1s');
  Writeln('An isolated child runs the integrated Cozy NHW engine.');
  Writeln('The harness job and open process handle may appear in monitor observations.');
  Writeln('The samples cover engine liveness, resources, and orderly shutdown.');
  R := RunValidationChild(Exe, '--child-soak', Cardinal(Minutes) * 60000, True);
  PrintChild(R);
  M := R.Metrics;
  Writeln('samples=', M.Samples, ' failed_samples=', M.FailedSamples);
  Writeln('private_bytes first=', M.First.PrivateBytes, ' last=', M.Last.PrivateBytes,
    ' max=', M.Maximum.PrivateBytes);
  Writeln('working_set_bytes first=', M.First.WorkingSetBytes, ' last=', M.Last.WorkingSetBytes,
    ' max=', M.Maximum.WorkingSetBytes);
  Writeln('handle_count first=', M.First.Handles, ' last=', M.Last.Handles,
    ' max=', M.Maximum.Handles);
  if M.HasWarmBaseline then
    Writeln('post_warmup_baseline private_bytes=', M.WarmBaseline.PrivateBytes,
      ' handle_count=', M.WarmBaseline.Handles);
  if (M.Samples > 1) and (M.Last.Cpu100ns >= M.First.Cpu100ns) then
    Writeln('sampled_cpu_ms=', (M.Last.Cpu100ns - M.First.Cpu100ns) div 10000);
  if R.Cancelled then Exit(3);
  if not R.DurationReached then
  begin
    Writeln('FAIL: main exited or failed before the requested observation duration.');
    Exit(1);
  end;
  if R.ExitCode = FP1_IDLE_REPEATED_EXIT then
  begin
    Writeln('FAIL: an FP1 category recurred during the idle observation.');
    Exit(1);
  end;
  if not CleanTestExit(R) or not R.GracefulSignalSent then
  begin
    Writeln('FAIL/INCOMPLETE: orderly main and observer shutdown was not established.');
    Exit(1);
  end;
  if (M.Samples < 2) or (M.FailedSamples <> 0) then
  begin
    Writeln('INCOMPLETE: resource observation contains missing samples.');
    Exit(3);
  end;
  Writeln('LIFECYCLE OBSERVED: duration completed and owned processes stopped normally.');
  Writeln('Resource growth requires review; these samples do not prove absence of leaks.');
  Writeln('Idle checks cover repeated observations in the six FP1 categories.');
  Result := 0;
end;

procedure RunSoakChild;
var
  Opt: TOptions;
  Seen, Repeated: TDetectionKinds;
begin
  Seen := [];
  Repeated := [];
  ExitCode := 1;
  if not SetConsoleCtrlHandler(@ConsoleControl, True) then RaiseLastOSError;
  try
    ResolveWinPointers;
    ResolveNativeAPIs;
    ConfigureDefaultMonitoring(Opt);
    Run(Opt,
      function: Boolean
      begin
        Result := ValidationStopRequested;
      end,
      procedure(const Kinds: TDetectionKinds; const Confirmed: Boolean)
      var
        Observed: TDetectionKinds;
      begin
        Observed := Kinds * FP1_IDLE_KINDS;
        Repeated := Repeated + (Seen * Observed);
        Seen := Seen + Observed;
      end);
    if ValidationStopRequested then
    begin
      if Repeated = [] then ExitCode := 0
      else ExitCode := FP1_IDLE_REPEATED_EXIT;
    end;
  finally
    SetConsoleCtrlHandler(@ConsoleControl, False);
  end;
end;

function RunChildSelfMode: Boolean;
var I: Integer;
begin
  Result := True;
  if (ParamCount = 1) and (ParamStr(1) = '--child-ok') then
  begin
    Writeln('child-ok'); ExitCode := 0;
  end
  else if (ParamCount = 1) and (ParamStr(1) = '--child-fail') then
    ExitCode := 17
  else if (ParamCount = 1) and (ParamStr(1) = '--child-output') then
  begin
    for I := 1 to 160 do Writeln(StringOfChar('x', 4096));
    ExitCode := 0;
  end
  else if (ParamCount = 1) and (ParamStr(1) = '--child-wait') then
  begin
    Sleep(60000); ExitCode := 0;
  end
  else if (ParamCount = 1) and (ParamStr(1) = '--child-soak') then
  begin
    try
      RunSoakChild;
    except
      on E: Exception do
      begin
        Writeln('SOAK ENGINE ERROR: ', E.ClassName);
        ExitCode := 2;
      end;
    end;
  end
  else Result := False;
end;

var
  Options: TRunOptions;
  Root: string;
  SuiteCode: Integer;
begin
  if TryRunObserverMode then Exit;
  if RunChildSelfMode then Exit;
  if (ParamCount = 1) and ((ParamStr(1) = '--help') or (ParamStr(1) = '/?')) then
  begin
    ShowHelp; Exit;
  end;
  try
    Options := ParseOptions;
    Root := IncludeTrailingPathDelimiter(ExpandFileName(ExtractFilePath(ParamStr(0)) + '..'));
    SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
    if not SetConsoleCtrlHandler(@ConsoleControl, True) then RaiseLastOSError;
    try
      Writeln('Cozy NHW FullValidation - result labels reflect this run only.');
      if not RunHarnessSelfTests then
      begin
        Writeln('BLOCKED: validation harness self-check failed.');
        ExitCode := 2;
        Exit;
      end;
      case Options.Mode of
        rmSelfTest: ExitCode := 0;
        rmSuite: ExitCode := RunSuite(Root, Options);
        rmSoak: ExitCode := RunSoak(Options.Minutes);
        rmAll:
          begin
            SuiteCode := RunSuite(Root, Options);
            if SuiteCode <> 0 then
            begin
              Writeln('SOAK BLOCKED: regression suite did not complete successfully.');
              ExitCode := SuiteCode;
            end
            else ExitCode := RunSoak(Options.Minutes);
          end;
      end;
      Writeln('VALIDATION EXIT CODE: ', ExitCode);
    finally
      SetConsoleCtrlHandler(@ConsoleControl, False);
    end;
  except
    on E: Exception do
    begin
      Writeln('VALIDATION ERROR: ', E.ClassName, ': ', E.Message);
      ExitCode := 2;
    end;
  end;
end.
