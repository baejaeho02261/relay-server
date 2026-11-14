type TStackTestFrames = array[0..MAX_BACKTRACE_FRAMES-1] of Pointer;
     PStackTestFrames = ^TStackTestFrames;
var
  StackTestCount: Word;
  StackTestBadIndex, StackTestPrivateIndex, StackTestCalls: Integer;
  StackTestUnknown, StackTestZeroBase, StackTestRaise: Boolean;
  StackTestFrames: TStackTestFrames;
function StackTestCapture(Skip, Capacity: Cardinal;
  Buffer: Pointer; Hash: Pointer): Word; stdcall;
var I: Integer;
begin
  for I := 0 to Integer(Capacity) - 1 do
    if I < MAX_BACKTRACE_FRAMES then
      PStackTestFrames(Buffer)^[I] := StackTestFrames[I];
  Result := StackTestCount;
end;
function StackTestDescribe(Address: NativeUInt; out Kind: TCodeLocation;
  out Base: NativeUInt): Boolean;
var I: Integer;
begin
  Inc(StackTestCalls);
  I := Integer((Address - $10000) div $1000);
  Kind := clImage;
  Base := $10000;
  if I = StackTestBadIndex then
  begin
    if StackTestRaise then raise Exception.Create('synthetic frame query failure');
    if StackTestUnknown then Kind := clUnknown;
    if StackTestZeroBase then Base := 0;
    Exit(StackTestUnknown or StackTestZeroBase);
  end;
  if I = StackTestPrivateIndex then
  begin Kind := clPrivate; Base := $90000; end;
  Result := True;
end;
function TestThreadStackHardening(out Failure: string;
  out Checks: Integer): Boolean;
var
  SavedTrace: TBackTrace; SavedResolved: Boolean; SavedHook: TStackDescribeHook;
  M: TThreadStackProvenanceMonitor; Region: NativeUInt;
  D: TDetectionKinds; I: Integer; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Setup;
  var J: Integer;
  begin
    for J := 0 to MAX_BACKTRACE_FRAMES - 1 do
      StackTestFrames[J] := Pointer(NativeUInt($10000) + NativeUInt(J) * $1000);
    StackTestCount := 3; StackTestBadIndex := -1; StackTestPrivateIndex := -1;
    StackTestUnknown := False; StackTestZeroBase := False;
    StackTestRaise := False; StackTestCalls := 0;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedTrace := BackTraceFn; SavedResolved := BackTraceResolved;
  SavedHook := StackDescribeHook;
  try
    try
      BackTraceResolved := True; BackTraceFn := StackTestCapture;
      StackDescribeHook := StackTestDescribe;
      Setup;
      Check(CaptureCurrentStackOrigin(Region) and (Region = 0), 'complete image-only stack');
      Check(StackTestCalls = 3, 'all reported frames inspected');
      StackTestPrivateIndex := 0; StackTestCalls := 0;
      Check(CaptureCurrentStackOrigin(Region) and (Region = $90000), 'private candidate published');
      Check(StackTestCalls = 3, 'private first frame does not skip later frames');
      StackTestBadIndex := 2;
      Check(not CaptureCurrentStackOrigin(Region), 'late failed query rejects entire sample');
      Check(Region = 0, 'partial private result not leaked');
      StackTestUnknown := True;
      Check(not CaptureCurrentStackOrigin(Region) and (Region = 0), 'unknown kind is incomplete');
      StackTestUnknown := False; StackTestZeroBase := True;
      Check(not CaptureCurrentStackOrigin(Region), 'zero region rejected');
      Setup; StackTestFrames[1] := nil;
      Check(not CaptureCurrentStackOrigin(Region) and (Region = 0), 'null reported frame rejected');
      Setup; StackTestCount := 0;
      Check(not CaptureCurrentStackOrigin(Region), 'zero captured frames');
      Check(StackTestCalls = 0, 'zero count never walks frames');
      StackTestCount := MAX_BACKTRACE_FRAMES + 1;
      Check(not CaptureCurrentStackOrigin(Region), 'oversized return count rejected');
      Check(StackTestCalls = 0, 'oversized count never indexes frames');
      StackTestCount := High(Word);
      Check(not CaptureCurrentStackOrigin(Region), 'maximum Word count rejected');
      Setup; StackTestCount := MAX_BACKTRACE_FRAMES;
      Check(CaptureCurrentStackOrigin(Region), 'exact frame capacity accepted');
      Check(StackTestCalls = MAX_BACKTRACE_FRAMES, 'exact capacity loop bounded');
      Setup; StackTestPrivateIndex := 0; StackTestBadIndex := 2; StackTestRaise := True;
      Raised := False; Region := 42;
      try CaptureCurrentStackOrigin(Region); except on E: Exception do Raised := True; end;
      Check(Raised and (Region = 0), 'query exception preserves cleared output');
      Setup; M := TThreadStackProvenanceMonitor.Create; StackTestPrivateIndex := 0;
      D := []; M.Examine(False, True, 1000, D);
      Check((M.FConfirmations = 1) and (D = []), 'first candidate not reported');
      StackTestBadIndex := 2; M.Examine(False, True, 7000, D);
      Check((M.FConfirmations = 0) and (M.FPreviousRegion = 0), 'failed stack clears candidate');
      StackTestBadIndex := -1; M.Examine(False, True, 13000, D);
      Check((M.FConfirmations = 1) and (D = []), 'recovery must start from one');
      M.Examine(False, True, 19000, D);
      Check(dkThreadStackOrigin in D, 'two complete post-failure stacks report');
      M.Reset; D := []; M.Examine(False, False, 1000, D); M.Examine(False, False, 7000, D);
      Check(D = [], 'independent evidence still required');
      M.Reset; M.Examine(True, True, 1000, D);
      Check(M.FConfirmations = 0, 'baseline excluded');
      M.Examine(False, True, 7000, D); M.Examine(False, True, 38001, D);
      Check((M.FConfirmations = 1) and (D = []), 'long observation gap restarts candidate');
      M.Examine(False, True, 100, D);
      Check((M.FConfirmations = 1) and (D = []), 'clock rollback reanchors');
      StackTestPrivateIndex := -1; M.Examine(False, True, 6100, D);
      Check(M.FConfirmations = 0, 'normal sample clears private candidate');
      M.Reset; StackTestPrivateIndex := 0; D := [];
      for I := 0 to 9 do M.Examine(False, False, UInt64(1000 + I * 6000), D);
      Check((M.FConfirmations = 3) and (D = []), 'confirmation count saturates');
      StackTestBadIndex := 1; StackTestRaise := True; Raised := False;
      try M.Examine(False, True, 61000, D); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FConfirmations = 0), 'monitor invalidates on exception');
      BackTraceFn := nil;
      Check(not CaptureCurrentStackOrigin(Region), 'unavailable API remains unknown');
      Check(not StackOriginCandidate($90000, 1, True), 'single confirmation rejected');
      Check(StackOriginCandidate($90000, 2, True), 'existing two-sample rule preserved');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; BackTraceFn := SavedTrace; BackTraceResolved := SavedResolved;
    StackDescribeHook := SavedHook;
  end;
end;
