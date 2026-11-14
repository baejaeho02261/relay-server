var
  SnapshotTestCaptureStatus, SnapshotTestFreeStatus: Cardinal;
  SnapshotTestBadClass: Integer;
  SnapshotTestThreadCount: Cardinal;
  SnapshotTestCaptureCalls, SnapshotTestFreeCalls, SnapshotTestQueryCalls: Integer;
  SnapshotTestNullHandle, SnapshotTestRaiseQuery, SnapshotTestRaiseFree: Boolean;
function SnapshotTestCapture(Process: THandle; Flags, ContextFlags: Cardinal;
  out Snapshot: THandle): Cardinal; stdcall;
begin
  Inc(SnapshotTestCaptureCalls);
  if SnapshotTestNullHandle then Snapshot := 0 else Snapshot := $100000;
  Result := SnapshotTestCaptureStatus;
end;
function SnapshotTestFree(Process: THandle; Snapshot: THandle): Cardinal; stdcall;
begin
  Inc(SnapshotTestFreeCalls);
  if SnapshotTestRaiseFree then raise Exception.Create('synthetic free exception');
  Result := SnapshotTestFreeStatus;
end;
function SnapshotTestQuery(Snapshot: THandle; InformationClass: Cardinal;
  Buffer: Pointer; BufferLength: Cardinal): Cardinal; stdcall;
var T: TPSSCapturedThreads;
begin
  Inc(SnapshotTestQueryCalls);
  if SnapshotTestRaiseQuery then raise Exception.Create('synthetic query exception');
  FillChar(Buffer^, BufferLength, 0);
  if InformationClass = PSS_QUERY_THREAD_INFORMATION then
  begin
    T := Default(TPSSCapturedThreads); T.ThreadsCaptured := SnapshotTestThreadCount;
    Move(T, Buffer^, SizeOf(T));
  end
  else if InformationClass = PSS_QUERY_HANDLE_INFORMATION then PCardinal(Buffer)^ := 100
  else PCardinal(Buffer)^ := 50;
  if Integer(InformationClass) = SnapshotTestBadClass then Result := ERROR_BAD_LENGTH
  else Result := ERROR_SUCCESS;
end;
function TestProcessSnapshotHardening(out Failure: string; out Checks: Integer): Boolean;
var
  C: TPssCaptureSnapshot; F: TPssFreeSnapshot; Q: TPssQuerySnapshot;
  Tried, Uncertain: Boolean; UncertainHandle: THandle; LastError: Cardinal;
  A, B: TForensicSnapshot; M: TProcessSnapshotMonitor;
  Detected: TDetectionKinds; I, Calls: Integer; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure ClearFake;
  begin
    SnapshotTestCaptureStatus := 0; SnapshotTestFreeStatus := 0;
    SnapshotTestBadClass := -1; SnapshotTestThreadCount := 1;
    SnapshotTestCaptureCalls := 0; SnapshotTestFreeCalls := 0; SnapshotTestQueryCalls := 0;
    SnapshotTestNullHandle := False; SnapshotTestRaiseQuery := False; SnapshotTestRaiseFree := False;
    PSSCleanupUncertain := False; PSSUncertainSnapshot := 0; PSSLastError := 0;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  C := CaptureSnapshotFn; F := FreeSnapshotFn; Q := QuerySnapshotFn;
  Tried := PSSTried; Uncertain := PSSCleanupUncertain;
  UncertainHandle := PSSUncertainSnapshot; LastError := PSSLastError;
  try
    try
      PSSTried := True; CaptureSnapshotFn := SnapshotTestCapture;
      FreeSnapshotFn := SnapshotTestFree; QuerySnapshotFn := SnapshotTestQuery;
      ClearFake;
      A := Default(TForensicSnapshot); B := A;
      Check(not SnapshotCountDelta(A, B, True), 'uncaptured not evidence');
      A.Captured := True; B.Captured := True; B.HandleCount := 12;
      Check(not SnapshotCountDelta(A, B, True), '12 handles not a delta');
      B.HandleCount := 13;
      Check(SnapshotCountDelta(A, B, True), '13 handles a delta');
      Check(not SnapshotCountDelta(A, B, False), 'independent evidence required');
      A.HandleCount := High(Cardinal); B.HandleCount := High(Cardinal) - 12;
      Check(not SnapshotCountDelta(A, B, True), 'handle threshold no wrap');
      Check(CaptureSnapshotMetadata(100, A), 'complete PSS metadata');
      Check(A.Captured and (A.ThreadCount = 1) and (A.HandleCount = 100), 'PSS counts committed');
      Check((SnapshotTestQueryCalls = 3) and (SnapshotTestFreeCalls = 1), 'same snapshot queried and freed once');
      for I := 3 to 5 do
      begin
        ClearFake; SnapshotTestBadClass := I;
        Check(not CaptureSnapshotMetadata(200, A), 'query failure rejected');
        Check(not A.Captured and (A.HandleCount = 0), 'query failure clears snapshot');
        Check(SnapshotTestFreeCalls = 1, 'query failure closes once');
      end;
      ClearFake; SnapshotTestThreadCount := 0;
      Check(not CaptureSnapshotMetadata(250, A), 'zero self-thread count rejected');
      Check(not A.Captured and (SnapshotTestFreeCalls = 1), 'unwritten count closed but not committed');
      ClearFake; SnapshotTestCaptureStatus := ERROR_ACCESS_DENIED;
      Check(not CaptureSnapshotMetadata(300, A), 'capture failure rejected');
      Check(SnapshotTestFreeCalls = 0, 'failed capture output not treated as owned');
      ClearFake; SnapshotTestNullHandle := True;
      Check(not CaptureSnapshotMetadata(400, A), 'successful status with null handle rejected');
      Check(SnapshotTestFreeCalls = 0, 'null handle not freed');
      ClearFake; SnapshotTestFreeStatus := ERROR_INVALID_HANDLE;
      Check(not CaptureSnapshotMetadata(500, A), 'free failure invalidates observation');
      Check(PSSCleanupUncertain and (PSSUncertainSnapshot <> 0), 'ambiguous descriptor retained diagnostically');
      Calls := SnapshotTestCaptureCalls;
      Check(not CaptureSnapshotMetadata(600, A), 'new snapshots stopped after free failure');
      Check((SnapshotTestCaptureCalls = Calls) and (SnapshotTestFreeCalls = 1), 'no repeated free or resource accumulation');
      M := TProcessSnapshotMonitor.Create; M.Reset;
      Check(PSSCleanupUncertain, 'monitor reset does not clear cleanup uncertainty');
      ClearFake; SnapshotTestRaiseQuery := True; Raised := False;
      try CaptureSnapshotMetadata(700, A); except on E: Exception do Raised := True; end;
      Check(Raised and (SnapshotTestFreeCalls = 1), 'query exception still frees');
      Check(not A.Captured, 'query exception does not commit');
      ClearFake; SnapshotTestRaiseFree := True; Raised := False;
      try CaptureSnapshotMetadata(800, A); except on E: Exception do Raised := True; end;
      Check(Raised and PSSCleanupUncertain, 'free exception blocks new captures');
      ClearFake; Detected := []; M.Reset;
      M.Examine(True, True, False, 10000, Detected);
      SnapshotTestThreadCount := 2; M.Examine(True, False, True, 16000, Detected);
      Check(M.FConfirmations = 1, 'first corroborated delta');
      SnapshotTestBadClass := 4; M.Examine(True, False, True, 22000, Detected);
      Check((M.FConfirmations = 0) and not M.FPrevious.Captured, 'failed sample breaks continuity');
      SnapshotTestBadClass := -1; SnapshotTestThreadCount := 3;
      M.Examine(True, False, True, 28000, Detected);
      Check(M.FConfirmations = 0, 'first recovery sample is a new anchor');
      SnapshotTestThreadCount := 4; M.Examine(True, False, True, 34000, Detected);
      Check(not (dkProcessSnapshot in Detected), 'one post-gap delta insufficient');
      SnapshotTestThreadCount := 5; M.Examine(True, False, True, 40000, Detected);
      Check(dkProcessSnapshot in Detected, 'two new post-gap deltas detect');
      M.Examine(False, False, False, 41000, Detected);
      Check(not M.FPrevious.Captured and (M.FConfirmations = 0), 'target change breaks continuity');
      Detected := []; M.Reset; ClearFake;
      M.Examine(True, True, True, 1000, Detected);
      Calls := SnapshotTestCaptureCalls;
      M.Examine(True, False, True, 2499, Detected, True);
      Check(SnapshotTestCaptureCalls = Calls, 'fast cooldown before 1500ms');
      M.Examine(True, False, True, 2500, Detected, True);
      Check(SnapshotTestCaptureCalls = Calls + 1, 'fast cooldown at 1500ms');
      M.Examine(True, False, True, 100, Detected);
      Check((M.FConfirmations = 0) and not (dkProcessSnapshot in Detected), 'clock rollback reanchors');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free;
    CaptureSnapshotFn := C; FreeSnapshotFn := F; QuerySnapshotFn := Q;
    PSSTried := Tried; PSSCleanupUncertain := Uncertain;
    PSSUncertainSnapshot := UncertainHandle; PSSLastError := LastError;
  end;
end;
