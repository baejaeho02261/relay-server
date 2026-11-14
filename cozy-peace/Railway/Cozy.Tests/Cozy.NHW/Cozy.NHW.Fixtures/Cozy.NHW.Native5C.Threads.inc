type
  TReferenceFailNotify = class
    procedure Notify(Sender: TObject; const Item: THandle;
      Action: TCollectionNotification);
  end;
var
  RefTestMode, RefTestNextCalls, RefTestClosed: Integer;
  RefTestCloseValues: array[0..MAX_TARGET_THREADS + 4] of THandle;
procedure TReferenceFailNotify.Notify(Sender: TObject; const Item: THandle;
  Action: TCollectionNotification);
begin
  if Action = cnAdded then raise EOutOfMemory.Create('synthetic post-insertion failure');
end;
function RefTestOpen(PID, Rights: Cardinal): THandle;
begin
  if RefTestMode = 1 then Exit(0);
  Result := 100;
end;
function RefTestNext(ProcessHandle, Previous: THandle; Rights: Cardinal;
  out Next: THandle): TNTStatus;
begin
  Inc(RefTestNextCalls);
  Next := 0;
  if RefTestMode = 2 then Exit(TNTStatus($8000001A));
  if RefTestMode = 7 then
  begin
    Next := THandle(1000 + RefTestNextCalls);
    Exit(0);
  end;
  if RefTestNextCalls = 1 then
  begin Next := 201; Exit(0); end;
  case RefTestMode of
    3: Exit(TNTStatus($C0000022));
    4: begin Next := 202; Exit(TNTStatus($C0000022)); end;
    5: begin Next := 201; Exit(0); end;
    6: Exit(0); // success with no handle is not a normal enumeration end
  end;
  Result := TNTStatus($8000001A);
end;
procedure RefTestClose(var Handle: THandle);
begin
  if Handle <> 0 then
  begin
    RefTestCloseValues[RefTestClosed] := Handle;
    Inc(RefTestClosed);
  end;
  Handle := 0;
end;
function TestThreadsHardening(out Failure: string; out Checks: Integer): Boolean;
var
  L: TList<THandle>;
  N: TReferenceFailNotify;
  Raised: Boolean;
  I: Integer;
  procedure Check(V: Boolean; const Name: string);
  begin Inc(Checks); if not V then raise Exception.Create(Name); end;
  procedure Mode(M: Integer);
  begin
    RefTestMode := M; RefTestNextCalls := 0; RefTestClosed := 0;
    FillChar(RefTestCloseValues, SizeOf(RefTestCloseValues), 0);
  end;
  function Capture(PID: Cardinal; Available: Boolean): Boolean;
  begin
    Result := CaptureReferencesCore(PID, L, Available,
      RefTestOpen, RefTestNext, RefTestClose);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  L := nil; N := nil;
  try
    try
      L := TList<THandle>.Create; N := TReferenceFailNotify.Create;
      Mode(0); ReleaseReferencesCore(nil, RefTestClose);
      Check(not CaptureReferencesCore(1, nil, True, RefTestOpen,
        RefTestNext, RefTestClose), 'nil list rejected');
      Check(not Capture(0, True), 'zero target rejected');
      Check(RefTestNextCalls = 0, 'zero target did not enumerate');
      L.Add(301); L.Add(301); L.Add(0); L.Add(THandle(High(NativeUInt)));
      ReleaseReferencesCore(L, RefTestClose);
      Check((L.Count = 0) and (RefTestClosed = 1), 'duplicate and invalid cleanup');
      Mode(1); Check(not Capture(99, True), 'open failure');
      Check((L.Count = 0) and (RefTestClosed = 0), 'open failure owns nothing');
      Mode(0); L.Add(302); Check(not Capture(99, False), 'unavailable enumerator');
      Check((L.Count = 0) and (RefTestClosed = 1), 'old references released');
      Mode(2); Check(Capture(99, True), 'empty completed enumeration');
      Check((L.Count = 0) and (RefTestClosed = 1), 'empty closes process only');
      Mode(0); Check(Capture(99, True), 'one-thread normal end');
      Check((L.Count = 1) and (L[0] = 201), 'reference retained for caller snapshot');
      Check(RefTestClosed = 1, 'success closes process only');
      ReleaseReferencesCore(L, RefTestClose);
      Check(RefTestClosed = 2, 'later release closes thread');
      Mode(3); Check(not Capture(99, True), 'mid-enumeration error');
      Check((L.Count = 0) and (RefTestClosed = 2), 'partial set cleaned');
      Mode(4); Check(not Capture(99, True), 'error accompanied by handle');
      Check((L.Count = 0) and (RefTestClosed = 3), 'uncommitted failure handle cleaned');
      Mode(5); Check(not Capture(99, True), 'duplicate returned reference');
      Check((L.Count = 0) and (RefTestClosed = 2), 'duplicate closed once');
      Mode(6); Check(not Capture(99, True), 'success with zero handle rejected');
      Check((L.Count = 0) and (RefTestClosed = 2), 'zero-handle partial cleanup');
      Mode(7); Check(not Capture(99, True), 'thread cap is incomplete coverage');
      Check((RefTestNextCalls = MAX_TARGET_THREADS) and (L.Count = 0), 'bounded loop');
      Check(RefTestClosed = MAX_TARGET_THREADS + 1, 'cap handles cleaned');
      Mode(0); Raised := False; L.OnNotify := N.Notify;
      try
        Capture(99, True);
      except on E: EOutOfMemory do Raised := True; end;
      Check(Raised, 'post-insertion exception propagated');
      Check((L.Count = 0) and (RefTestClosed = 2), 'exception ownership cleaned');
      L.OnNotify := nil;
      for I := 0 to RefTestClosed - 1 do
        Check(RefTestCloseValues[I] <> 0, 'no zero close');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    if L <> nil then
    begin L.OnNotify := nil; ReleaseReferencesCore(L, RefTestClose); end;
    N.Free; L.Free;
  end;
end;
