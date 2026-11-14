var
  TestHeapMode, TestHeapCalls, TestHeapDestroys: Integer;
function TestGetHeaps(NumberOfHeaps: Cardinal; Heaps: Pointer): Cardinal; stdcall;
var
  Values: array[0..2] of NativeUInt;
begin
  if NumberOfHeaps = 0 then
  begin
    if TestHeapMode = 5 then Exit(513);
    Exit(2);
  end;
  Inc(TestHeapCalls);
  if TestHeapMode = 1 then Exit(NumberOfHeaps + 1);
  if (TestHeapMode = 2) and (TestHeapCalls = 1) then Exit(3);
  if TestHeapMode = 6 then Exit(0);
  Values[0] := 300; Values[1] := 100; Values[2] := 200;
  Result := 2;
  if TestHeapMode = 2 then Result := 3;
  if TestHeapMode = 3 then Values[1] := 300;
  if TestHeapMode = 4 then Values[1] := 0;
  if TestHeapMode = 7 then Values[1] := High(NativeUInt);
  Move(Values[0], Heaps^, Result * SizeOf(NativeUInt));
end;
function TestDestroyHeap(Heap: THandle): BOOL; stdcall;
begin
  Inc(TestHeapDestroys);
  Result := TestHeapMode = 0;
end;
function TestHeapTLSNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedResolved: Integer;
  SavedAvailable: Boolean;
  SavedHeaps: TProcessHeapsFn;
  SavedDestroy: THeapDestroyFn;
  A: TArray<NativeUInt>;
  H: THandle;
  procedure Check(V: Boolean; const Name: string);
  begin Inc(Checks); if not V then raise Exception.Create(Name); end;
  procedure Mode(N: Integer);
  begin TestHeapMode := N; TestHeapCalls := 0; end;
begin
  Result := False; Failure := ''; Checks := 0;
  SavedResolved := HeapTLSResolved; SavedAvailable := FAvailable;
  SavedHeaps := ProcessHeapsFn; SavedDestroy := HeapDestroyFn;
  try
    try
      HeapTLSResolved := 1; FAvailable := True;
      ProcessHeapsFn := TestGetHeaps;
      Mode(0); Check(LocalHeapSnapshot(A), 'heap snapshot accepted');
      Check((Length(A) = 2) and (A[0] = 100) and (A[1] = 300), 'deterministic heap sort');
      Mode(2); Check(LocalHeapSnapshot(A), 'growing heap list retried');
      Check((Length(A) = 3) and (TestHeapCalls = 2), 'growth retry result');
      Mode(1); Check(not LocalHeapSnapshot(A), 'endless growth fails');
      Check((Length(A) = 0) and (TestHeapCalls = 3), 'bounded retries no partial snapshot');
      Mode(3); Check(not LocalHeapSnapshot(A), 'duplicate handles rejected');
      Check(Length(A) = 0, 'duplicates no output');
      Mode(4); Check(not LocalHeapSnapshot(A), 'zero heap rejected');
      Mode(5); Check(not LocalHeapSnapshot(A), 'heap cap enforced');
      Check(TestHeapCalls = 0, 'over-cap allocation avoided');
      Mode(6); Check(not LocalHeapSnapshot(A), 'failed heap query');
      Mode(7); Check(not LocalHeapSnapshot(A), 'invalid heap rejected');
      HeapDestroyFn := TestDestroyHeap;
      TestHeapDestroys := 0; H := 123; Mode(1);
      LocalHeapDestroy(H); Check(H = 123, 'destroy failure preserves owner handle');
      Mode(0); LocalHeapDestroy(H); Check(H = 0, 'successful destroy invalidates handle');
      LocalHeapDestroy(H); Check(TestHeapDestroys = 2, 'zero handle not destroyed twice');
      H := INVALID_HANDLE_VALUE; LocalHeapDestroy(H);
      Check(TestHeapDestroys = 2, 'invalid handle not sent to heap API');
      Check(not LocalTlsSetValue(INVALID_LOCAL_SLOT, nil), 'invalid TLS slot rejected');
      Check(not LocalFlsSetValue(INVALID_LOCAL_SLOT, nil), 'invalid FLS slot rejected');
      Check(LocalTlsGetValue(INVALID_LOCAL_SLOT) = nil, 'invalid TLS read');
      Check(LocalFlsGetValue(INVALID_LOCAL_SLOT) = nil, 'invalid FLS read');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    HeapTLSResolved := SavedResolved; FAvailable := SavedAvailable;
    ProcessHeapsFn := SavedHeaps; HeapDestroyFn := SavedDestroy;
  end;
end;
