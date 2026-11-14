var
  TestStackMode: Integer;
function TestStackMemory(Handle: THandle; Address: Pointer;
  InfoClass: Cardinal; Buffer: Pointer; BufferLength: NativeUInt;
  Returned: PNativeUInt): LongInt; stdcall;
var
  R: TMemoryBasicX64;
begin
  R := Default(TMemoryBasicX64);
  R.BaseAddress := Pointer(NativeUInt($10000));
  R.AllocationBase := R.BaseAddress;
  R.RegionSize := $2000; R.State := MEM_COMMIT_VALUE;
  case TestStackMode of
    2: R.RegionSize := 0;
    3: R.RegionSize := High(NativeUInt);
    4: R.State := 999;
  end;
  Move(R, Buffer^, SizeOf(R)); Returned^ := SizeOf(R);
  if TestStackMode = 1 then Returned^ := 0;
  if TestStackMode = 5 then Returned^ := SizeOf(R) - 1;
  if TestStackMode = 6 then Exit(-1);
  Result := 0;
end;
function TestStackPID(Handle: THandle): Cardinal; stdcall;
begin Result := 123; end;
function TestStackThread(Handle: THandle; InfoClass: Cardinal;
  Buffer: Pointer; Bytes: Cardinal; Returned: PCardinal): LongInt; stdcall;
var
  R: TThreadBasicX64;
begin
  R := Default(TThreadBasicX64); R.ExitStatus := THREAD_STILL_ACTIVE;
  R.TebBaseAddress := Pointer(NativeUInt($20000));
  R.ClientProcessID := 123; R.ClientThreadID := 456;
  if TestStackMode = 10 then R.ClientProcessID := 124;
  if TestStackMode = 11 then R.ExitStatus := 0;
  if TestStackMode = 12 then R.TebBaseAddress := Pointer(High(NativeUInt) - 8);
  Move(R, Buffer^, SizeOf(R)); Returned^ := SizeOf(R);
  if TestStackMode = 13 then Returned^ := 0;
  Result := 0;
end;
function TestStackRead(Handle: THandle; Address, Buffer: Pointer;
  Bytes: NativeUInt; ReadBytes: PNativeUInt): LongInt; stdcall;
var
  R: TNTTibHead;
begin
  R := Default(TNTTibHead); R.SelfPtr := Address;
  R.StackBase := Pointer(NativeUInt($40000));
  R.StackLimit := Pointer(NativeUInt($30000));
  if TestStackMode = 14 then R.SelfPtr := nil;
  Move(R, Buffer^, SizeOf(R)); ReadBytes^ := SizeOf(R);
  if TestStackMode = 15 then ReadBytes^ := SizeOf(R) - 1;
  Result := 0;
end;
function TestStackNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedQuery: TNtQueryVirtualMemory;
  SavedThread: TNtQueryInformationThread;
  SavedRead: TNtReadVirtualMemory;
  SavedPID: TProcessIDFn;
  R: TMemoryBasicX64;
  A, B: TThreadBasicX64;
  X, Y: TNTTibHead;
  procedure Check(V: Boolean; const Name: string);
  begin Inc(Checks); if not V then raise Exception.Create(Name); end;
begin
  Result := False; Failure := ''; Checks := 0;
  SavedQuery := QueryMemoryPtr; SavedThread := QueryThreadPtr;
  SavedRead := ReadMemoryPtr; SavedPID := ProcessIDPtr;
  try
    try
      Check(SizeOf(TThreadBasicX64) = 48, 'thread basic ABI');
      Check(SizeOf(TNTTibHead) = 56, 'TIB ABI');
      Check(SizeOf(TMemoryBasicX64) = 48, 'memory basic ABI');
      Check(StackAddressSpan($10000, 1), 'normal span');
      Check(not StackAddressSpan(1, 1), 'low address rejected');
      Check(not StackAddressSpan($10000, 0), 'empty span rejected');
      Check(not StackAddressSpan(High(NativeUInt) - 1, 4), 'span overflow rejected');
      QueryMemoryPtr := TestStackMemory; TestStackMode := 0;
      Check(QueryPage(1, $10001, R), 'valid memory metadata');
      Check(not QueryPage(1, $13000, R), 'address outside region');
      TestStackMode := 1; Check(not QueryPage(1, $10001, R), 'missing returned length');
      Check(R.RegionSize = 0, 'failed region output reset');
      TestStackMode := 2; Check(not QueryPage(1, $10001, R), 'empty region');
      TestStackMode := 3; Check(not QueryPage(1, $10001, R), 'region overflow');
      TestStackMode := 4; Check(not QueryPage(1, $10001, R), 'unknown state');
      TestStackMode := 5; Check(not QueryPage(1, $10001, R), 'partial region response');
      TestStackMode := 6; Check(not QueryPage(1, $10001, R), 'query error');
      QueryThreadPtr := TestStackThread; ReadMemoryPtr := TestStackRead; ProcessIDPtr := TestStackPID;
      TestStackMode := 0; Check(ReadStackHead(1, 2, A, X), 'valid owned TIB');
      B := A; Y := X; Check(SameStackHead(A, B, X, Y), 'same snapshot endpoints');
      Y.StackLimit := Pointer(NativeUInt($31000));
      Check(not SameStackHead(A, B, X, Y), 'stack growth invalidates sweep');
      Y := X; Y.FiberData := Pointer(NativeUInt(1));
      Check(not SameStackHead(A, B, X, Y), 'fiber switch invalidates sweep');
      TestStackMode := 10; Check(not ReadStackHead(1, 2, A, X), 'wrong process thread rejected');
      TestStackMode := 11; Check(not ReadStackHead(1, 2, A, X), 'terminated thread rejected');
      TestStackMode := 12; Check(not ReadStackHead(1, 2, A, X), 'TEB span overflow rejected');
      TestStackMode := 13; Check(not ReadStackHead(1, 2, A, X), 'thread basic short response');
      TestStackMode := 14; Check(not ReadStackHead(1, 2, A, X), 'TIB self pointer mismatch');
      TestStackMode := 15; Check(not ReadStackHead(1, 2, A, X), 'short TIB read rejected');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    QueryMemoryPtr := SavedQuery; QueryThreadPtr := SavedThread;
    ReadMemoryPtr := SavedRead; ProcessIDPtr := SavedPID;
  end;
end;
