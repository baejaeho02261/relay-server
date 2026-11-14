var MappingTestMode, MappingTestCalls: Integer;
function MappingTestWS(ProcessHandle: THandle; Buffer: Pointer;
  BufferBytes: Cardinal): BOOL; stdcall;
var P: ^TMappingWorkingSetItem;
begin
  Inc(MappingTestCalls); P := Buffer;
  P^.Attributes := NativeUInt($8001);
  if MappingTestMode = 1 then Exit(False);
  if MappingTestMode = 2 then raise Exception.Create('synthetic query exception');
  Result := True;
end;
function MappingTestName(ProcessHandle: THandle; Address: Pointer;
  Buffer: PWideChar; Characters: Cardinal): Cardinal; stdcall;
const V: array[0..3] of WideChar = ('a', 'b', 'c', #0);
begin
  Move(V[0], Buffer^, SizeOf(V));
  case MappingTestMode of
    1: Exit(0);
    2: Exit(Characters);
    3: begin Buffer[1] := #0; Exit(3); end;
  end;
  Result := 3;
end;
function TestMappingHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedResolved: Integer; SavedWS: TQueryWorkingSetExPtr;
  SavedName: TGetMappedFileNamePtr;
  A: array[0..1] of TMappingWorkingSetItem;
  Path: string; Raised: Boolean;
  procedure Check(V: Boolean; const Name: string);
  begin Inc(Checks); if not V then raise Exception.Create(Name); end;
  procedure Dirty;
  begin A[0].Attributes := $8001; A[1].Attributes := $8001; end;
begin
  Result := False; Failure := ''; Checks := 0;
  SavedResolved := Resolved; SavedWS := WSPtr; SavedName := FilenamePtr;
  try
    try
      Resolved := 1; WSPtr := MappingTestWS; FilenamePtr := MappingTestName;
      A[0].VirtualAddress := Pointer(NativeUInt($100000));
      A[1].VirtualAddress := Pointer(NativeUInt($101000));
      MappingTestMode := 1; MappingTestCalls := 0; Dirty;
      Check(not QueryMappingWorkingSet(1, A, 2), 'partial failed WS rejected');
      Check((A[0].Attributes = 0) and (A[1].Attributes = 0), 'failed WS invalidated');
      Check(A[0].VirtualAddress = Pointer(NativeUInt($100000)), 'input address preserved');
      MappingTestMode := 2; Dirty; Raised := False;
      try QueryMappingWorkingSet(1, A, 2);
      except on E: Exception do Raised := True; end;
      Check(Raised, 'WS exception propagated');
      Check((A[0].Attributes = 0) and (A[1].Attributes = 0), 'WS exception cleanup');
      MappingTestMode := 0; Dirty;
      Check(QueryMappingWorkingSet(1, A, 2), 'successful WS');
      Check(MappingPageResident(A[0]) and MappingPageShared(A[0]), 'valid shared resident');
      Check(not MappingPageResident(A[1]), 'unwritten flags do not retain old data');
      A[0].Attributes := $8000;
      Check(not MappingPageShared(A[0]), 'invalid page not treated as shared observation');
      A[0].Attributes := 1;
      Check(MappingPageResident(A[0]) and not MappingPageShared(A[0]), 'private resident');
      Dirty; Check(not QueryMappingWorkingSet(1, A, -1), 'negative count rejected');
      Check(A[0].Attributes = 0, 'invalid count clears stale output');
      Dirty; Check(not QueryMappingWorkingSet(1, A, 3), 'capacity rejected');
      Check(not QueryMappingWorkingSet(0, A, 2), 'zero process rejected');
      A[0].VirtualAddress := nil;
      Check(not QueryMappingWorkingSet(1, A, 2), 'nil page address rejected');
      Check(QueryMappingBacking(1, $100000, Path), 'mapping name accepted');
      Check(Path = 'abc', 'mapping name exact length');
      MappingTestMode := 1; Check(not QueryMappingBacking(1, $100000, Path), 'name failure');
      Check(Path = '', 'name failure clears prior value');
      MappingTestMode := 2; Check(not QueryMappingBacking(1, $100000, Path), 'name truncation');
      MappingTestMode := 3; Check(not QueryMappingBacking(1, $100000, Path), 'embedded null rejected');
      Check(not QueryMappingBacking(1, High(NativeUInt), Path), 'bad mapping span');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    Resolved := SavedResolved; WSPtr := SavedWS; FilenamePtr := SavedName;
  end;
end;
