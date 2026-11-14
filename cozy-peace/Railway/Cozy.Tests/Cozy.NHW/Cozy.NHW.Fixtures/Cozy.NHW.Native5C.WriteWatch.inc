var
  WatchTestMode, WatchTestCalls, WatchTestFrees, WatchTestAllocs: Integer;
function WatchTestAlloc(Address: Pointer; Size: NativeUInt;
  AllocationType, Protect: Cardinal): Pointer; stdcall;
begin
  Inc(WatchTestAllocs);
  if WatchTestMode = 8 then Exit(nil);
  Result := Pointer(NativeUInt($100000));
end;
function WatchTestFree(Address: Pointer; Size: NativeUInt;
  FreeType: Cardinal): BOOL; stdcall;
begin
  Inc(WatchTestFrees);
  Result := (WatchTestMode <> 9) and (Size = 0) and (FreeType = NHW_MEM_RELEASE);
end;
procedure WatchTestInfo(var Info: TSystemInfo); stdcall;
begin
  Info := Default(TSystemInfo); Info.dwPageSize := 4096;
  if WatchTestMode = 10 then Info.dwPageSize := 8192;
end;
function WatchTestQuery(Flags: Cardinal; Address: Pointer; RegionSize: NativeUInt;
  Pages: PPointer; var Count: NativeUInt; var Granularity: Cardinal): Cardinal; stdcall;
var P: array[0..3] of Pointer;
begin
  Inc(WatchTestCalls);
  Result := 0; Granularity := 4096; Count := 2;
  P[0] := Address; P[1] := Pointer(NativeUInt(Address) + 4096);
  P[2] := nil; P[3] := nil;
  case WatchTestMode of
    1: begin Count := 0; end;
    2: begin Count := 5; end;
    3: Granularity := 8192;
    4: P[1] := Pointer(NativeUInt(Address) + RegionSize);
    5: P[1] := Pointer(NativeUInt(Address) - 4096);
    6: P[1] := Pointer(NativeUInt(Address) + 1);
    7: Result := 5;
    11: P[1] := P[0];
  end;
  if Flags <> NHW_WRITE_WATCH_RESET then Result := 87;
  Move(P[0], Pages^, SizeOf(P));
end;
function TestWriteWatchHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedResolved: Integer;
  SavedAlloc: TVirtualAllocPtr; SavedFree: TVirtualFreePtr;
  SavedWatch: TGetWriteWatchPtr; SavedInfo: TGetNativeSystemInfoPtr;
  P: Pointer; Bytes: NativeUInt; PageSize, Mask: Cardinal; M: Integer;
  procedure Check(V: Boolean; const Name: string);
  begin Inc(Checks); if not V then raise Exception.Create(Name); end;
begin
  Result := False; Failure := ''; Checks := 0;
  SavedResolved := APIsResolved; SavedAlloc := AllocPtr; SavedFree := FreePtr;
  SavedWatch := GetWatchPtr; SavedInfo := InfoPtr;
  try
    try
      APIsResolved := 1; AllocPtr := WatchTestAlloc; FreePtr := WatchTestFree;
      GetWatchPtr := WatchTestQuery; InfoPtr := WatchTestInfo;
      WatchTestCalls := 0; WatchTestFrees := 0; WatchTestAllocs := 0;
      WatchTestMode := 8; P := nil;
      Check(not CreateWriteWatchRegion(P, Bytes, PageSize), 'allocation failed');
      Check((P = nil) and (Bytes = 0) and (PageSize = 0), 'failed allocation outputs zero');
      WatchTestMode := 10;
      Check(not CreateWriteWatchRegion(P, Bytes, PageSize), 'unsupported page size');
      Check(WatchTestAllocs = 1, 'unsupported page no allocation');
      WatchTestMode := 0;
      Check(CreateWriteWatchRegion(P, Bytes, PageSize), 'create region');
      Check((Bytes = 16384) and (PageSize = 4096), 'same four-page contract');
      Check(QueryAndResetWriteWatch(P, Bytes, PageSize, Mask), 'valid watch query');
      Check(Mask = 3, 'two pages published');
      WatchTestMode := 1;
      Check(QueryAndResetWriteWatch(P, Bytes, PageSize, Mask), 'empty dirty set valid');
      Check(Mask = 0, 'empty dirty mask');
      for M := 2 to 7 do
      begin
        WatchTestMode := M; Mask := $FFFFFFFF;
        Check(not QueryAndResetWriteWatch(P, Bytes, PageSize, Mask), 'malformed or failed query');
        Check(Mask = 0, 'no partial dirty mask');
      end;
      WatchTestMode := 11;
      Check(QueryAndResetWriteWatch(P, Bytes, PageSize, Mask), 'duplicate page idempotent');
      Check(Mask = 1, 'duplicate page has one bit');
      Check(not QueryAndResetWriteWatch(Pointer(NativeUInt($100001)),
        Bytes, PageSize, Mask), 'unaligned base rejected');
      Check(not QueryAndResetWriteWatch(Pointer(High(NativeUInt) - 4095),
        Bytes, PageSize, Mask), 'wrapping region rejected');
      Check(not QueryAndResetWriteWatch(nil, Bytes, PageSize, Mask), 'nil region');
      WatchTestMode := 9; ReleaseWriteWatchRegion(P);
      Check(P = Pointer(NativeUInt($100000)), 'failed free preserves owner');
      Check(not CreateWriteWatchRegion(P, Bytes, PageSize), 'old owner cannot be overwritten');
      Check(P = Pointer(NativeUInt($100000)), 'creation refusal preserves owner');
      FreePtr := nil; ReleaseWriteWatchRegion(P);
      Check(P <> nil, 'missing free preserves owner');
      FreePtr := WatchTestFree; WatchTestMode := 0; ReleaseWriteWatchRegion(P);
      Check(P = nil, 'successful free clears owner');
      ReleaseWriteWatchRegion(P);
      Check(WatchTestFrees = 2, 'nil free avoided');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    APIsResolved := SavedResolved; AllocPtr := SavedAlloc; FreePtr := SavedFree;
    GetWatchPtr := SavedWatch; InfoPtr := SavedInfo;
  end;
end;
