type PTestWorkingSetInfo = ^TWorkingSetInfo;
var
  COWTestBases: array[0..3] of NativeUInt;
  COWTestPages: array[0..3] of Integer;
  COWTestMode, COWTestWSCalls, COWTestRegionCalls: Integer;
  COWTestRegionFail, COWTestRegionMalformed, COWTestNonExec, COWTestRaise: Boolean;
  COWTestDuplicates: Integer;
  COWTestThisScan, COWTestAll: TDictionary<NativeUInt, Byte>;
function COWTestModule(Index: Integer): HMODULE;
begin Result := HMODULE(COWTestBases[Index]); end;
function COWTestRegion(Address: NativeUInt; out Region: TVirtualRegion): Boolean;
var I: Integer; ImageEnd: NativeUInt;
begin
  Inc(COWTestRegionCalls); Region := Default(TVirtualRegion);
  if COWTestRegionFail then Exit(False);
  if COWTestRaise then raise Exception.Create('synthetic COW region failure');
  for I := 0 to 3 do
    if (COWTestBases[I] <> 0) and (Address >= COWTestBases[I]) and
       (Address < COWTestBases[I] + NativeUInt(MAX_IMAGE_SCAN_BYTES)) then
    begin
      ImageEnd := COWTestBases[I] + NativeUInt(COWTestPages[I]) * PAGE_BYTES;
      if Address < ImageEnd then
      begin
        Region.BaseAddress := COWTestBases[I];
        Region.AllocationBase := COWTestBases[I];
        Region.Size := NativeUInt(COWTestPages[I]) * PAGE_BYTES;
        Region.State := ALLOC_MEM_COMMIT; Region.RegionType := ALLOC_MEM_IMAGE;
        if COWTestNonExec then
        begin Region.BaseAddress := Address; Region.Size := PAGE_BYTES; Region.Protect := $02; end
        else Region.Protect := ALLOC_PAGE_EXECUTE_READ;
      end
      else
      begin
        Region.BaseAddress := Address; Region.Size := PAGE_BYTES;
        Region.State := ALLOC_MEM_FREE;
      end;
      if COWTestRegionMalformed then Region.Size := 0;
      Exit(True);
    end;
  Result := False;
end;
function COWTestWS(Process: THandle; Info: Pointer; Bytes: Cardinal): BOOL; stdcall;
var Address: NativeUInt;
begin
  Inc(COWTestWSCalls);
  Address := NativeUInt(PTestWorkingSetInfo(Info)^.VirtualAddress);
  if COWTestThisScan.ContainsKey(Address) then Inc(COWTestDuplicates);
  COWTestThisScan.AddOrSetValue(Address, 1); COWTestAll.AddOrSetValue(Address, 1);
  PTestWorkingSetInfo(Info)^.Flags := 0;
  case COWTestMode of
    0: PTestWorkingSetInfo(Info)^.Flags := $8001; // shared + valid
    1: PTestWorkingSetInfo(Info)^.Flags := 1;     // private + valid
    2: PTestWorkingSetInfo(Info)^.Flags := $8000; // invalid shared bit ignored
    3: Exit(False);
  end;
  Result := True;
end;
function TestImageCOWHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedWS: TQueryWorkingSetEx; SavedResolved: Boolean;
  SavedModule: TCOWModuleHook; SavedRegion: TCOWRegionHook;
  M: TImageCOWMonitor; D: TDetectionKinds; I, J: Integer; Page: NativeUInt;
  Pending: Byte; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Setup(Pages: Integer; FourModules: Boolean);
  var K: Integer;
  begin
    M.Reset; D := []; COWTestMode := 0; COWTestRegionFail := False;
    COWTestRegionMalformed := False; COWTestNonExec := False; COWTestRaise := False;
    COWTestAll.Clear;
    for K := 0 to 3 do
    begin
      if FourModules or (K = 0) then COWTestBases[K] := NativeUInt(K + 1) * $10000000
      else COWTestBases[K] := 0;
      COWTestPages[K] := Pages;
    end;
  end;
  procedure Scan(Tick: UInt64; Baseline, CodeChange: Boolean);
  begin
    D := []; if CodeChange then Include(D, dkPECodeIntegrity);
    COWTestThisScan.Clear; COWTestDuplicates := 0;
    COWTestWSCalls := 0; COWTestRegionCalls := 0;
    M.Examine(Baseline, Tick, D);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  COWTestThisScan := nil; COWTestAll := nil;
  SavedWS := FQueryWS; SavedResolved := FQueryResolved;
  SavedModule := COWModuleHook; SavedRegion := COWRegionHook;
  try
    try
      FQueryResolved := True; FQueryWS := COWTestWS;
      COWModuleHook := COWTestModule; COWRegionHook := COWTestRegion;
      COWTestThisScan := TDictionary<NativeUInt, Byte>.Create;
      COWTestAll := TDictionary<NativeUInt, Byte>.Create;
      M := TImageCOWMonitor.Create; Setup(1000, True); Scan(1000, True, False);
      Check(COWTestWSCalls = MAX_COW_PAGES_PER_SCAN, '384-page global cap');
      Check(COWTestDuplicates = 0, 'no duplicate confirmation in one sweep');
      for I := 0 to 3 do
      begin
        Check(M.FCursor[I] = COWTestBases[I] + NativeUInt(96 * PAGE_BYTES), 'each large module gets work');
        Check(COWTestAll.ContainsKey(COWTestBases[I]), 'all original module slots reached');
      end;
      for J := 1 to 10 do
      begin
        Scan(UInt64(1000 + J * 6000), False, False);
        Check(COWTestWSCalls <= MAX_COW_PAGES_PER_SCAN, 'each scan respects page cap');
        Check(COWTestDuplicates = 0, 'no wrap/revisit within a sweep');
      end;
      Check(COWTestAll.Count = 4000, 'all 1000 pages of all four stable modules reached');
      for I := 0 to 3 do
        Check(COWTestAll.ContainsKey(COWTestBases[I] + NativeUInt(999 * PAGE_BYTES)), 'last page of large module sampled');
      Check(not (dkImageCOWIntegrity in D), 'coverage improvement alone is not detection');
      Setup(1, False); Scan(1000, True, False); COWTestMode := 1;
      Scan(7000, False, True);
      Check(M.FPending.TryGetValue(COWTestBases[0], Pending) and (Pending = 1), 'first shared-to-private observation');
      Check(not (dkImageCOWIntegrity in D), 'single COW observation insufficient');
      Scan(13000, False, False);
      Check(dkImageCOWIntegrity in D, 'two observations with recent code evidence');
      COWTestMode := 2; Scan(19000, False, True);
      Check(M.FPending.Count = 0, 'invalid residency breaks pending candidate');
      Check(not (dkImageCOWIntegrity in D), 'nonresident page is unknown');
      Setup(1, False); Scan(1000, True, False); COWTestMode := 1; Scan(7000, False, True);
      COWTestMode := 3; Scan(13000, False, False);
      Check(M.FPending.Count = 0, 'working-set API failure clears candidate');
      COWTestMode := 1; Scan(19000, False, True);
      Check(M.FPending.TryGetValue(COWTestBases[0], Pending) and (Pending = 1), 'recovery starts with one');
      Scan(25000, True, True);
      Check((M.FPending.Count = 0) and not (dkImageCOWIntegrity in D), 'baseline never accumulates a detection');
      Setup(1, False); COWTestMode := 1; Scan(1000, False, True); Scan(7000, False, True);
      Check(M.FPending.Count = 0, 'initially private page is not a shared-to-private transition');
      Setup(1, False); Scan(1000, True, False); COWTestMode := 1; Scan(7000, False, True);
      COWTestNonExec := True; Scan(13000, False, True);
      Check(M.FPending.Count = 0, 'nonexecutable region invalidates its pending pages');
      Setup(1, False); Scan(1000, True, False); COWTestMode := 1; Scan(7000, False, True);
      COWTestRegionFail := True; Scan(13000, False, False);
      Check(M.FPending.Count = 0, 'region failure breaks continuity');
      Check(M.FCursor[0] > COWTestBases[0], 'failed address does not pin cursor');
      Setup(1000, True); COWTestRegionMalformed := True; Scan(1000, False, False);
      Check((COWTestWSCalls = 0) and (COWTestRegionCalls <= 4), 'malformed region rejected without unbounded loop');
      Setup(8192, True); COWTestNonExec := True; Scan(1000, True, False);
      Check(COWTestRegionCalls = MAX_COW_REGION_QUERIES, 'nonexecuting metadata work bounded');
      Check(COWTestWSCalls = 0, 'nonexecuting pages not working-set sampled');
      Setup(10, False); COWTestBases[1] := COWTestBases[0]; Scan(1000, True, False);
      Check((COWTestDuplicates = 0) and (COWTestWSCalls = 10), 'duplicate module bases sampled once');
      Setup(1, False); Scan(1000, True, False); COWTestMode := 1; Scan(7000, False, True);
      Page := COWTestBases[0]; COWTestBases[0] := $50000000; Scan(13000, False, True);
      Check(not M.FShared.ContainsKey(Page) and (M.FPending.Count = 0), 'observed base change clears address history');
      Setup(1, False); Scan(1000, True, False); COWTestMode := 1; Scan(7000, False, True);
      Scan(100, False, False);
      Check(not (dkImageCOWIntegrity in D) and (M.FLastCodeChange = 0), 'clock rollback invalidates code correlation');
      Setup(1, False); Scan(1000, True, False); COWTestRaise := True; Raised := False;
      try Scan(7000, False, False); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FPending.Count = 0), 'query exception clears candidates');
      Setup(1, False); COWTestBases[0] := High(NativeUInt) - $1000; Scan(1000, False, False);
      Check(COWTestWSCalls = 0, 'overflowing module span rejected');
      Check(IsConfirmedCOW(True, False, 2, True), 'existing COW predicate maintained');
      Check(not IsConfirmedCOW(True, False, 2, False), 'independent code change still required');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; COWTestThisScan.Free; COWTestAll.Free;
    COWTestThisScan := nil; COWTestAll := nil;
    FQueryWS := SavedWS; FQueryResolved := SavedResolved;
    COWModuleHook := SavedModule; COWRegionHook := SavedRegion;
  end;
end;
