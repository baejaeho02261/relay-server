// Compiled only in the isolated NHW_NATIVE5D_TESTS project.
var
  CanaryTestBuffer: array[0..4095] of Byte;
  CanaryAllocStatus, CanaryProtectStatus, CanaryFreeStatus: LongInt;
  CanaryAllocCalls, CanaryProtectCalls, CanaryFreeCalls: Integer;
  CanaryReturnedSize: NativeUInt;
  CanaryFreeSize: NativeUInt;
  CanaryFreeFlags: Cardinal;

function CanaryTestAllocate(ProcessHandle: THandle;
  var BaseAddress: Pointer; ZeroBits: NativeUInt; var RegionSize: NativeUInt;
  AllocationType, Protect: Cardinal): LongInt; stdcall;
begin
  Inc(CanaryAllocCalls);
  BaseAddress := @CanaryTestBuffer[0];
  RegionSize := CanaryReturnedSize;
  Result := CanaryAllocStatus;
end;
function CanaryTestProtect(ProcessHandle: THandle; var BaseAddress: Pointer;
  var RegionSize: NativeUInt; NewProtect: Cardinal;
  var OldProtect: Cardinal): LongInt; stdcall;
begin
  Inc(CanaryProtectCalls);
  OldProtect := CANARY_PAGE_READWRITE;
  Result := CanaryProtectStatus;
end;
function CanaryTestFree(ProcessHandle: THandle; var BaseAddress: Pointer;
  var RegionSize: NativeUInt; FreeType: Cardinal): LongInt; stdcall;
begin
  Inc(CanaryFreeCalls);
  CanaryFreeSize := RegionSize;
  CanaryFreeFlags := FreeType;
  BaseAddress := nil; // Even a failed API may modify its local in/out slot.
  RegionSize := 123;
  Result := CanaryFreeStatus;
end;
function TestReadCanaryHardening(out Failure: string; out Checks: Integer): Boolean;
var
  A: TNtAllocateVirtualMemoryPtr; P: TNtProtectVirtualMemoryPtr;
  F: TNtFreeVirtualMemoryPtr; SavedResolved: Boolean;
  Page, Owner: Pointer; Guarded: Boolean; Calls: Integer;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
begin
  Result := False; Failure := ''; Checks := 0;
  A := AllocatePtr; P := ProtectPtr; F := FreePtr; SavedResolved := Resolved;
  try
    try
      Resolved := True; AllocatePtr := CanaryTestAllocate;
      ProtectPtr := CanaryTestProtect; FreePtr := CanaryTestFree;
      CanaryAllocStatus := 0; CanaryProtectStatus := 0; CanaryFreeStatus := 0;
      CanaryAllocCalls := 0; CanaryProtectCalls := 0; CanaryFreeCalls := 0;
      CanaryReturnedSize := CANARY_PAGE_SIZE;
      Owner := @CanaryTestBuffer[0];
      Page := nil;
      ReleaseReadCanary(Page);
      Check(CanaryFreeCalls = 0, 'nil release makes no call');
      Page := Owner;
      Check(not CreateReadCanary(Page), 'live owner not overwritten');
      Check((Page = Owner) and (CanaryAllocCalls = 0), 'live owner retained');
      CanaryFreeStatus := -1;
      ReleaseReadCanary(Page);
      Check(Page = Owner, 'failed release retains original pointer');
      Check(CanaryFreeSize = 0, 'release size zero');
      Check(CanaryFreeFlags = CANARY_MEM_RELEASE, 'release flag preserved');
      FreePtr := nil;
      Calls := CanaryFreeCalls;
      ReleaseReadCanary(Page);
      Check((Page = Owner) and (Calls = CanaryFreeCalls), 'missing free keeps owner');
      FreePtr := CanaryTestFree;
      CanaryFreeStatus := 0;
      ReleaseReadCanary(Page);
      Check(Page = nil, 'successful release clears owner');
      Calls := CanaryFreeCalls;
      ReleaseReadCanary(Page);
      Check(CanaryFreeCalls = Calls, 'no double free after success');
      CanaryAllocStatus := -1;
      Check(not CreateReadCanary(Page), 'allocation failure rejected');
      Check(Page = nil, 'failed allocation does not adopt undefined output');
      CanaryAllocStatus := 0; CanaryProtectStatus := -1;
      Check(not CreateReadCanary(Page), 'arm failure rejected');
      Check(Page = nil, 'failed arm cleanup successful');
      CanaryFreeStatus := -1;
      Check(not CreateReadCanary(Page), 'arm failure and cleanup failure');
      Check(Page = Owner, 'failed cleanup retains allocated owner');
      Calls := CanaryAllocCalls;
      Check(not CreateReadCanary(Page), 'retry cannot overwrite leaked owner');
      Check(CanaryAllocCalls = Calls, 'no second allocation over retained owner');
      CanaryFreeStatus := 0; ReleaseReadCanary(Page);
      CanaryProtectStatus := 0; CanaryReturnedSize := 16;
      Check(not CreateReadCanary(Page), 'short allocation response rejected');
      Check(Page = nil, 'short allocation cleaned up');
      CanaryReturnedSize := CANARY_PAGE_SIZE;
      Check(CreateReadCanary(Page), 'complete successful creation');
      Check(Page = Owner, 'successful owner returned');
      Check(CanaryTestBuffer[0] = 83, 'initial data written before arm');
      Check(CanaryTestBuffer[1] = 112, 'initial pattern preserved');
      ReleaseReadCanary(Page);
      Calls := CanaryProtectCalls;
      Check(not ArmReadCanary(nil), 'nil arm rejected');
      Check(not ArmReadCanary(Pointer(High(NativeUInt) - 1)), 'overflow arm rejected');
      Check(CanaryProtectCalls = Calls, 'bad arm makes no native call');
      Guarded := True;
      Check(not QueryReadCanary(nil, Guarded), 'nil canary unavailable');
      Check(not Guarded, 'failed query clears guarded output');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    AllocatePtr := A; ProtectPtr := P; FreePtr := F; Resolved := SavedResolved;
  end;
end;
