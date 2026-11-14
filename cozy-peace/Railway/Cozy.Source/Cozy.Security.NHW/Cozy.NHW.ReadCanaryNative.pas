unit Cozy.NHW.ReadCanaryNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.AllocationNative;

// Only this process's single purpose-made private page is modified.
// Kernel object pointers or addresses in other processes are NEVER
// dereferenced. No ReadProcessMemory, hooks, drivers, or page scanning.
// Ownership: initialize Page to nil before the FIRST call. A non-nil
// allocation is never overwritten, including after a failed release.
function CreateReadCanary(var Page: Pointer): Boolean;
function QueryReadCanary(Page: Pointer; out Guarded: Boolean): Boolean;
function ArmReadCanary(Page: Pointer): Boolean;
procedure ReleaseReadCanary(var Page: Pointer);
{$IFDEF NHW_NATIVE5D_TESTS}
function TestReadCanaryHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, System.SyncObjs, Cozy.NHW.WinPointers;

const
  CANARY_PAGE_SIZE = 4096;
  CANARY_MEM_COMMIT = $00001000;
  CANARY_MEM_RESERVE = $00002000;
  CANARY_MEM_RELEASE = $00008000;
  CANARY_PAGE_READWRITE = $00000004;
  CANARY_PAGE_READONLY = $00000002;
  CANARY_PAGE_GUARD = $00000100;

type
  TNtAllocateVirtualMemoryPtr = function(ProcessHandle: THandle;
    var BaseAddress: Pointer; ZeroBits: NativeUInt;
    var RegionSize: NativeUInt; AllocationType: Cardinal;
    Protect: Cardinal): LongInt; stdcall;
  TNtProtectVirtualMemoryPtr = function(ProcessHandle: THandle;
    var BaseAddress: Pointer; var RegionSize: NativeUInt;
    NewProtect: Cardinal; var OldProtect: Cardinal): LongInt; stdcall;
  TNtFreeVirtualMemoryPtr = function(ProcessHandle: THandle;
    var BaseAddress: Pointer; var RegionSize: NativeUInt;
    FreeType: Cardinal): LongInt; stdcall;

var
  ResolveLock: TCriticalSection;
  Resolved: Boolean = False;
  AllocatePtr: TNtAllocateVirtualMemoryPtr = nil;
  ProtectPtr: TNtProtectVirtualMemoryPtr = nil;
  FreePtr: TNtFreeVirtualMemoryPtr = nil;

procedure ResolveCanaryNative;
var
  Ntdll: HMODULE;
  A: TNtAllocateVirtualMemoryPtr;
  P: TNtProtectVirtualMemoryPtr;
  F: TNtFreeVirtualMemoryPtr;
begin
  // Always take the lock: no unsynchronized Boolean publication/read.
  ResolveLock.Acquire;
  try
    if Resolved then Exit;
    Ntdll := WinModule('ntdll.dll');
    if Ntdll = 0 then Exit;
    A := TNtAllocateVirtualMemoryPtr(WinExport(Ntdll, 'NtAllocateVirtualMemory'));
    P := TNtProtectVirtualMemoryPtr(WinExport(Ntdll, 'NtProtectVirtualMemory'));
    F := TNtFreeVirtualMemoryPtr(WinExport(Ntdll, 'NtFreeVirtualMemory'));
    if not Assigned(A) or not Assigned(P) or not Assigned(F) then Exit;
    AllocatePtr := A;
    ProtectPtr := P;
    FreePtr := F;
    Resolved := True;
  finally
    ResolveLock.Release;
  end;
end;

function CanaryAddressValid(Page: Pointer): Boolean;
var Address: NativeUInt;
begin
  Address := NativeUInt(Page);
  Result := (Address >= $10000) and
    (Address <= High(NativeUInt) - CANARY_PAGE_SIZE);
end;

function ProtectCanary(Page: Pointer; NewProtect: Cardinal): Boolean;
var
  Address: Pointer;
  Size: NativeUInt;
  Previous: Cardinal;
begin
  Result := False;
  if not CanaryAddressValid(Page) then Exit;
  ResolveCanaryNative;
  if not Assigned(ProtectPtr) then Exit;
  Address := Page;
  Size := CANARY_PAGE_SIZE;
  Previous := 0;
  Result := ProtectPtr(WinCurrentProcess, Address, Size,
    NewProtect, Previous) >= 0;
end;

procedure InitializeCanaryContents(Page: Pointer);
var
  InitBytes: array[0..31] of Byte;
  I: Integer;
begin
  for I := Low(InitBytes) to High(InitBytes) do
    InitBytes[I] := Byte((I * 29 + 83) and $FF);
  Move(InitBytes[0], PByte(Page)^, SizeOf(InitBytes));
end;

function CanaryRegionValid(Page: Pointer; const Region: TVirtualRegion): Boolean;
var
  Address, Offset: NativeUInt;
begin
  Result := False;
  Address := NativeUInt(Page);
  if not CanaryAddressValid(Page) then Exit;
  if (Region.State <> ALLOC_MEM_COMMIT) or
     (Region.RegionType <> ALLOC_MEM_PRIVATE) or
     (Region.AllocationBase <> Address) or
     (Region.BaseAddress > Address) then Exit;
  Offset := Address - Region.BaseAddress;
  if Offset >= Region.Size then Exit;
  Result := CANARY_PAGE_SIZE <= Region.Size - Offset;
end;

procedure ReleaseReadCanary(var Page: Pointer);
var
  Address: Pointer;
  Size: NativeUInt;
begin
  if Page = nil then Exit;
  ResolveCanaryNative;
  if not Assigned(FreePtr) then Exit;
  Address := Page;
  Size := 0; // MEM_RELEASE requires zero size and the allocation base.
  // The native function may change its in/out arguments even on failure.
  // Keep the caller's original owner until success has been established.
  if FreePtr(WinCurrentProcess, Address, Size, CANARY_MEM_RELEASE) >= 0 then
    Page := nil;
end;

function ArmReadCanary(Page: Pointer): Boolean;
begin
  Result := ProtectCanary(Page,
    CANARY_PAGE_READONLY or CANARY_PAGE_GUARD);
end;

function CreateReadCanary(var Page: Pointer): Boolean;
var
  Address: Pointer;
  Size: NativeUInt;
begin
  Result := False;
  // A failed previous release must not silently lose its allocation owner.
  if Page <> nil then Exit;
  ResolveCanaryNative;
  if not Assigned(AllocatePtr) or not Assigned(ProtectPtr) or
     not Assigned(FreePtr) then Exit;
  Address := nil;
  Size := CANARY_PAGE_SIZE;
  if AllocatePtr(WinCurrentProcess, Address, 0, Size,
    CANARY_MEM_RESERVE or CANARY_MEM_COMMIT,
    CANARY_PAGE_READWRITE) < 0 then Exit;
  if Address = nil then Exit;
  Page := Address;
  try
    if (Size < CANARY_PAGE_SIZE) or not CanaryAddressValid(Page) then Exit;
    // Initialize BEFORE applying PAGE_GUARD. Later never dereference.
    InitializeCanaryContents(Page);
    Result := ArmReadCanary(Page);
  finally
    // On failure Page remains non-nil if cleanup itself fails. The owner
    // may retry ReleaseReadCanary; never overwrite the outstanding page.
    if not Result then ReleaseReadCanary(Page);
  end;
end;

function QueryReadCanary(Page: Pointer; out Guarded: Boolean): Boolean;
var
  Region: TVirtualRegion;
begin
  Result := False;
  Guarded := False;
  if not CanaryAddressValid(Page) then Exit;
  if not QueryVirtualRegion(WinCurrentProcess, NativeUInt(Page), Region) then Exit;
  if not CanaryRegionValid(Page, Region) then Exit;
  Guarded := (Region.Protect and CANARY_PAGE_GUARD) <> 0;
  Result := True;
end;

{$IFDEF NHW_NATIVE5D_TESTS}
{$I Cozy.NHW.Native5D.ReadCanary.inc}
{$ENDIF}

initialization
  ResolveLock := TCriticalSection.Create;
finalization
  ResolveLock.Free;
end.
