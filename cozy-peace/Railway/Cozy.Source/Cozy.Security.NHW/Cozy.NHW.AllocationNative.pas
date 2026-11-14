unit Cozy.NHW.AllocationNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils;

// Read-only virtual address metadata. The returned pointers describe addresses
// in a target process; they must never be dereferenced by this program.
const
  ALLOC_MEM_COMMIT  = $00001000;
  ALLOC_MEM_RESERVE = $00002000;
  ALLOC_MEM_FREE    = $00010000;
  ALLOC_MEM_PRIVATE = $00020000;
  ALLOC_MEM_MAPPED  = $00040000;
  ALLOC_MEM_IMAGE   = $01000000;
  ALLOC_PAGE_GUARD  = $00000100;
  ALLOC_PAGE_EXECUTE = $00000010;
  ALLOC_PAGE_EXECUTE_READ = $00000020;
  ALLOC_PAGE_EXECUTE_READWRITE = $00000040;
  ALLOC_PAGE_EXECUTE_WRITECOPY = $00000080;

type
  TVirtualRegion = record
    BaseAddress: NativeUInt;
    AllocationBase: NativeUInt;
    Size: NativeUInt;
    State: Cardinal;
    Protect: Cardinal;
    RegionType: Cardinal;
  end;

function AllocationNativeAvailable: Boolean;
function MaximumUserVirtualAddress: NativeUInt;
function QueryVirtualRegion(ProcessHandle: THandle;
  Address: NativeUInt; out Region: TVirtualRegion): Boolean;
function ConfirmFreeAddress(ProcessHandle: THandle;
  Address: NativeUInt): Boolean;
function RegionIsPrivate(const Region: TVirtualRegion): Boolean;
function RegionIsExecutable(const Region: TVirtualRegion): Boolean;
function RegionIsRWX(const Region: TVirtualRegion): Boolean;

implementation

uses Cozy.NHW.WinPointers, Cozy.NHW.NativeSafety;

type
  // x64 MEMORY_BASIC_INFORMATION (48 bytes).
  TMemoryBasicInformation64 = record
    BaseAddress: Pointer;
    AllocationBase: Pointer;
    AllocationProtect: Cardinal;
    PartitionId: Word;
    Reserved: Word;
    RegionSize: NativeUInt;
    State: Cardinal;
    Protect: Cardinal;
    RegionType: Cardinal;
    Reserved2: Cardinal;
  end;

  TNtQueryVirtualMemory = function(ProcessHandle: THandle;
    BaseAddress: Pointer; MemoryInformationClass: Cardinal;
    MemoryInformation: Pointer; MemoryInformationLength: NativeUInt;
    ReturnLength: PNativeUInt): LongInt; stdcall;
  TGetNativeSystemInfo = procedure(var Info: TSystemInfo); stdcall;

var
  QueryMemoryPtr: TNtQueryVirtualMemory = nil;
  SystemInfoPtr: TGetNativeSystemInfo = nil;
  Resolved: Boolean = False;
  UserMax: NativeUInt = 0;

function ResolveAllocationPointers: Boolean;
var
  ModNtdll, ModKernel: HMODULE;
begin
  Result := False;
  ModNtdll := WinModule('ntdll.dll');
  ModKernel := WinModule('kernel32.dll');
  if (ModNtdll = 0) or (ModKernel = 0) then Exit;
  QueryMemoryPtr := TNtQueryVirtualMemory(WinExport(ModNtdll, 'NtQueryVirtualMemory'));
  SystemInfoPtr := TGetNativeSystemInfo(WinExport(ModKernel, 'GetNativeSystemInfo'));
  Result := Assigned(QueryMemoryPtr) and Assigned(SystemInfoPtr);
end;

procedure CaptureMaximumUserAddress;
var Info: TSystemInfo;
begin
  Info := Default(TSystemInfo);
  SystemInfoPtr(Info);
  UserMax := NativeUInt(Info.lpMaximumApplicationAddress);
  if (UserMax < $100000) or (UserMax > $00007FFFFFFFFFFF) then UserMax := 0;
end;

procedure ResolveAllocationNative;
begin
  if Resolved then Exit;
  Resolved := True;
  if SizeOf(TMemoryBasicInformation64) <> 48 then Exit;
  if not ResolveAllocationPointers then Exit;
  CaptureMaximumUserAddress;
end;

function AllocationNativeAvailable: Boolean;
begin
  ResolveAllocationNative;
  Result := Assigned(QueryMemoryPtr) and (UserMax <> 0);
end;

function MaximumUserVirtualAddress: NativeUInt;
begin
  ResolveAllocationNative;
  Result := UserMax;
end;

function QueryMemoryBasic(ProcessHandle: THandle; Address: NativeUInt;
  out Basic: TMemoryBasicInformation64): Boolean;
var Returned: NativeUInt;
begin
  Result := False;
  Basic := Default(TMemoryBasicInformation64);
  Returned := 0;
  if QueryMemoryPtr(ProcessHandle, Pointer(Address), 0, @Basic,
     SizeOf(Basic), @Returned) < 0 then Exit;
  if (Returned <> 0) and (Returned < SizeOf(Basic)) then Exit;
  Result := True;
end;

function BasicContainsAddress(const Basic: TMemoryBasicInformation64;
  Address: NativeUInt): Boolean;
begin
  Result := NHWContainedSpan(NativeUInt(Basic.BaseAddress), Basic.RegionSize,
    Address, 1);
end;

procedure PublishVirtualRegion(const Basic: TMemoryBasicInformation64;
  out Region: TVirtualRegion);
begin
  Region.BaseAddress := NativeUInt(Basic.BaseAddress);
  Region.AllocationBase := NativeUInt(Basic.AllocationBase);
  Region.Size := Basic.RegionSize;
  Region.State := Basic.State;
  Region.Protect := Basic.Protect;
  Region.RegionType := Basic.RegionType;
end;

function QueryVirtualRegion(ProcessHandle: THandle;
  Address: NativeUInt; out Region: TVirtualRegion): Boolean;
var Basic: TMemoryBasicInformation64;
begin
  Result := False;
  Region := Default(TVirtualRegion);
  ResolveAllocationNative;
  if not Assigned(QueryMemoryPtr) or (ProcessHandle = 0) or
     (Address < $10000) or (Address > UserMax) then Exit;
  if not QueryMemoryBasic(ProcessHandle, Address, Basic) then Exit;
  if not BasicContainsAddress(Basic, Address) then Exit;
  PublishVirtualRegion(Basic, Region);
  Result := True;
end;

function ConfirmFreeAddress(ProcessHandle: THandle;
  Address: NativeUInt): Boolean;
var
  Region: TVirtualRegion;
begin
  Result := QueryVirtualRegion(ProcessHandle, Address, Region) and
    (Region.State = ALLOC_MEM_FREE);
end;

function RegionIsPrivate(const Region: TVirtualRegion): Boolean;
begin
  Result := (Region.State = ALLOC_MEM_COMMIT) and
    (Region.RegionType = ALLOC_MEM_PRIVATE) or
    ((Region.State = ALLOC_MEM_RESERVE) and
     ((Region.RegionType = 0) or (Region.RegionType = ALLOC_MEM_PRIVATE)));
end;

function RegionIsExecutable(const Region: TVirtualRegion): Boolean;
begin
  Result := False;
  if (Region.State <> ALLOC_MEM_COMMIT) or
     ((Region.Protect and ALLOC_PAGE_GUARD) <> 0) then Exit;
  case Region.Protect and $FF of
    ALLOC_PAGE_EXECUTE, ALLOC_PAGE_EXECUTE_READ,
    ALLOC_PAGE_EXECUTE_READWRITE, ALLOC_PAGE_EXECUTE_WRITECOPY:
      Result := True;
  end;
end;

function RegionIsRWX(const Region: TVirtualRegion): Boolean;
begin
  Result := (Region.State = ALLOC_MEM_COMMIT) and
    ((Region.Protect and ALLOC_PAGE_GUARD) = 0) and
    ((Region.Protect and $FF) = ALLOC_PAGE_EXECUTE_READWRITE);
end;

end.
