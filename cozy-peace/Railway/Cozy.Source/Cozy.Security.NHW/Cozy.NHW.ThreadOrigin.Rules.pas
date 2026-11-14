unit Cozy.NHW.ThreadOrigin.Rules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Internal read-only decoding layer; callers retain collection/handle ownership.
uses
  Winapi.Windows, System.SysUtils, Cozy.NHW.NativeSafety;

const
  NT_MEM_COMMIT = $00001000;
  NT_MEM_RESERVE = $00002000;
  NT_MEM_FREE = $00010000;
  NT_MEM_PRIVATE = $00020000;
  NT_MEM_MAPPED = $00040000;
  NT_MEM_IMAGE = $01000000;
  NT_PAGE_GUARD = $00000100;
  NT_PAGE_NOACCESS = $00000001;
  NT_PAGE_EXECUTE = $00000010;
  NT_PAGE_EXECUTE_READ = $00000020;
  NT_PAGE_EXECUTE_READWRITE = $00000040;
  NT_PAGE_EXECUTE_WRITECOPY = $00000080;


type
  TThreadOriginRegion = record
    Known: Boolean;
    StartAddress: NativeUInt;
    BaseAddress: NativeUInt;
    AllocationBase: NativeUInt;
    RegionSize: NativeUInt;
    State: Cardinal;
    Protect: Cardinal;
    RegionType: Cardinal;
  end;

  // Windows 64-bit MEMORY_BASIC_INFORMATION layout: 48 bytes.
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


function UserAddressCandidate(Address: NativeUInt): Boolean; inline;
function StartResultValid(Status: LongInt; Address: NativeUInt; Returned: Cardinal): Boolean;
function NormalizeStartRegion(Status: LongInt; StartAddress: NativeUInt;
  const Basic: TMemoryBasicInformation64; Returned: NativeUInt;
  out Region: TThreadOriginRegion): Boolean;
function IsExecutableProtection(Protect: Cardinal): Boolean;
function IsNonImageExecutableStart(const Region: TThreadOriginRegion): Boolean;
function IsPrivateExecutableStart(const Region: TThreadOriginRegion): Boolean;
function IsThreadRegionChanged(const Before, After: TThreadOriginRegion): Boolean;

implementation

function UserAddressCandidate(Address: NativeUInt): Boolean; inline;
begin
  // Numeric bounds are not a promise that an address is readable/executable.
  Result := (Address >= $10000) and (Address <= NativeUInt(High(NativeInt)));
end;

function StartResultValid(Status: LongInt; Address: NativeUInt; Returned: Cardinal): Boolean;
begin
  // Preserve the existing zero-ReturnLength compatibility case. A nonzero
  // count must describe exactly the pointer written into our fixed buffer.
  Result := (Status = 0) and UserAddressCandidate(Address) and
    ((Returned = 0) or (Returned = Cardinal(SizeOf(Pointer))));
end;

function NormalizeStartRegion(Status: LongInt; StartAddress: NativeUInt;
  const Basic: TMemoryBasicInformation64; Returned: NativeUInt;
  out Region: TThreadOriginRegion): Boolean;
var
  Base, Allocation: NativeUInt;
begin
  Result := False;
  Region := Default(TThreadOriginRegion);
  if (Status <> 0) or not UserAddressCandidate(StartAddress) or
     (SizeOf(Basic) <> 48) then Exit;
  if (Returned <> 0) and (Returned <> NativeUInt(SizeOf(Basic))) then Exit;
  Base := NativeUInt(Basic.BaseAddress);
  if not UserAddressCandidate(Base) or
     not NHWAddressSpan(Base, Basic.RegionSize) then Exit;
  if Basic.RegionSize - 1 > NativeUInt(High(NativeInt)) - Base then Exit;
  if (StartAddress < Base) or ((StartAddress - Base) >= Basic.RegionSize) then Exit;
  case Basic.State of
    NT_MEM_COMMIT, NT_MEM_RESERVE, NT_MEM_FREE: ;
  else
    Exit;
  end;
  Allocation := 0;
  if Basic.State <> NT_MEM_FREE then
  begin
    Allocation := NativeUInt(Basic.AllocationBase);
    if not UserAddressCandidate(Allocation) or (Allocation > Base) then Exit;
    case Basic.RegionType of
      NT_MEM_IMAGE, NT_MEM_MAPPED, NT_MEM_PRIVATE: ;
    else
      Exit;
    end;
  end;
  Region.StartAddress := StartAddress;
  Region.BaseAddress := Base;
  Region.RegionSize := Basic.RegionSize;
  Region.State := Basic.State;
  // MEM_FREE: allocation/protection/type are undefined. MEM_RESERVE:
  // protection is undefined. Normalize them so garbage is not a transition.
  if Basic.State <> NT_MEM_FREE then
  begin
    Region.AllocationBase := Allocation;
    Region.RegionType := Basic.RegionType;
    if Basic.State = NT_MEM_COMMIT then Region.Protect := Basic.Protect;
  end;
  Region.Known := True;
  Result := True;
end;

function IsExecutableProtection(Protect: Cardinal): Boolean;
begin
  if (Protect and NT_PAGE_GUARD) <> 0 then Exit(False);
  if (Protect and $FF) = NT_PAGE_NOACCESS then Exit(False);
  case Protect and $FF of
    NT_PAGE_EXECUTE, NT_PAGE_EXECUTE_READ,
    NT_PAGE_EXECUTE_READWRITE, NT_PAGE_EXECUTE_WRITECOPY: Result := True;
  else
    Result := False;
  end;
end;

function IsNonImageExecutableStart(const Region: TThreadOriginRegion): Boolean;
begin
  Result := Region.Known and (Region.State = NT_MEM_COMMIT) and
    IsExecutableProtection(Region.Protect) and
    ((Region.RegionType = NT_MEM_PRIVATE) or (Region.RegionType = NT_MEM_MAPPED));
end;

function IsPrivateExecutableStart(const Region: TThreadOriginRegion): Boolean;
begin
  Result := IsNonImageExecutableStart(Region) and (Region.RegionType = NT_MEM_PRIVATE);
end;

function IsThreadRegionChanged(const Before, After: TThreadOriginRegion): Boolean;
begin
  Result := False;
  if not Before.Known or not After.Known or
     (Before.StartAddress <> After.StartAddress) then Exit;
  if Before.State <> After.State then Exit(True);
  if Before.State = NT_MEM_FREE then Exit;
  if Before.RegionType <> After.RegionType then Exit(True);
  if Before.State = NT_MEM_COMMIT then
    Result := Before.Protect <> After.Protect;
  // Preserve the existing comparison scope; no new detector is introduced.
end;

end.
