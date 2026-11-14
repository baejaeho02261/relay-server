unit Cozy.NHW.ThreadOriginNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.ThreadOrigin.Rules;

// Only queries metadata for a *single* thread start address.  These pointers
// are remote virtual addresses passed to Windows, not directly dereferenced.
// No ReadProcessMemory, Move(remote...), VirtualProtect or thread modification.
type
  TThreadOriginRegion = Cozy.NHW.ThreadOrigin.Rules.TThreadOriginRegion;

function ThreadOriginNativeAvailable: Boolean;
function QueryWin32ThreadStart(ThreadHandle: THandle;
  out StartAddress: NativeUInt): Boolean;
function QueryThreadStartRegion(ProcessHandle: THandle;
  StartAddress: NativeUInt; out Region: TThreadOriginRegion): Boolean;
function IsExecutableProtection(Protect: Cardinal): Boolean;
function IsNonImageExecutableStart(const Region: TThreadOriginRegion): Boolean;
function IsPrivateExecutableStart(const Region: TThreadOriginRegion): Boolean;
function IsThreadRegionChanged(const Before, After: TThreadOriginRegion): Boolean;

{$IFDEF NHW_HARDENING_TESTS}
function TestThreadOriginHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.WinPointers,
  Cozy.NHW.NativeSafety;

const
  THREAD_QUERY_SET_WIN32_START_ADDRESS = 9;
  MEMORY_BASIC_INFORMATION_CLASS = 0;

type
  TMemoryBasicInformation64 = Cozy.NHW.ThreadOrigin.Rules.TMemoryBasicInformation64;

  TNtQueryInformationThread = function(ThreadHandle: THandle;
    ThreadInformationClass: Cardinal; ThreadInformation: Pointer;
    ThreadInformationLength: Cardinal; ReturnLength: PCardinal): LongInt; stdcall;
  TNtQueryVirtualMemory = function(ProcessHandle: THandle; BaseAddress: Pointer;
    MemoryInformationClass: Cardinal; MemoryInformation: Pointer;
    MemoryInformationLength: NativeUInt; ReturnLength: PNativeUInt): LongInt; stdcall;

var
  ResolveLock: TCriticalSection;
  Resolved: Boolean = False;
  QueryThreadPtr: TNtQueryInformationThread = nil;
  QueryMemoryPtr: TNtQueryVirtualMemory = nil;

procedure ResolveNativeThreadOrigin;
var
  M: HMODULE;
begin
  ResolveLock.Acquire;
  try
    if Resolved then Exit;
    M := WinModule('ntdll.dll');
    if M = 0 then Exit; // bootstrap may not have completed; allow a later retry
    QueryThreadPtr := TNtQueryInformationThread(WinExport(M, 'NtQueryInformationThread'));
    QueryMemoryPtr := TNtQueryVirtualMemory(WinExport(M, 'NtQueryVirtualMemory'));
    Resolved := True; // publish immutable pointers only after both assignments
  finally
    ResolveLock.Release;
  end;
end;

function ThreadOriginNativeAvailable: Boolean;
begin
  ResolveNativeThreadOrigin;
  Result := Assigned(QueryThreadPtr) and Assigned(QueryMemoryPtr) and
    (SizeOf(TMemoryBasicInformation64) = 48) and (SizeOf(Pointer) = 8);
end;

function QueryWin32ThreadStart(ThreadHandle: THandle;
  out StartAddress: NativeUInt): Boolean;
var
  Address: Pointer;
  Needed: Cardinal;
  Status: LongInt;
begin
  Result := False;
  StartAddress := 0;
  if ThreadHandle = 0 then Exit;
  ResolveNativeThreadOrigin;
  if not Assigned(QueryThreadPtr) then Exit;
  Address := nil;
  Needed := 0;
  Status := QueryThreadPtr(ThreadHandle, THREAD_QUERY_SET_WIN32_START_ADDRESS,
    @Address, SizeOf(Address), @Needed);
  if not StartResultValid(Status, NativeUInt(Address), Needed) then Exit;
  StartAddress := NativeUInt(Address);
  Result := True;
end;

function QueryThreadStartRegion(ProcessHandle: THandle;
  StartAddress: NativeUInt; out Region: TThreadOriginRegion): Boolean;
var
  Basic: TMemoryBasicInformation64;
  Returned: NativeUInt;
  Status: LongInt;
begin
  Region := Default(TThreadOriginRegion);
  Result := False;
  if (ProcessHandle = 0) or not UserAddressCandidate(StartAddress) then Exit;
  ResolveNativeThreadOrigin;
  if not Assigned(QueryMemoryPtr) or (SizeOf(Basic) <> 48) then Exit;
  Basic := Default(TMemoryBasicInformation64);
  Returned := 0;
  Status := QueryMemoryPtr(ProcessHandle, Pointer(StartAddress),
    MEMORY_BASIC_INFORMATION_CLASS, @Basic, SizeOf(Basic), @Returned);
  Result := NormalizeStartRegion(Status, StartAddress, Basic, Returned, Region);
end;

function IsExecutableProtection(Protect: Cardinal): Boolean;
begin
  Result := Cozy.NHW.ThreadOrigin.Rules.IsExecutableProtection(Protect);
end;

function IsNonImageExecutableStart(const Region: TThreadOriginRegion): Boolean;
begin
  Result := Cozy.NHW.ThreadOrigin.Rules.IsNonImageExecutableStart(Region);
end;

function IsPrivateExecutableStart(const Region: TThreadOriginRegion): Boolean;
begin
  Result := Cozy.NHW.ThreadOrigin.Rules.IsPrivateExecutableStart(Region);
end;

function IsThreadRegionChanged(const Before, After: TThreadOriginRegion): Boolean;
begin
  Result := Cozy.NHW.ThreadOrigin.Rules.IsThreadRegionChanged(Before, After);
end;

{$IFDEF NHW_HARDENING_TESTS}
function TestThreadOriginHardening(out Failure: string; out Checks: Integer): Boolean;
var
  B: TMemoryBasicInformation64;
  R, Other: TThreadOriginRegion;

  procedure Check(Condition: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Text);
  end;

  procedure Fixture;
  begin
    B := Default(TMemoryBasicInformation64);
    B.BaseAddress := Pointer($100000);
    B.AllocationBase := Pointer($100000);
    B.RegionSize := $1000;
    B.State := NT_MEM_COMMIT;
    B.Protect := NT_PAGE_EXECUTE_READ;
    B.RegionType := NT_MEM_PRIVATE;
  end;

  function Normalize: Boolean;
  begin
    Result := NormalizeStartRegion(0, $100010, B, SizeOf(B), R);
  end;

begin
  Result := False; Failure := ''; Checks := 0;
  try
    Check(StartResultValid(0, $100000, 8), 'valid pointer response');
    Check(StartResultValid(0, $100000, 0), 'zero return-length compatibility');
    Check(not StartResultValid($103, $100000, 8), 'pending is not a completed query');
    Check(not StartResultValid(0, $100000, 4), 'partial pointer response');
    Check(not StartResultValid(0, High(NativeUInt), 8), 'kernel/sentinel address rejected');
    Fixture;
    Check(Normalize and IsPrivateExecutableStart(R), 'valid committed executable region');
    B.RegionSize := 0;
    Check(not Normalize and not R.Known, 'zero region size rejected/cleared');
    Fixture; B.RegionSize := High(NativeUInt);
    Check(not Normalize, 'overflow region rejected');
    Fixture; B.AllocationBase := Pointer($200000);
    Check(not Normalize, 'allocation cannot begin after the region');
    Fixture;
    Check(not NormalizeStartRegion(0, $101000, B, SizeOf(B), R), 'exclusive end outside region');
    Check(not NormalizeStartRegion(0, $100010, B, 49, R), 'oversized returned length');
    Check(not NormalizeStartRegion(-1, $100010, B, SizeOf(B), R) and
      not R.Known and (R.StartAddress = 0), 'failed query clears old result');
    B.State := NT_MEM_FREE; B.RegionType := High(Cardinal); B.Protect := High(Cardinal);
    B.AllocationBase := Pointer(High(NativeUInt));
    Check(Normalize and (R.RegionType = 0) and (R.Protect = 0) and
      (R.AllocationBase = 0), 'undefined MEM_FREE fields normalized');
    Other := R; Other.Protect := NT_PAGE_EXECUTE_READ;
    Check(not IsThreadRegionChanged(R, Other), 'free protection is not a change');
    Fixture; B.State := NT_MEM_RESERVE; B.Protect := High(Cardinal);
    Check(Normalize and (R.Protect = 0), 'undefined reserve protection normalized');
    Other := R; Other.Protect := NT_PAGE_EXECUTE_READ;
    Check(not IsThreadRegionChanged(R, Other), 'reserve protection is not a change');
    Fixture; B.RegionType := 0;
    Check(not Normalize, 'unrecognized committed mapping is unknown');
    Fixture; B.Protect := NT_PAGE_EXECUTE_READ or NT_PAGE_GUARD;
    Check(Normalize and not IsPrivateExecutableStart(R), 'guard page not executable evidence');
    Result := True;
  except
    on E: Exception do Failure := E.Message;
  end;
end;
{$ENDIF}

initialization
  ResolveLock := TCriticalSection.Create;

finalization
  ResolveLock.Free;

end.
