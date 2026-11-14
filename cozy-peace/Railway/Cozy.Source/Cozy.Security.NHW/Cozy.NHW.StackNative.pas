unit Cozy.NHW.StackNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils;

type
  // Known stack metadata only. Never scan the contents of stack memory.
  TNativeStackSnapshot = record
    Known: Boolean;
    BoundsValid: Boolean;
    CreateTime: UInt64;
    StackBase: NativeUInt;
    StackLimit: NativeUInt;
    AllocationBase: NativeUInt;
    ReservedBytes: UInt64;
    CommittedBytes: UInt64;
    HasGuard: Boolean;
    HasExecutablePage: Boolean;
  end;

function StackNativeAvailable: Boolean;
function QueryNativeThreadStack(ProcessHandle, ThreadHandle: THandle;
  out Snapshot: TNativeStackSnapshot): Boolean;

{$IFDEF NHW_NATIVE5B_TESTS}
function TestStackNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SyncObjs, Cozy.NHW.WinPointers;

const
  THREAD_BASIC_INFORMATION_CLASS = 0;
  MEMORY_BASIC_INFORMATION_CLASS = 0;
  PAGE_GUARD_BIT = $00000100;
  PAGE_EXECUTE = $00000010;
  PAGE_EXECUTE_READ = $00000020;
  PAGE_EXECUTE_READWRITE = $00000040;
  PAGE_EXECUTE_WRITECOPY = $00000080;
  MEM_COMMIT_VALUE = $1000;
  MEM_RESERVE_VALUE = $2000;
  MEM_FREE_VALUE = $10000;
  THREAD_STILL_ACTIVE = $103;
  MAX_STACK_RESERVE_BYTES = UInt64(256) * 1024 * 1024;
  MAX_STACK_MEMORY_REGIONS = 64;

type
  // Windows x64 native THREAD_BASIC_INFORMATION layout = 48 bytes.
  TThreadBasicX64 = record
    ExitStatus: LongInt;
    Alignment: Cardinal;
    TebBaseAddress: Pointer;
    ClientProcessID: THandle;
    ClientThreadID: THandle;
    AffinityMask: NativeUInt;
    Priority: LongInt;
    BasePriority: LongInt;
  end;

  // Beginning of NT_TIB within x64 TEB = 7 native pointers, 56 bytes.
  TNTTibHead = record
    ExceptionList: Pointer;
    StackBase: Pointer;
    StackLimit: Pointer;
    SubSystemTib: Pointer;
    FiberData: Pointer;
    ArbitraryUserPointer: Pointer;
    SelfPtr: Pointer;
  end;

  // x64 MEMORY_BASIC_INFORMATION = 48 bytes, as used in v20.
  TMemoryBasicX64 = record
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

  TProcessIDFn = function(ProcessHandle: THandle): Cardinal; stdcall;
  TNtQueryInformationThread = function(ThreadHandle: THandle;
    InfoClass: Cardinal; Buffer: Pointer; BufferLength: Cardinal;
    Returned: PCardinal): LongInt; stdcall;
  TNtQueryVirtualMemory = function(ProcessHandle: THandle;
    Address: Pointer; InfoClass: Cardinal; Buffer: Pointer;
    BufferLength: NativeUInt; Returned: PNativeUInt): LongInt; stdcall;
  TNtReadVirtualMemory = function(ProcessHandle: THandle;
    Address: Pointer; Buffer: Pointer; BufferLength: NativeUInt;
    BytesRead: PNativeUInt): LongInt; stdcall;

var
  StackResolveLock: TCriticalSection;
  StackResolved: Integer = 0;
  ProcessIDPtr: TProcessIDFn = nil;
  QueryThreadPtr: TNtQueryInformationThread = nil;
  QueryMemoryPtr: TNtQueryVirtualMemory = nil;
  ReadMemoryPtr: TNtReadVirtualMemory = nil;

procedure ResolveStackPointers;
var
  M, K: HMODULE;
begin
  if TInterlocked.CompareExchange(StackResolved, 0, 0) <> 0 then Exit;
  StackResolveLock.Acquire;
  try
    if StackResolved <> 0 then Exit;
    M := WinModule('ntdll.dll');
    K := WinModule('kernel32.dll');
    if (M = 0) or (K = 0) then Exit;
    QueryThreadPtr := TNtQueryInformationThread(WinExport(M, 'NtQueryInformationThread'));
    QueryMemoryPtr := TNtQueryVirtualMemory(WinExport(M, 'NtQueryVirtualMemory'));
    ReadMemoryPtr := TNtReadVirtualMemory(WinExport(M, 'NtReadVirtualMemory'));
    ProcessIDPtr := TProcessIDFn(WinExport(K, 'GetProcessId'));
    TInterlocked.Exchange(StackResolved, 1);
  finally
    StackResolveLock.Release;
  end;
end;

function StackNativeAvailable: Boolean;
begin
  ResolveStackPointers;
  Result := Assigned(QueryThreadPtr) and Assigned(QueryMemoryPtr) and
    Assigned(ReadMemoryPtr) and Assigned(ProcessIDPtr) and
    (SizeOf(TThreadBasicX64) = 48) and
    (SizeOf(TNTTibHead) = 56) and
    (SizeOf(TMemoryBasicX64) = 48);
end;

function StackAddressSpan(Address, Bytes: NativeUInt): Boolean;
begin
  Result := (Address >= $10000) and (Bytes <> 0) and
    (Bytes <= High(NativeUInt) - Address);
end;

function QueryPage(ProcessHandle: THandle; Address: NativeUInt;
  out Region: TMemoryBasicX64): Boolean;
var
  Returned: NativeUInt;
  Candidate: TMemoryBasicX64;
  First: NativeUInt;
begin
  Region := Default(TMemoryBasicX64);
  Result := False;
  if (ProcessHandle = 0) or (Address < $10000) or
     not Assigned(QueryMemoryPtr) then Exit;
  Candidate := Default(TMemoryBasicX64);
  Returned := 0;
  if QueryMemoryPtr(ProcessHandle, Pointer(Address),
    MEMORY_BASIC_INFORMATION_CLASS, @Candidate, SizeOf(Candidate), @Returned) < 0 then Exit;
  if Returned <> SizeOf(Candidate) then Exit;
  First := NativeUInt(Candidate.BaseAddress);
  if not StackAddressSpan(First, Candidate.RegionSize) then Exit;
  if First > Address then Exit;
  if Address - First >= Candidate.RegionSize then Exit;
  if (Candidate.State <> MEM_COMMIT_VALUE) and
     (Candidate.State <> MEM_RESERVE_VALUE) and
     (Candidate.State <> MEM_FREE_VALUE) then Exit;
  Region := Candidate;
  Result := True;
end;

function ReadStackHead(ProcessHandle, ThreadHandle: THandle;
  out Basic: TThreadBasicX64; out Tib: TNTTibHead): Boolean;
var
  Returned: Cardinal;
  ReadBytes: NativeUInt;
  OwnerPID: Cardinal;
begin
  Result := False;
  Basic := Default(TThreadBasicX64);
  Tib := Default(TNTTibHead);
  if (ProcessHandle = 0) or (ThreadHandle = 0) or
     not Assigned(ProcessIDPtr) or not Assigned(QueryThreadPtr) or
     not Assigned(ReadMemoryPtr) then Exit;
  Returned := 0;
  if QueryThreadPtr(ThreadHandle, THREAD_BASIC_INFORMATION_CLASS,
    @Basic, SizeOf(Basic), @Returned) < 0 then Exit;
  if Returned <> SizeOf(Basic) then Exit;
  if Basic.ExitStatus <> THREAD_STILL_ACTIVE then Exit;
  if (Basic.ClientProcessID = 0) or
     (NativeUInt(Basic.ClientProcessID) > High(Cardinal)) or
     (Basic.ClientThreadID = 0) or
     (NativeUInt(Basic.ClientThreadID) > High(Cardinal)) then Exit;
  OwnerPID := ProcessIDPtr(ProcessHandle);
  if (OwnerPID = 0) or (OwnerPID <> Cardinal(Basic.ClientProcessID)) then Exit;
  if not StackAddressSpan(NativeUInt(Basic.TebBaseAddress), SizeOf(Tib)) then Exit;
  ReadBytes := 0;
  if ReadMemoryPtr(ProcessHandle, Basic.TebBaseAddress, @Tib,
    SizeOf(Tib), @ReadBytes) < 0 then Exit;
  if ReadBytes <> SizeOf(Tib) then Exit;
  Result := Tib.SelfPtr = Basic.TebBaseAddress;
end;

function SameStackHead(const A, B: TThreadBasicX64;
  const X, Y: TNTTibHead): Boolean;
begin
  // Fiber/stack switching and stack growth invalidate this sweep, not the target.
  Result := (A.TebBaseAddress = B.TebBaseAddress) and
    (A.ClientProcessID = B.ClientProcessID) and
    (A.ClientThreadID = B.ClientThreadID) and
    (X.SelfPtr = Y.SelfPtr) and (X.StackBase = Y.StackBase) and
    (X.StackLimit = Y.StackLimit) and (X.FiberData = Y.FiberData);
end;

function ConfirmStackHead(ProcessHandle, ThreadHandle: THandle;
  const Basic: TThreadBasicX64; const Tib: TNTTibHead;
  CreationTime: UInt64): Boolean;
var
  Again: TThreadBasicX64;
  TibAgain: TNTTibHead;
  C, E, K, U: TFileTime;
begin
  Result := False;
  if not ReadStackHead(ProcessHandle, ThreadHandle, Again, TibAgain) then Exit;
  if not SameStackHead(Basic, Again, Tib, TibAgain) then Exit;
  if not WinGetThreadTimes(ThreadHandle, C, E, K, U) then Exit;
  if (E.dwHighDateTime <> 0) or (E.dwLowDateTime <> 0) then Exit;
  Result := ((UInt64(C.dwHighDateTime) shl 32) or C.dwLowDateTime) = CreationTime;
end;

function IsExec(Protect: Cardinal): Boolean;
begin
  case (Protect and $FF) of
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY: Result := True;
  else
    Result := False;
  end;
end;

function QueryNativeThreadStack(ProcessHandle, ThreadHandle: THandle;
  out Snapshot: TNativeStackSnapshot): Boolean;
var
  Basic: TThreadBasicX64;
  Tib: TNTTibHead;
  TopRegion: TMemoryBasicX64;
  Base, Limit, Alloc: NativeUInt;
  Candidate: TNativeStackSnapshot;

  function ReadInitialStackIdentity: Boolean;
  var
    C, E, K, U: TFileTime;
  begin
    Result := False;
    // Read only TEB metadata (56 bytes); never scan stack contents.
    if not ReadStackHead(ProcessHandle, ThreadHandle, Basic, Tib) then Exit;
    if not WinGetThreadTimes(ThreadHandle, C, E, K, U) then Exit;
    if (E.dwHighDateTime <> 0) or (E.dwLowDateTime <> 0) then Exit;
    Candidate := Default(TNativeStackSnapshot);
    Candidate.CreateTime := (UInt64(C.dwHighDateTime) shl 32) or C.dwLowDateTime;
    if Candidate.CreateTime = 0 then Exit;
    Candidate.StackBase := NativeUInt(Tib.StackBase);
    Candidate.StackLimit := NativeUInt(Tib.StackLimit);
    Base := Candidate.StackBase;
    Limit := Candidate.StackLimit;
    Candidate.Known := True;
    Result := True;
  end;

  function ScanStackReservation: Boolean;
  var
    Region: TMemoryBasicX64;
    Cur, EndOfRegion, Covered: NativeUInt;
    J: Integer;
  begin
    Result := False;
    Candidate.AllocationBase := Alloc;
    Candidate.ReservedBytes := UInt64(Base - Alloc);
    Cur := Alloc;
    for J := 0 to MAX_STACK_MEMORY_REGIONS - 1 do
    begin
      if Cur >= Base then Break;
      if not QueryPage(ProcessHandle, Cur, Region) then Exit;
      // A disappearing/replaced reservation may be a legitimate termination race.
      if NativeUInt(Region.AllocationBase) <> Alloc then Exit;
      if (Region.State <> MEM_COMMIT_VALUE) and
         (Region.State <> MEM_RESERVE_VALUE) then Exit;
      EndOfRegion := NativeUInt(Region.BaseAddress) + Region.RegionSize;
      if EndOfRegion <= Cur then Exit;
      if EndOfRegion > Base then EndOfRegion := Base;
      Covered := EndOfRegion - Cur;
      if Region.State = MEM_COMMIT_VALUE then
      begin
        if UInt64(Covered) > Candidate.ReservedBytes - Candidate.CommittedBytes then Exit;
        Inc(Candidate.CommittedBytes, UInt64(Covered));
        if (Region.Protect and PAGE_GUARD_BIT) <> 0 then Candidate.HasGuard := True;
        if IsExec(Region.Protect) then Candidate.HasExecutablePage := True;
      end;
      Cur := EndOfRegion;
    end;
    if Cur < Base then Exit;
    Result := True;
  end;

begin
  Result := False;
  Snapshot := Default(TNativeStackSnapshot);
  if (ProcessHandle = 0) or (ThreadHandle = 0) or not StackNativeAvailable then Exit;
  if not ReadInitialStackIdentity then Exit;
  if (Base < $10000) or (Limit < $10000) or (Limit >= Base) then
  begin
    if not ConfirmStackHead(ProcessHandle, ThreadHandle, Basic, Tib,
      Candidate.CreateTime) then Exit;
    Snapshot := Candidate;
    Exit(True);
  end;
  if UInt64(Base - Limit) > MAX_STACK_RESERVE_BYTES then Exit;
  if not QueryPage(ProcessHandle, Base - 1, TopRegion) then Exit;
  if TopRegion.State <> MEM_COMMIT_VALUE then Exit;
  Alloc := NativeUInt(TopRegion.AllocationBase);
  if (Alloc < $10000) or (Alloc > Limit) then
  begin
    if not ConfirmStackHead(ProcessHandle, ThreadHandle, Basic, Tib,
      Candidate.CreateTime) then Exit;
    Snapshot := Candidate;
    Exit(True);
  end;
  if UInt64(Base - Alloc) > MAX_STACK_RESERVE_BYTES then Exit;
  if not ScanStackReservation then Exit;
  if not ConfirmStackHead(ProcessHandle, ThreadHandle, Basic, Tib,
    Candidate.CreateTime) then Exit;
  Candidate.BoundsValid := True;
  Snapshot := Candidate;
  Result := True;
end;

{$IFDEF NHW_NATIVE5B_TESTS}
  {$I Cozy.NHW.Native5B.Stack.inc}
{$ENDIF}
initialization
  StackResolveLock := TCriticalSection.Create;
finalization
  // The engine must have joined workers before Delphi unit finalization.
  StackResolveLock.Free;
end.
