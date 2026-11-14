unit Cozy.NHW.WriteWatchNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows;

const
  WRITE_WATCH_PAGE_COUNT = 4;

// Own-process private memory only. No remote memory operations.
// Base must be nil for creation. A failed release preserves Base, and a later
// creation refuses to overwrite it. Existing callers initialize Base to nil.
function CreateWriteWatchRegion(var Base: Pointer;
  out RegionSize: NativeUInt; out PageSize: Cardinal): Boolean;
procedure ReleaseWriteWatchRegion(var Base: Pointer);
function QueryAndResetWriteWatch(Base: Pointer; RegionSize: NativeUInt;
  PageSize: Cardinal; out DirtyMask: Cardinal): Boolean;

{$IFDEF NHW_NATIVE5C_TESTS}
function TestWriteWatchHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils,
  System.SyncObjs,
  Cozy.NHW.NativeSafety,
  Cozy.NHW.WinPointers;

const
  NHW_MEM_COMMIT = $00001000;
  NHW_MEM_RESERVE = $00002000;
  NHW_MEM_RELEASE = $00008000;
  NHW_MEM_WRITE_WATCH = $00200000;
  NHW_PAGE_READWRITE = $00000004;
  NHW_WRITE_WATCH_RESET = $00000001;

type
  TVirtualAllocPtr = function(Address: Pointer; Size: NativeUInt;
    AllocationType, Protect: Cardinal): Pointer; stdcall;
  TVirtualFreePtr = function(Address: Pointer; Size: NativeUInt;
    FreeType: Cardinal): BOOL; stdcall;
  TGetWriteWatchPtr = function(Flags: Cardinal; Address: Pointer;
    RegionSize: NativeUInt; Pages: PPointer; var Count: NativeUInt;
    var Granularity: Cardinal): Cardinal; stdcall;
  TGetNativeSystemInfoPtr = procedure(var Info: TSystemInfo); stdcall;

var
  ResolveLock: TCriticalSection;
  APIsResolved: Integer = 0;
  AllocPtr: TVirtualAllocPtr = nil;
  FreePtr: TVirtualFreePtr = nil;
  GetWatchPtr: TGetWriteWatchPtr = nil;
  InfoPtr: TGetNativeSystemInfoPtr = nil;

procedure ResolveWriteWatchAPIs;
var
  ModKernel: HMODULE;

  procedure ResolveAllocationAPIs;
  begin
    AllocPtr := TVirtualAllocPtr(WinExport(ModKernel, 'VirtualAlloc'));
    FreePtr := TVirtualFreePtr(WinExport(ModKernel, 'VirtualFree'));
  end;

  procedure ResolveWatchAPIs;
  begin
    GetWatchPtr := TGetWriteWatchPtr(WinExport(ModKernel, 'GetWriteWatch'));
    InfoPtr := TGetNativeSystemInfoPtr(WinExport(ModKernel, 'GetNativeSystemInfo'));
  end;
begin
  if TInterlocked.CompareExchange(APIsResolved, 0, 0) <> 0 then Exit;
  ResolveLock.Acquire;
  try
    if APIsResolved <> 0 then Exit;
    ModKernel := WinModule('kernel32.dll');
    if ModKernel = 0 then Exit; // bootstrap unavailable: allow retry
    ResolveAllocationAPIs;
    ResolveWatchAPIs;
    TInterlocked.Exchange(APIsResolved, 1); // immutable table publication
  finally
    ResolveLock.Release;
  end;
end;

function CreateWriteWatchRegion(var Base: Pointer;
  out RegionSize: NativeUInt; out PageSize: Cardinal): Boolean;
var
  Info: TSystemInfo;
  Bytes: NativeUInt;
  Candidate: Pointer;

  function PrepareRegionSize: Boolean;
  begin
    Info := Default(TSystemInfo);
    InfoPtr(Info);
    // Preserve the existing four 4 KiB pages; no new detection scope.
    Result := Info.dwPageSize = 4096;
    if Result then
      Bytes := NativeUInt(Info.dwPageSize) * NativeUInt(WRITE_WATCH_PAGE_COUNT);
  end;
begin
  Result := False;
  RegionSize := 0;
  PageSize := 0;
  if Base <> nil then Exit; // do not lose a previous failed-release owner
  ResolveWriteWatchAPIs;
  if not Assigned(AllocPtr) or not Assigned(FreePtr) or
     not Assigned(GetWatchPtr) or not Assigned(InfoPtr) then Exit;
  if not PrepareRegionSize then Exit;
  Candidate := AllocPtr(nil, Bytes,
    NHW_MEM_RESERVE or NHW_MEM_COMMIT or NHW_MEM_WRITE_WATCH,
    NHW_PAGE_READWRITE);
  if Candidate = nil then Exit;
  Base := Candidate;
  PageSize := Info.dwPageSize;
  RegionSize := Bytes;
  Result := True;
end;

procedure ReleaseWriteWatchRegion(var Base: Pointer);
begin
  if Base = nil then Exit;
  ResolveWriteWatchAPIs;
  if not Assigned(FreePtr) then Exit;
  // MEM_RELEASE requires the allocation base and a zero size.
  // Do not discard ownership on a failed or unavailable VirtualFree call.
  if FreePtr(Base, 0, NHW_MEM_RELEASE) then Base := nil;
end;

function QueryAndResetWriteWatch(Base: Pointer; RegionSize: NativeUInt;
  PageSize: Cardinal; out DirtyMask: Cardinal): Boolean;
var
  Pages: array[0..WRITE_WATCH_PAGE_COUNT - 1] of Pointer;
  Count: NativeUInt;
  Granularity, CandidateMask: Cardinal;
  StartAddress: NativeUInt;

  function RequestValid: Boolean;
  begin
    Result := (Base <> nil) and (PageSize = 4096) and
      (RegionSize = NativeUInt(PageSize) * NativeUInt(WRITE_WATCH_PAGE_COUNT));
    if not Result then Exit;
    StartAddress := NativeUInt(Base);
    Result := NHWAddressSpan(StartAddress, RegionSize) and
      ((StartAddress mod NativeUInt(PageSize)) = 0);
  end;

  function DecodeDirtyPages: Boolean;
  var
    I: Integer;
    Address, Offset, Index: NativeUInt;
  begin
    Result := False;
    if (Granularity <> PageSize) or (Count > WRITE_WATCH_PAGE_COUNT) then Exit;
    CandidateMask := 0;
    for I := 0 to Integer(Count) - 1 do
    begin
      Address := NativeUInt(Pages[I]);
      if Address < StartAddress then Exit;
      Offset := Address - StartAddress;
      if (Offset >= RegionSize) or ((Offset mod NativeUInt(PageSize)) <> 0) then Exit;
      Index := Offset div NativeUInt(PageSize);
      if Index >= WRITE_WATCH_PAGE_COUNT then Exit;
      CandidateMask := CandidateMask or (Cardinal(1) shl Cardinal(Index));
    end;
    Result := True;
  end;
begin
  Result := False;
  DirtyMask := 0;
  if not RequestValid then Exit;
  ResolveWriteWatchAPIs;
  if not Assigned(GetWatchPtr) then Exit;
  FillChar(Pages, SizeOf(Pages), 0);
  Count := WRITE_WATCH_PAGE_COUNT;
  Granularity := 0;
  // One API call requests query/reset; avoid a separate reset-call window.
  if GetWatchPtr(NHW_WRITE_WATCH_RESET, Base, RegionSize, @Pages[0],
      Count, Granularity) <> 0 then Exit;
  if not DecodeDirtyPages then Exit;
  // Partial/malformed replies never publish a partially computed dirty mask.
  DirtyMask := CandidateMask;
  Result := True;
end;

{$IFDEF NHW_NATIVE5C_TESTS}
  {$I Cozy.NHW.Native5C.WriteWatch.inc}
{$ENDIF}
initialization
  ResolveLock := TCriticalSection.Create;
finalization
  // All users/workers must have stopped before unit finalization.
  ResolveLock.Free;
end.
