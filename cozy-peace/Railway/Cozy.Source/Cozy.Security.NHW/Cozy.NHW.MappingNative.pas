unit Cozy.NHW.MappingNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils;

type
  TMappingWorkingSetItem = record
    VirtualAddress: Pointer;
    Attributes: NativeUInt;
  end;

function MappingNativeAvailable: Boolean;
function QueryMappingBacking(ProcessHandle: THandle; Address: NativeUInt;
  out DevicePath: string): Boolean;
function QueryMappingWorkingSet(ProcessHandle: THandle;
  var Items: array of TMappingWorkingSetItem; Count: Integer): Boolean;
function MappingPageResident(const Item: TMappingWorkingSetItem): Boolean;
function MappingPageShared(const Item: TMappingWorkingSetItem): Boolean;

{$IFDEF NHW_NATIVE5C_TESTS}
function TestMappingHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs, Cozy.NHW.NativeSafety, Cozy.NHW.WinPointers;

type
  TQueryWorkingSetExPtr = function(ProcessHandle: THandle;
    Buffer: Pointer; BufferBytes: Cardinal): BOOL; stdcall;
  TGetMappedFileNamePtr = function(ProcessHandle: THandle;
    Address: Pointer; Buffer: PWideChar; Characters: Cardinal): Cardinal; stdcall;

var
  ResolveLock: TCriticalSection;
  Resolved: Integer = 0;
  WSPtr: TQueryWorkingSetExPtr = nil;
  FilenamePtr: TGetMappedFileNamePtr = nil;

procedure ResolveMappingNative;
var
  Kernel, Psapi: HMODULE;

  procedure ResolveKernelExports;
  begin
    WSPtr := TQueryWorkingSetExPtr(WinExport(Kernel, 'K32QueryWorkingSetEx'));
    FilenamePtr := TGetMappedFileNamePtr(WinExport(Kernel, 'K32GetMappedFileNameW'));
  end;

  procedure ResolvePsapiFallbacks;
  begin
    Psapi := WinModule('psapi.dll');
    if Psapi = 0 then Psapi := WinLoadLibrary('psapi.dll');
    // Keep a dynamically loaded module alive while its function pointers live.
    if Psapi = 0 then Exit;
    if not Assigned(WSPtr) then
      WSPtr := TQueryWorkingSetExPtr(WinExport(Psapi, 'QueryWorkingSetEx'));
    if not Assigned(FilenamePtr) then
      FilenamePtr := TGetMappedFileNamePtr(WinExport(Psapi, 'GetMappedFileNameW'));
  end;
begin
  if TInterlocked.CompareExchange(Resolved, 0, 0) <> 0 then Exit;
  ResolveLock.Acquire;
  try
    if Resolved <> 0 then Exit;
    if SizeOf(TMappingWorkingSetItem) <> 16 then Exit;
    Kernel := WinModule('kernel32.dll');
    if Kernel = 0 then Exit;
    ResolveKernelExports;
    if not Assigned(WSPtr) or not Assigned(FilenamePtr) then
      ResolvePsapiFallbacks;
    TInterlocked.Exchange(Resolved, 1);
  finally
    ResolveLock.Release;
  end;
end;

function MappingNativeAvailable: Boolean;
begin
  ResolveMappingNative;
  Result := Assigned(WSPtr) or Assigned(FilenamePtr);
end;

function QueryMappingBacking(ProcessHandle: THandle; Address: NativeUInt;
  out DevicePath: string): Boolean;
var
  Buffer: array[0..32767] of WideChar;
  Characters: Cardinal;

  function DecodeMappedPath: Boolean;
  var
    I: Integer;
  begin
    Result := False;
    if (Characters = 0) or (Characters >= Cardinal(Length(Buffer) - 1)) then Exit;
    for I := 0 to Integer(Characters) - 1 do
      if Buffer[I] = #0 then Exit;
    SetString(DevicePath, PWideChar(@Buffer[0]), Integer(Characters));
    Result := DevicePath <> '';
  end;
begin
  Result := False;
  DevicePath := '';
  if (ProcessHandle = 0) or not NHWAddressSpan(Address, 1) then Exit;
  ResolveMappingNative;
  if not Assigned(FilenamePtr) then Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Characters := FilenamePtr(ProcessHandle, Pointer(Address),
    @Buffer[0], Cardinal(Length(Buffer)));
  Result := DecodeMappedPath;
end;

procedure ClearMappingAttributes(var Items: array of TMappingWorkingSetItem);
var I: Integer;
begin
  for I := 0 to High(Items) do Items[I].Attributes := 0;
end;

function QueryMappingWorkingSet(ProcessHandle: THandle;
  var Items: array of TMappingWorkingSetItem; Count: Integer): Boolean;
var
  Bytes: NativeUInt;

  function PrepareWorkingSetRequest: Boolean;
  var
    I: Integer;
  begin
    Result := False;
    if (ProcessHandle = 0) or (Count < 1) or (Count > Length(Items)) then Exit;
    if not NHWTryMultiplySize(NativeUInt(Count),
      SizeOf(TMappingWorkingSetItem), Bytes) then Exit;
    if Bytes > NativeUInt(High(Cardinal)) then Exit;
    for I := 0 to Count - 1 do
      if not NHWAddressSpan(NativeUInt(Items[I].VirtualAddress), 1) then Exit;
    Result := True;
  end;
begin
  Result := False;
  // Input addresses survive failure; all stale result flags are invalidated.
  ClearMappingAttributes(Items);
  if not PrepareWorkingSetRequest then Exit;
  ResolveMappingNative;
  if not Assigned(WSPtr) then Exit;
  try
    Result := WSPtr(ProcessHandle, @Items[0], Cardinal(Bytes));
  finally
    if not Result then ClearMappingAttributes(Items);
  end;
end;

function MappingPageResident(const Item: TMappingWorkingSetItem): Boolean;
begin
  Result := (Item.Attributes and NativeUInt(1)) <> 0;
end;

function MappingPageShared(const Item: TMappingWorkingSetItem): Boolean;
begin
  // This helper reports sharing for valid resident-page observations only.
  // False for an invalid observation is UNKNOWN, not proof of a private page.
  Result := MappingPageResident(Item) and
    ((Item.Attributes and (NativeUInt(1) shl 15)) <> 0);
end;

{$IFDEF NHW_NATIVE5C_TESTS}
  {$I Cozy.NHW.Native5C.Mapping.inc}
{$ENDIF}
initialization
  ResolveLock := TCriticalSection.Create;
finalization
  ResolveLock.Free;
end.
